// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Context table build (Routes).
//!
//! The routing decision is a two-stage ACL lookup, one stage per direction, over
//! four wide tables: `{remote, local} x {v4, v6}`. Source VPC, destination VPC and
//! L4 protocol are carried as *key fields* (exact / mask), not as separate
//! per-VPC / per-protocol tables, so a single classifier call (and, later, a
//! single batched call) resolves a heterogeneous batch.
//!
//! - Stage 1 (`remote`): match the destination against every peer's public
//!   prefixes, scoped to the source VPC, yielding a [`Verdict`] (dst VPC + dst NAT).
//! - Stage 2 (`local`): using that dst VPC, match the source against that peering's
//!   private prefixes, yielding the source NAT mode.
//!
//! A "default" (catch-all) expose lowers to a lowest-priority `/0` rule, so
//! longest-prefix-match (encoded in the rule priority, see [`rule_priority`])
//! handles it uniformly.
//!
//! Masquerade destinations are kept in the remote tables even though they cannot
//! accept new connections: their [`Verdict`] marks reply traffic on established
//! masquerade flows as distinguishable from a destination no peering covers, and
//! the NF gates them on flow state. Port-forwarding sources stay out of the local
//! tables (a covering expose must answer for connection initiation), so a stage-2
//! miss is reported distinctly (see [`LookupResult`]) for the NF to resolve
//! against flow state.

use crate::{NatMode, NatRequirement};
use acl::dpdk::dyn_table::predicate_to_chunks;
use acl::dpdk::install::install_table;
use acl::dpdk::lookup::{DpdkAclLookup, MAX_BATCH};
use acl::dpdk::rule::{AclFieldChunks, RuleSpec};
#[cfg(test)]
use acl::reference::table::{RefRule, ReferenceTable};
use concurrency::sync::LazyLock;
use concurrency::sync::atomic::{AtomicU64, Ordering};
use config::external::overlay::ValidatedOverlay;
use dpdk::acl::{CategoryMask, Priority};
#[cfg(test)]
use lookup::Lookup;
use lpm::prefix::Prefix;
use lpm::prefix::with_ports::{L4Protocol, PORT_RANGE_WILDCARD};
use match_action::{
    Erased, ExactSpec, FieldPredicate, FixedSize, MaskSpec, MatchKey, PrefixSpec, RangeSpec,
};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use net::vxlan::Vni;
use std::cmp::Reverse;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
#[cfg(test)]
use tracing::debug;

/// A resolved route: destination VPC, destination NAT mode, source NAT mode. All `Copy`, so batch
/// results can be extracted and the context guard dropped before packet metadata is mutated.
type Route = (VpcDiscriminant, NatMode, NatMode);

/// One lookup outcome. The two miss variants are distinct because the NF's fallback differs:
/// a destination miss means no peering covers the packet at all (drop, fail closed), while a
/// source miss can still be legitimate reply traffic from a port-forwarding-only source, whose
/// rules are deliberately absent from the local tables (the NF resolves it against flow state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LookupResult {
    /// Both stages matched.
    Route(Route),
    /// Stage 1 resolved the destination VPC, but the source matched nothing.
    SourceMiss(VpcDiscriminant),
    /// Stage 1 matched nothing: no peering covers this destination (also used for IP-version
    /// mismatches).
    DestinationMiss,
}

/// One packet's routing question, IP-version-agnostic (partitioned by version inside
/// [`FlowFilterContext::lookup_batch`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct LookupInput {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) src_ip: IpAddr,
    pub(crate) dst_ip: IpAddr,
    pub(crate) proto: NextHeader,
    pub(crate) ports: Option<(u16, u16)>,
}

/// Result of a stage-1 (remote/destination) match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) nat_mode: NatMode,
    pub(super) dst_vpcd: VpcDiscriminant,
}

/// A single IP-version's batched query (partitioned by IP version, so the address type is
/// concrete; every other field is carried verbatim from the [`LookupInput`]).
struct Query<I> {
    src_vni: Vni,
    proto: NextHeader,
    src_ip: I,
    dst_ip: I,
    src_port: u16,
    dst_port: u16,
}

/// Lower a config L4 protocol to a `(value, mask)` bitmask predicate: a specific protocol matches
/// exactly (every bit significant); "any" wildcards (no bit significant).
///
/// The mask is spelled as a `NextHeader` only because [`MaskSpec<T>`](MaskSpec) types the mask like
/// the value it constrains: it is a bit pattern, not a protocol number.
fn proto_mask(proto: L4Protocol) -> (NextHeader, NextHeader) {
    let all_bits = NextHeader::new(0xff);
    let no_bits = NextHeader::new(0x00);
    match proto {
        L4Protocol::Tcp => (NextHeader::TCP, all_bits),
        L4Protocol::Udp => (NextHeader::UDP, all_bits),
        L4Protocol::Any => (no_bits, no_bits),
    }
}

/// The VNI that keys the tables.
///
/// Total today: a VNI is the only discriminant a VPC can carry. That is a fact about the present
/// configuration surface, not a law -- so the tables key on the VNI *as a VNI* rather than
/// conflating "VPC discriminant" with "VXLAN identifier". A second discriminant variant turns this
/// match into a compile error, which is exactly where the table redesign should start.
fn key_vni(vpcd: VpcDiscriminant) -> Vni {
    match vpcd {
        VpcDiscriminant::VNI(vni) => vni,
    }
}

// -------------------------------------------------------------------------------------------------
// Keys.
//
// "proto" is first because rte_acl requires a one-byte first field; a #[mask] NextHeader satisfies
// that (one byte, and it lowers to the same Bitmask field type as #[exact]). VNIs are exact 4-byte
// fields -- see the FixedSize impl on Vni: the key encoding is padded to 4 bytes because classifier
// fields must be 1, 2, or 4 bytes wide, so it is NOT the 24-bit VXLAN wire encoding.
//
// Both key structs are byte-identical to their previous (u8, u32) spelling, so nothing about the
// lowered rules, the rte_acl layout, or the priorities changes here.

/// Stage-1 key: "which peer does this destination belong to, for this source VPC?"
#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
pub(super) struct RemoteKey<I> {
    #[mask]
    proto: NextHeader,
    #[exact]
    src_vni: Vni,
    #[prefix]
    dst_ip: I,
    #[range]
    dst_port: u16,
}

/// Stage-2 key: "is this source allowed to reach that peer, and with what source NAT?"
#[derive(Debug, MatchKey, Clone, PartialEq, Eq)]
pub(super) struct LocalKey<I> {
    #[mask]
    proto: NextHeader,
    #[exact]
    src_vni: Vni,
    #[exact]
    dst_vni: Vni,
    #[prefix]
    src_ip: I,
    #[range]
    src_port: u16,
}

// -------------------------------------------------------------------------------------------------
// Backend selection.
//
// Every rule is lowered once to backend-neutral FieldPredicate-s (via the Erased backend); each
// backend then consumes those. Reference is the linear-scan differential oracle (no EAL); Dpdk is
// the production, batchable rte_acl backend. This is the single place the backend choice lives.

/// The backend used to build the production context: the batchable rte_acl backend. Requires EAL
/// to be initialized (done once in `dataplane::main`). The reference backend is not compiled into
/// production builds (it is `cfg(test)`-gated).
pub(super) const PRODUCTION_BACKEND: Backend = Backend::Dpdk;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Backend {
    Dpdk,
    #[cfg(test)]
    Reference,
}

/// One backend-neutral, already-lowered rule.
///
/// `fields` is the erased form the backends consume; `rule` is the same rule with its field types
/// intact, which is what the table retains for the CLI (see [`RuleRow`]).
struct NeutralRule<K: MatchKey, A> {
    priority: u32,
    fields: Vec<FieldPredicate>,
    rule: K::Rule,
    action: A,
}

/// One retained rule, in match order. Keeping the *typed* rule (rather than the erased predicates,
/// or nothing at all) is what lets the CLI render a VNI as a VNI and a protocol as `TCP`, without
/// decoding bytes or trusting field position.
pub(super) struct RuleRow<K: MatchKey, A> {
    pub(super) priority: u32,
    pub(super) rule: K::Rule,
    pub(super) action: A,
}

/// A built table: a classifier plus the rules it was built from.
///
/// The rules are retained unconditionally. An rte_acl context is opaque once built -- it cannot be
/// asked what is in it -- so without this the production CLI can only report a rule count, which is
/// precisely the situation in which an operator most wants the rules.
pub(super) struct AnyTable<K: MatchKey, A> {
    classifier: Classifier<K, A>,
    rules: Box<[RuleRow<K, A>]>,
}

/// The classifier backing a table. `Dpdk` is production (and exposes `lookup_batch` for the batched
/// fast path); `Reference` is the test/opt-in linear-scan oracle; `Empty` matches nothing.
#[allow(clippy::large_enum_variant)] // backend reprs differ in size; boxing would add a hot-path indirection
enum Classifier<K: MatchKey, A> {
    /// No rules: every lookup misses. Used for the default context and zero-rule tables (avoids
    /// asking rte_acl to build an empty context).
    Empty,
    Dpdk(DpdkAclLookup<K, A>),
    #[cfg(test)]
    Reference(ReferenceTable<K, A>),
}

impl<K: MatchKey, A> AnyTable<K, A> {
    /// A table that matches nothing.
    pub(super) fn empty() -> Self {
        Self {
            classifier: Classifier::Empty,
            rules: Box::new([]),
        }
    }

    // Single-key lookup: only the test oracle uses it (production runs lookup_batch()).
    #[cfg(test)]
    fn lookup(&self, key: &K) -> Option<&A> {
        match &self.classifier {
            Classifier::Empty => None,
            Classifier::Dpdk(table) => table.lookup(key),
            Classifier::Reference(table) => table.lookup(key),
        }
    }

    /// Classify a batch of keys (`keys.len() <= MAX_BATCH`, `out.len() == keys.len()`), writing one
    /// result per key. The `Dpdk` backend does this in a single rte_acl call; the others loop.
    fn lookup_batch<'a>(&'a self, keys: &[K], out: &mut [Option<&'a A>]) {
        match &self.classifier {
            Classifier::Empty => out.iter_mut().for_each(|slot| *slot = None),
            Classifier::Dpdk(table) => table
                .lookup_batch(keys, out)
                .expect("caller chunks to MAX_BATCH with a matching output length"),
            #[cfg(test)]
            Classifier::Reference(table) => {
                for (key, slot) in keys.iter().zip(out.iter_mut()) {
                    *slot = table.lookup(key);
                }
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.rules.len()
    }

    /// The rules this table was built from, highest priority (= match order) first.
    pub(super) fn rules(&self) -> &[RuleRow<K, A>] {
        &self.rules
    }
}

impl<K: MatchKey, A> fmt::Debug for AnyTable<K, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.classifier {
            Classifier::Empty => "empty",
            Classifier::Dpdk(_) => "dpdk",
            #[cfg(test)]
            Classifier::Reference(_) => "reference",
        };
        write!(f, "AnyTable::{kind}({} rules)", self.len())
    }
}

// Lazily initialized so this compiles under the loom backend, whose AtomicU64::new is not const
// (each instance registers with the loom executor). The atomic itself is still the backend atomic,
// so fetch_add() stays instrumented; only construction is deferred. On every other backend LazyLock
// is a thin wrapper over an otherwise-const atomic.
static TABLE_SEQ: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

/// A process-unique rte_acl context name (rte_acl rejects duplicate names).
fn table_name(base: &str) -> String {
    format!(
        "flow_filter_{base}_{}",
        TABLE_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Build one table from backend-neutral rules using the selected backend.
fn build_table<K: MatchKey, A: Copy>(
    backend: Backend,
    base_name: &str,
    mut rules: Vec<NeutralRule<K, A>>,
) -> Result<AnyTable<K, A>, String>
where
    K::Rule: Copy,
{
    // Descending priority is match order. The reference backend needs it (it is first-match, so
    // this is what reproduces rte_acl's highest-priority-wins), and the CLI dump reads top-down.
    // rte_acl takes each priority explicitly, so the order is immaterial to it.
    rules.sort_by_key(|rule| Reverse(rule.priority));
    let rows: Box<[RuleRow<K, A>]> = rules
        .iter()
        .map(|rule| RuleRow {
            priority: rule.priority,
            rule: rule.rule,
            action: rule.action,
        })
        .collect();

    let classifier = match backend {
        Backend::Dpdk => {
            // A zero-rule table matches nothing; represent it as Empty rather than asking rte_acl
            // to build an empty context
            if rules.is_empty() {
                return Ok(AnyTable::empty());
            }
            let specs = K::field_specs();
            let max = NonZero::new(u32::try_from(rules.len()).unwrap_or(u32::MAX)).unwrap();
            let mut specs_out = Vec::with_capacity(rules.len());
            for rule in rules {
                let chunks: Vec<AclFieldChunks> = rule
                    .fields
                    .iter()
                    .zip(specs)
                    .map(|(pred, spec)| predicate_to_chunks(pred, spec.size))
                    .collect();
                let priority =
                    Priority::new(i32::try_from(rule.priority).map_err(|e| e.to_string())?)
                        .map_err(|e| e.to_string())?;
                specs_out.push(
                    RuleSpec::<K, A>::new(
                        priority,
                        CategoryMask::new(1).map_err(|e| e.to_string())?,
                        chunks,
                        rule.action,
                    )
                    .map_err(|e| e.to_string())?,
                );
            }
            install_table::<K, A>(&table_name(base_name), max, specs_out)
                .map(Classifier::Dpdk)
                .map_err(|e| e.to_string())?
        }
        #[cfg(test)]
        Backend::Reference => {
            let rules = rules
                .into_iter()
                .map(|r| RefRule::new(r.fields, r.action))
                .collect();
            Classifier::Reference(ReferenceTable::new(rules))
        }
    };
    Ok(AnyTable {
        classifier,
        rules: rows,
    })
}

// -------------------------------------------------------------------------------------------------
// Rule accumulation.
//
// Walk the overlay once, emitting each expose prefix as a rule into the correct
// "{remote, local} x {v4, v6}" bucket. The IP version is taken from each concrete prefix; defaults
// (which carry no prefix) use the peering's version.

/// Rule priority: longest-prefix-match, with port forwarding beating an equal-length overlap.
///
/// Config validation guarantees that rules with intersecting match sets never share a prefix
/// length, with one exception: a port-forwarding public range may overlap a masquerade public
/// range of the same length. Port forwarding must win that tie (a masquerade destination can only
/// carry reply traffic), so the priority reserves its low bit for it; everything else keeps pure
/// prefix-length ordering.
fn rule_priority(ip_range: Prefix, port_forwarding: bool) -> u32 {
    ((u32::from(ip_range.length()) + 1) << 1) | u32::from(port_forwarding)
}

/// Lower a stage-1 (remote) rule into the v4 or v6 bucket according to its prefix.
#[allow(clippy::too_many_arguments)] // internal builder; grouping the fields would not aid clarity
fn emit_remote(
    v4: &mut Vec<NeutralRule<RemoteKey<Ipv4Addr>, Verdict>>,
    v6: &mut Vec<NeutralRule<RemoteKey<Ipv6Addr>, Verdict>>,
    src_vni: Vni,
    ip_range: Prefix,
    port_range: RangeSpec<u16>,
    (proto_value, proto_mask): (NextHeader, NextHeader),
    action: Verdict,
) {
    let priority = rule_priority(
        ip_range,
        action.nat_mode == Some(NatRequirement::PortForwarding),
    );
    match ip_range {
        Prefix::IPV4(prefix) => {
            let rule = RemoteKeyRule::<Ipv4Addr> {
                proto: MaskSpec::from((proto_value, proto_mask)),
                src_vni: ExactSpec::new(src_vni),
                dst_ip: PrefixSpec::from(prefix),
                dst_port: port_range,
            };
            v4.push(NeutralRule {
                priority,
                fields: rule.into_backend_fields::<Erased>(),
                rule,
                action,
            });
        }
        Prefix::IPV6(prefix) => {
            let rule = RemoteKeyRule::<Ipv6Addr> {
                proto: MaskSpec::from((proto_value, proto_mask)),
                src_vni: ExactSpec::new(src_vni),
                dst_ip: PrefixSpec::from(prefix),
                dst_port: port_range,
            };
            v6.push(NeutralRule {
                priority,
                fields: rule.into_backend_fields::<Erased>(),
                rule,
                action,
            });
        }
    }
}

/// Lower a stage-2 (local) rule into the v4 or v6 bucket according to its prefix.
#[allow(clippy::too_many_arguments)] // internal builder; grouping the fields would not aid clarity
fn emit_local(
    v4: &mut Vec<NeutralRule<LocalKey<Ipv4Addr>, NatMode>>,
    v6: &mut Vec<NeutralRule<LocalKey<Ipv6Addr>, NatMode>>,
    src_vni: Vni,
    dst_vni: Vni,
    ip_range: Prefix,
    port_range: RangeSpec<u16>,
    (proto_value, proto_mask): (NextHeader, NextHeader),
    action: NatMode,
) {
    // Port-forwarding sources are never emitted into the local tables, so the tie-break bit is
    // always clear here; local rules keep pure prefix-length ordering.
    let priority = rule_priority(ip_range, false);
    match ip_range {
        Prefix::IPV4(prefix) => {
            let rule = LocalKeyRule::<Ipv4Addr> {
                proto: MaskSpec::from((proto_value, proto_mask)),
                src_vni: ExactSpec::new(src_vni),
                dst_vni: ExactSpec::new(dst_vni),
                src_ip: PrefixSpec::from(prefix),
                src_port: port_range,
            };
            v4.push(NeutralRule {
                priority,
                fields: rule.into_backend_fields::<Erased>(),
                rule,
                action,
            });
        }
        Prefix::IPV6(prefix) => {
            let rule = LocalKeyRule::<Ipv6Addr> {
                proto: MaskSpec::from((proto_value, proto_mask)),
                src_vni: ExactSpec::new(src_vni),
                dst_vni: ExactSpec::new(dst_vni),
                src_ip: PrefixSpec::from(prefix),
                src_port: port_range,
            };
            v6.push(NeutralRule {
                priority,
                fields: rule.into_backend_fields::<Erased>(),
                rule,
                action,
            });
        }
    }
}

#[derive(Default)]
struct RuleSet {
    remote_v4: Vec<NeutralRule<RemoteKey<Ipv4Addr>, Verdict>>,
    remote_v6: Vec<NeutralRule<RemoteKey<Ipv6Addr>, Verdict>>,
    local_v4: Vec<NeutralRule<LocalKey<Ipv4Addr>, NatMode>>,
    local_v6: Vec<NeutralRule<LocalKey<Ipv6Addr>, NatMode>>,
}

impl RuleSet {
    fn from_overlay(overlay: &ValidatedOverlay) -> Self {
        let mut rules = Self::default();
        for vpc in overlay.vpc_table().values() {
            let src_vni = vpc.vni();
            for peering in vpc.peerings() {
                let remote_vni = overlay.vpc_table().get_remote_vni(peering);
                let remote_vpcd = VpcDiscriminant::from_vni(remote_vni);
                let default_ip = || {
                    if peering.is_v4() {
                        Prefix::root_v4()
                    } else {
                        Prefix::root_v6()
                    }
                };

                // Stage 1: peer's public prefixes -> Verdict{dst VPC, dst NAT}. Masquerade
                // destinations cannot receive connections, but their rules stay in the table:
                // a masquerade Verdict lets the NF tell reply traffic on an established
                // masquerade flow apart from a destination no peering covers (which must drop).
                // The NF only accepts a masquerade Verdict when the packet rides such a flow.
                for expose in peering.remote().valexp() {
                    let proto = proto_mask(expose.nat_proto().unwrap_or(L4Protocol::Any));
                    let action = Verdict {
                        nat_mode: NatRequirement::from_expose(expose),
                        dst_vpcd: remote_vpcd,
                    };
                    for prefix in expose.public_ips() {
                        emit_remote(
                            &mut rules.remote_v4,
                            &mut rules.remote_v6,
                            src_vni,
                            prefix.prefix(),
                            prefix.into(),
                            proto,
                            action,
                        );
                    }
                }
                if peering.remote().has_default_expose() {
                    emit_remote(
                        &mut rules.remote_v4,
                        &mut rules.remote_v6,
                        src_vni,
                        default_ip(),
                        PORT_RANGE_WILDCARD,
                        proto_mask(L4Protocol::Any),
                        Verdict {
                            nat_mode: None,
                            dst_vpcd: remote_vpcd,
                        },
                    );
                }

                // Stage 2: source's private prefixes -> source NAT mode. Port-forwarding sources
                // cannot initiate connections, so they are excluded here.
                for expose in peering
                    .local()
                    .valexp()
                    .iter()
                    .filter(|expose| expose.can_init_connection())
                {
                    let proto = proto_mask(expose.nat_proto().unwrap_or(L4Protocol::Any));
                    let action = NatRequirement::from_expose(expose);
                    for prefix in expose.ips() {
                        emit_local(
                            &mut rules.local_v4,
                            &mut rules.local_v6,
                            src_vni,
                            remote_vni,
                            prefix.prefix(),
                            prefix.into(),
                            proto,
                            action,
                        );
                    }
                }
                if peering.local().has_default_expose() {
                    emit_local(
                        &mut rules.local_v4,
                        &mut rules.local_v6,
                        src_vni,
                        remote_vni,
                        default_ip(),
                        PORT_RANGE_WILDCARD,
                        proto_mask(L4Protocol::Any),
                        None,
                    );
                }
            }
        }
        rules
    }
}

// -------------------------------------------------------------------------------------------------
// The four tables.

pub struct FlowFilterContext {
    pub(super) remote_v4: AnyTable<RemoteKey<Ipv4Addr>, Verdict>,
    pub(super) local_v4: AnyTable<LocalKey<Ipv4Addr>, NatMode>,
    pub(super) remote_v6: AnyTable<RemoteKey<Ipv6Addr>, Verdict>,
    pub(super) local_v6: AnyTable<LocalKey<Ipv6Addr>, NatMode>,
}

impl Default for FlowFilterContext {
    fn default() -> Self {
        Self {
            remote_v4: AnyTable::empty(),
            local_v4: AnyTable::empty(),
            remote_v6: AnyTable::empty(),
            local_v6: AnyTable::empty(),
        }
    }
}

impl fmt::Debug for FlowFilterContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowFilterContext")
            .field("remote_v4", &self.remote_v4)
            .field("local_v4", &self.local_v4)
            .field("remote_v6", &self.remote_v6)
            .field("local_v6", &self.local_v6)
            .finish()
    }
}

impl FlowFilterContext {
    /// Build the four tables from a validated overlay using `backend`.
    ///
    /// # Errors
    ///
    /// Returns the backend build error (only the `Dpdk` backend can fail; `Reference` is infallible).
    pub(super) fn build(overlay: &ValidatedOverlay, backend: Backend) -> Result<Self, String> {
        let rules = RuleSet::from_overlay(overlay);
        Ok(Self {
            remote_v4: build_table(backend, "remote_v4", rules.remote_v4)?,
            local_v4: build_table(backend, "local_v4", rules.local_v4)?,
            remote_v6: build_table(backend, "remote_v6", rules.remote_v6)?,
            local_v6: build_table(backend, "local_v6", rules.local_v6)?,
        })
    }

    // Single-key lookup: the readable per-packet oracle used by tests; production runs
    // lookup_batch. The differential test cross-checks the two against each other.
    #[cfg(test)]
    pub(super) fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        proto: NextHeader,
        ports: Option<(u16, u16)>,
    ) -> LookupResult {
        let src_vni = key_vni(src_vpcd);
        let (src_port, dst_port) = ports.unzip();
        let src_port = src_port.unwrap_or(0);
        let dst_port = dst_port.unwrap_or(0);

        match (src_ip, dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let Some(verdict) = self.remote_v4.lookup(&RemoteKey {
                    proto,
                    src_vni,
                    dst_ip,
                    dst_port,
                }) else {
                    return LookupResult::DestinationMiss;
                };
                match self.local_v4.lookup(&LocalKey {
                    proto,
                    src_vni,
                    dst_vni: key_vni(verdict.dst_vpcd),
                    src_ip,
                    src_port,
                }) {
                    Some(nat_mode) => {
                        LookupResult::Route((verdict.dst_vpcd, verdict.nat_mode, *nat_mode))
                    }
                    None => LookupResult::SourceMiss(verdict.dst_vpcd),
                }
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                let Some(verdict) = self.remote_v6.lookup(&RemoteKey {
                    proto,
                    src_vni,
                    dst_ip,
                    dst_port,
                }) else {
                    return LookupResult::DestinationMiss;
                };
                match self.local_v6.lookup(&LocalKey {
                    proto,
                    src_vni,
                    dst_vni: key_vni(verdict.dst_vpcd),
                    src_ip,
                    src_port,
                }) {
                    Some(nat_mode) => {
                        LookupResult::Route((verdict.dst_vpcd, verdict.nat_mode, *nat_mode))
                    }
                    None => LookupResult::SourceMiss(verdict.dst_vpcd),
                }
            }
            _ => {
                debug!(
                    "Source and destination IP versions do not match: src_ip={src_ip:?}, dst_ip={dst_ip:?}",
                );
                LookupResult::DestinationMiss
            }
        }
    }

    /// Batched form of [`lookup`](Self::lookup): resolve one [`LookupResult`] per input into `out`
    /// (`out.len() == inputs.len()`). Inputs are partitioned by IP version into per-version index
    /// lists (packets are never reordered), and each version runs the two-pass lookup in
    /// `MAX_BATCH`-sized rte_acl calls. IP-version mismatches resolve to
    /// [`LookupResult::DestinationMiss`] (as in `lookup`).
    pub(crate) fn lookup_batch(&self, inputs: &[LookupInput], out: &mut [LookupResult]) {
        debug_assert_eq!(inputs.len(), out.len());

        let mut v4_idx: Vec<usize> = Vec::new();
        let mut v4_q: Vec<Query<Ipv4Addr>> = Vec::new();
        let mut v6_idx: Vec<usize> = Vec::new();
        let mut v6_q: Vec<Query<Ipv6Addr>> = Vec::new();

        for (i, input) in inputs.iter().enumerate() {
            out[i] = LookupResult::DestinationMiss;
            let proto = input.proto;
            let src_vni = key_vni(input.src_vpcd);
            let (src_port, dst_port) = input.ports.unwrap_or((0, 0));
            match (input.src_ip, input.dst_ip) {
                (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                    v4_idx.push(i);
                    v4_q.push(Query {
                        src_vni,
                        proto,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    });
                }
                (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                    v6_idx.push(i);
                    v6_q.push(Query {
                        src_vni,
                        proto,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    });
                }
                _ => { /* version mismatch: leave "out[i] = DestinationMiss" */ }
            }
        }

        lookup_versioned(&self.remote_v4, &self.local_v4, &v4_q, &v4_idx, out);
        lookup_versioned(&self.remote_v6, &self.local_v6, &v6_q, &v6_idx, out);
    }
}

/// The two-pass batched lookup for one IP version. `queries[k]` corresponds to output slot
/// `out[idx[k]]`. Runs in `MAX_BATCH`-sized rte_acl calls: stage 1 (destination -> [`Verdict`]),
/// then stage 2 (source -> source NAT) over the stage-1 hits only.
fn lookup_versioned<I: FixedSize + Copy>(
    remote: &AnyTable<RemoteKey<I>, Verdict>,
    local: &AnyTable<LocalKey<I>, NatMode>,
    queries: &[Query<I>],
    idx: &[usize],
    out: &mut [LookupResult],
) where
    RemoteKey<I>: MatchKey,
    LocalKey<I>: MatchKey,
{
    for (q_chunk, i_chunk) in queries.chunks(MAX_BATCH).zip(idx.chunks(MAX_BATCH)) {
        // Stage 1: destination -> Verdict.
        let remote_keys: Vec<RemoteKey<I>> = q_chunk
            .iter()
            .map(|q| RemoteKey {
                proto: q.proto,
                src_vni: q.src_vni,
                dst_ip: q.dst_ip,
                dst_port: q.dst_port,
            })
            .collect();
        let mut verdicts: Vec<Option<&Verdict>> = vec![None; q_chunk.len()];
        remote.lookup_batch(&remote_keys, &mut verdicts);

        // Stage 2: for the hits only, source -> source NAT.
        let mut local_keys: Vec<LocalKey<I>> = Vec::new();
        let mut hit_pos: Vec<usize> = Vec::new();
        for (pos, verdict) in verdicts.iter().enumerate() {
            if let Some(verdict) = verdict {
                let q = &q_chunk[pos];
                local_keys.push(LocalKey {
                    proto: q.proto,
                    src_vni: q.src_vni,
                    dst_vni: key_vni(verdict.dst_vpcd),
                    src_ip: q.src_ip,
                    src_port: q.src_port,
                });
                hit_pos.push(pos);
            }
        }
        let mut nat_modes: Vec<Option<&NatMode>> = vec![None; local_keys.len()];
        local.lookup_batch(&local_keys, &mut nat_modes);

        // Scatter results back to the caller's output positions. A stage-1 miss stays
        // DestinationMiss; a stage-1 hit whose source matched nothing becomes SourceMiss.
        for (hit, &pos) in hit_pos.iter().enumerate() {
            let verdict = verdicts[pos].unwrap_or_else(|| unreachable!("hit_pos tracks Some"));
            out[i_chunk[pos]] = match nat_modes[hit] {
                Some(nat_mode) => {
                    LookupResult::Route((verdict.dst_vpcd, verdict.nat_mode, *nat_mode))
                }
                None => LookupResult::SourceMiss(verdict.dst_vpcd),
            };
        }
    }
}

// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn proto_mask_makes_every_bit_significant_except_for_any() {
        let all_bits = NextHeader::new(0xff);
        let no_bits = NextHeader::new(0x00);
        assert_eq!(proto_mask(L4Protocol::Tcp), (NextHeader::TCP, all_bits));
        assert_eq!(proto_mask(L4Protocol::Udp), (NextHeader::UDP, all_bits));
        assert_eq!(proto_mask(L4Protocol::Any), (no_bits, no_bits));
    }

    #[test]
    fn remote_key_has_four_fields_local_has_five() {
        assert_eq!(RemoteKey::<Ipv4Addr>::N, 4);
        assert_eq!(LocalKey::<Ipv4Addr>::N, 5);
    }

    #[test]
    fn default_tables_are_empty() {
        let tables = FlowFilterContext::default();
        assert_eq!(tables.remote_v4.len(), 0);
        assert_eq!(tables.local_v6.len(), 0);
    }

    /// The masked-byte lowering of the protocol constraint is equivalent to its direct
    /// semantics for EVERY possible packet protocol and every rule protocol.
    ///
    /// The key now carries the packet's real next-header byte rather than a collapsed sentinel,
    /// so this is what licenses that: a protocol no rule can name (anything but TCP/UDP) matches
    /// the `Any` rules and nothing else, purely by virtue of their zero mask.
    #[test]
    fn proto_lowering_matches_direct_semantics() {
        bolero::check!().with_type::<u8>().for_each(|&raw| {
            let packet = NextHeader::new(raw);
            for rule in [L4Protocol::Tcp, L4Protocol::Udp, L4Protocol::Any] {
                let (value, mask) = proto_mask(rule);
                let lowered = (packet.as_u8() & mask.as_u8()) == (value.as_u8() & mask.as_u8());
                let direct = match rule {
                    L4Protocol::Any => true,
                    L4Protocol::Tcp => packet == NextHeader::TCP,
                    L4Protocol::Udp => packet == NextHeader::UDP,
                };
                assert_eq!(lowered, direct, "protocol {raw}, rule {rule:?}");
            }
        });
    }

    /// `rule_priority` embeds the intended precedence order exactly: lexicographic in
    /// (prefix length, port-forwarding bit). A longer prefix always wins regardless of the
    /// tie-break bit; at equal length port forwarding wins; equal inputs tie. Every produced
    /// value is a valid rte_acl priority (>= 1).
    #[test]
    fn priority_is_lexicographic_in_length_then_port_forwarding() {
        use lpm::prefix::{IpPrefix, Ipv6Prefix};
        use std::net::Ipv6Addr;
        let prefix_of_len = |len: u8| {
            Prefix::IPV6(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, len).expect("valid length"))
        };
        bolero::check!()
            .with_type::<(u8, bool, u8, bool)>()
            .for_each(|&(len_a, fw_a, len_b, fw_b)| {
                let (len_a, len_b) = (len_a % 129, len_b % 129);
                let prio_a = rule_priority(prefix_of_len(len_a), fw_a);
                let prio_b = rule_priority(prefix_of_len(len_b), fw_b);
                assert_eq!(
                    prio_a.cmp(&prio_b),
                    (len_a, fw_a).cmp(&(len_b, fw_b)),
                    "priority order diverges from (length, port-forwarding) order for \
                     ({len_a}, {fw_a}) vs ({len_b}, {fw_b})",
                );
                assert!(prio_a >= 1, "priority must be a valid rte_acl priority");
            });
    }
}
