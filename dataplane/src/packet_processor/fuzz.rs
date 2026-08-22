// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packets driven through the overlay pipeline, against a generated configuration.
//!
//! The per-network-function harnesses -- `nat::{static_nat,masquerade,portfw}::probe`,
//! `acl_filter::nf_fuzz`, `flow_filter`'s adversarial stacks -- each configure one stage and feed
//! it packets. They are what says a stage does its own job. What none of them can say is what
//! happens when the stages are put in a row, and that is where the defects have actually been:
//!
//! - the IPv6 extension-header ACL bypass needed a packet shape the ACL's own generator never
//!   produced, because the shape was legal and the *reading* of it was wrong;
//! - the VLAN passthrough needed decapsulation, a filter and egress in the same test, because no
//!   single stage was doing anything wrong -- the tag simply survived all of them.
//!
//! Both are interaction bugs. A single-stage harness cannot see one by construction.
//!
//! # What this covers, and what it does not
//!
//! The stages here are the overlay slice of the production pipeline, in production order:
//! `IcmpErrorHandler`, `FlowLookup`, `FlowFilter`, `AclFilter`, `StaticNat`, `PortForwarder`,
//! `Masquerade`. See `start_router` in the parent module for the whole list.
//!
//! `Fabric::build` wires that slice alone; `Fabric::routed` wires the whole pipeline, `Ingress`,
//! both `IpForwarder`s and `Egress` included, over the underlay in `topology`. The difference is
//! whether a packet's arrival is stamped or earned -- see the `routed` module.
//!
//! Building the underlay needs the three tables those stages read populated to a known shape,
//! which is what `routing::testing::RouterTables` is for.
//!
//! # What the properties here do and do not catch
//!
//! What this reaches that a per-stage harness cannot:
//!
//! - Removing the line in `flow_entry`'s `FlowLookup` that attaches flow state fails
//!   `a_translated_flow_comes_back_to_where_it_started`. That is the claim this harness exists to
//!   make: a one-line change in a different crate, in a stage that decides nothing by itself, is
//!   caught because five stages have to agree for a flow to come back.
//! - Reverting the `acl_filter` extension-header fix fails
//!   `the_acl_verdict_follows_the_protocol_the_packet_carries`. That is the bypass itself, caught
//!   at the altitude it lived at: a rule naming TCP, a TCP packet behind an extension header, and
//!   a filter reading the protocol out of a field that names the extension.
//! - Removing the VLAN guard in `IpForwarder` fails `a_vlan_tag_is_refused_at_decapsulation`, and
//!   *not* `a_tagged_shape_never_reaches_the_wire`, because the filters refuse the shape too. Two
//!   properties about one behaviour, kept apart on purpose: one says where the decision is made,
//!   the other says what the gateway does. Only the first can notice a layer going missing.
//!
//! `every_shape_leaves_the_pipeline_with_a_verdict` is deliberately weak: it says a verdict was
//! reached and attributed, not that it was right. It catches a lost packet, a panic, and a packet
//! forwarded with nobody having chosen where it goes. It would not have caught either of the two
//! defects above, and saying so is the point -- a liveness property that looks like a correctness
//! property is worse than no property.
//!
//! # The classifier is the production one
//!
//! `FlowFilterContext::try_from` and `AclFilterContext::try_from` build `rte_acl` tables, so these
//! tests need the EAL. That is deliberate. The reference backends exist to be a fast oracle for
//! the crates that own them; an end-to-end harness that used them would be testing a classifier
//! that never ships.

#![cfg(test)]
#![cfg(not(miri))]

use acl_filter::{AclFilter, AclFilterContext, AclFilterContextWriter};
use concurrency::sync::Arc;
use config::external::overlay::acl::Acl;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::{Overlay, ValidatedOverlay};
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes_and_acl,
};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use flow_filter::{FlowFilter, FlowFilterContext, FlowFilterContextWriter};
use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
use nat::portfw::{PortForwarder, PortFwTableWriter};
use nat::static_nat::NatTablesWriter;
use nat::static_nat::setup::build_nat_configuration;
use nat::{IcmpErrorHandler, Masquerade, StaticNat};
use lpm::prefix::Prefix;
use net::buffer::{PacketBufferMut, TestBuffer};
use net::eth::mac::{Mac, SourceMac};
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use routing::testing::{FibGroup, FwAction, NhopKey, RouteOrigin};
use routing::{EgressObject, FibEntry, PktInstruction, ResolvedEncapsulation, ResolvedVxlan, Vtep};
use pipeline::{DynPipeline, NetworkFunction};
use routing::testing::RouterTables;
use std::net::IpAddr;

use super::egress::Egress;
use super::ingress::Ingress;
use super::ipforward::IpForwarder;

/// A configured overlay pipeline, and the handles that keep its tables alive.
///
/// Every writer is held for the fabric's lifetime: dropping one tears down the data it published,
/// so a fabric that let a writer go would be a pipeline whose configuration silently emptied.
pub(crate) struct Fabric {
    pipeline: DynPipeline<TestBuffer>,
    flow_table: Arc<FlowTable>,
    _flow_filter: FlowFilterContextWriter,
    _acl: AclFilterContextWriter,
    _static_nat: NatTablesWriter,
    _portfw: PortFwTableWriter,
    _masquerade: NatAllocatorWriter,
    /// Held for the same reason as the writers above: the fib writers live in here, and a fib
    /// whose writer is dropped is torn down. `None` for an overlay-slice fabric.
    _tables: Option<RouterTables>,
}

impl Fabric {
    /// Build the overlay pipeline for a set of exposes, or `None` if they do not form a valid
    /// configuration.
    ///
    /// A rejection here is not a finding: two generated exposes may legitimately overlap, and the
    /// generator does not try to avoid it. What would be a finding is a configuration that
    /// validates and then cannot be lowered into tables, so that step is an `expect` rather than a
    /// `?`.
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        Self::build_with_acl(exposes, None)
    }

    /// As [`Self::build`], with an ACL on the peering.
    pub(crate) fn build_with_acl(exposes: &[VpcExpose], acl: Option<&Acl>) -> Option<Self> {
        Self::assemble(exposes, acl, None)
    }

    /// The whole pipeline, not just the overlay slice: `Ingress`, both `IpForwarder`s and `Egress`
    /// as well, over the topology in [`topology`].
    ///
    /// The difference this makes is that a packet has to *earn* its arrival. An overlay-slice
    /// fabric is handed a bare inner packet with [`arrive`] stamping the metadata that
    /// decapsulation would have set; here the metadata is set by decapsulating a real tunnelled
    /// frame, and everything that stamp asserts -- that the vni names a fib, that the frame parses
    /// back, that nothing in it disqualifies it -- is under test rather than assumed.
    pub(crate) fn routed(exposes: &[VpcExpose], acl: Option<&Acl>) -> Option<Self> {
        Self::assemble(exposes, acl, Some(topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)])))
    }

    /// A routed fabric over a configuration the caller built, rather than the two-vpc one.
    ///
    /// For properties about *where* a packet goes, which need more than one destination to choose
    /// between. The caller supplies the underlay too, because the vnis it has to be able to
    /// encapsulate into are the ones its own configuration names.
    pub(crate) fn routed_over(overlay: &Overlay, tables: RouterTables) -> Option<Self> {
        Some(Self::with_overlay(
            &overlay.clone().validate().ok()?,
            Some(tables),
        ))
    }

    fn assemble(
        exposes: &[VpcExpose],
        acl: Option<&Acl>,
        tables: Option<RouterTables>,
    ) -> Option<Self> {
        let overlay = overlay_with_exposes_and_acl(exposes.to_vec(), acl)
            .ok()?
            .validate()
            .ok()?;
        Some(Self::with_overlay(&overlay, tables))
    }

    fn with_overlay(overlay: &ValidatedOverlay, tables: Option<RouterTables>) -> Self {
        let flow_table = Arc::new(FlowTable::default());
        let mut pipeline = DynPipeline::new();

        if let Some(tables) = &tables {
            pipeline = pipeline.add_stage(Ingress::new("ingress", tables.interfaces()));
            pipeline = pipeline.add_stage(IpForwarder::new("ip-forward-1", tables.fibs()));
            pipeline = pipeline.add_stage(Checkpoint::new(
                "after ip-forward-1",
                contract::decapsulated,
            ));
        }

        pipeline = pipeline.add_stage(IcmpErrorHandler::new(flow_table.clone()));
        pipeline = pipeline.add_stage(FlowLookup::new("flow-lookup", flow_table.clone()));

        let flow_filter = FlowFilterContextWriter::new();
        flow_filter.store(
            FlowFilterContext::try_from(overlay).expect("a validated overlay lowers to tables"),
        );
        pipeline = pipeline.add_stage(FlowFilter::new("flow-filter", flow_filter.get_reader()));
        pipeline = pipeline.add_stage(Checkpoint::new("after flow-filter", contract::placed));

        let acl = AclFilterContextWriter::new();
        acl.store(
            AclFilterContext::try_from(overlay).expect("a validated overlay lowers to acls"),
        );
        pipeline = pipeline.add_stage(AclFilter::new("acl-filter", acl.get_reader()));

        let mut static_nat = NatTablesWriter::new();
        static_nat.update_nat_tables(
            build_nat_configuration(overlay.vpc_table())
                .expect("a validated overlay lowers to nat"),
        );
        pipeline = pipeline.add_stage(StaticNat::with_reader(
            "static-nat",
            static_nat.get_reader(),
        ));

        let mut portfw = PortFwTableWriter::new();
        portfw
            .update_from_vpc_table(overlay.vpc_table())
            .expect("a validated overlay lowers to port forwarding");
        pipeline = pipeline.add_stage(PortForwarder::new(
            "port-forwarder",
            portfw.reader(),
            flow_table.clone(),
        ));

        let mut masquerade = NatAllocatorWriter::new();
        // Randomised port selection would make two runs of one configuration disagree on every
        // flow, which is legitimate behaviour and useless to compare.
        masquerade.update_nat_allocator(
            MasqueradeConfig::new(overlay.vpc_table()).set_randomize(false),
            1,
            &flow_table,
        );
        pipeline = pipeline.add_stage(Checkpoint::new(
            "before masquerade",
            contract::ready_to_translate,
        ));
        pipeline = pipeline.add_stage(Masquerade::new(
            "masquerade",
            flow_table.clone(),
            masquerade.get_reader(),
        ));

        if let Some(tables) = &tables {
            pipeline = pipeline.add_stage(IpForwarder::new("ip-forward-2", tables.fibs()));
            pipeline = pipeline.add_stage(Egress::new(
                "egress",
                tables.interfaces(),
                tables.adjacencies(),
            ));
            pipeline = pipeline.add_stage(Checkpoint::new("after egress", contract::finished));
        }

        Self {
            pipeline,
            flow_table,
            _flow_filter: flow_filter,
            _acl: acl,
            _static_nat: static_nat,
            _portfw: portfw,
            _masquerade: masquerade,
            _tables: tables,
        }
    }

    /// Send one packet through, and hand back what came out.
    ///
    /// A stage may drop a packet but must not lose it: `enforce` keeps a done packet so the reason
    /// can be read, and a pipeline that returned nothing would be a packet that vanished. That is
    /// asserted here rather than in a property, because every property depends on it.
    pub(crate) fn send(&mut self, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
        let mut out = self.send_batch(vec![packet]);
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }

    /// How many entries the flow table holds, for a property about state rather than packets.
    pub(crate) fn flows(&self) -> Option<usize> {
        self.flow_table.len()
    }

    /// Send several packets through as one burst, and hand back what came out.
    ///
    /// Not the same code path as calling [`Self::send`] repeatedly. `FlowFilter::process` collects
    /// its whole input before doing anything, so that it can pool the classifications into batched
    /// `rte_acl` calls -- which means that in a burst, every packet has been through `FlowLookup`
    /// before any of them reaches the nat stages. This is how the driver actually feeds the
    /// pipeline: one bounded rx burst per poll.
    pub(crate) fn send_batch(
        &mut self,
        packets: Vec<Packet<TestBuffer>>,
    ) -> Vec<Packet<TestBuffer>> {
        let sent = packets.len();
        let out: Vec<_> = self.pipeline.process(packets.into_iter()).collect();
        assert_eq!(out.len(), sent, "the pipeline did not return every packet");
        out
    }
}

/// The VPC a packet enters from.
pub(crate) fn local() -> VpcDiscriminant {
    VpcDiscriminant::VNI(Vni::new_checked(LOCAL_VNI).unwrap_or_else(|_| unreachable!()))
}

/// The VPC on the far side of the peering.
pub(crate) fn remote() -> VpcDiscriminant {
    VpcDiscriminant::VNI(Vni::new_checked(REMOTE_VNI).unwrap_or_else(|_| unreachable!()))
}

/// Stamp a packet as an overlay arrival from `src`, the way `IpForwarder` does after decapsulation.
///
/// `dst_vpcd` is deliberately left unset: the flow filter is what decides it, and setting it here
/// would skip the stage under test. See the note in `nat::masquerade::probe` -- an arrival is not
/// always a single stamp, and getting it wrong makes a harness lie.
pub(crate) fn arrive(packet: &mut Packet<TestBuffer>, src: VpcDiscriminant) {
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(src);
    // Keep a dropped packet rather than letting `enforce` swallow it, so a verdict can be read.
    packet.meta_mut().set_keep(true);
}

/// What the pipeline did with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Forwarded, with the VPC the flow filter chose.
    ///
    /// This is what the *overlay slice* produces, because it has no egress stage to hand the
    /// packet to. A routed fabric never returns it.
    Forwarded {
        dst_vpcd: Option<VpcDiscriminant>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    /// Framed and handed to an interface, with what it looked like on the wire.
    ///
    /// `Egress` finishes a packet with `DoneReason::Delivered`, which is a success and not a drop.
    /// Kept distinct from [`Verdict::Dropped`] so that a test cannot assert "not dropped" and
    /// accidentally accept a delivery, or the other way about.
    Delivered {
        oif: Option<InterfaceIndex>,
        src: Option<IpAddr>,
        dst: Option<IpAddr>,
    },
    /// Dropped, with the reason the stage that dropped it gave.
    Dropped(DoneReason),
}

pub(crate) fn verdict(packet: &Packet<TestBuffer>) -> Verdict {
    match packet.get_done() {
        Some(DoneReason::Delivered) => Verdict::Delivered {
            oif: packet.meta().oif,
            src: packet.ip_source(),
            dst: packet.ip_destination(),
        },
        Some(reason) => Verdict::Dropped(reason),
        None => Verdict::Forwarded {
            dst_vpcd: packet.meta().dst_vpcd,
            src: packet.ip_source(),
            dst: packet.ip_destination(),
        },
    }
}

/// How many bytes of driver input a property here may draw before it is truncated.
///
/// The default is 4096, and it is not a cap on the *corpus entry* -- it is the point at which
/// `bolero`'s byte driver stops reading and **fills the rest of every draw with zeros**. Nothing
/// fails when that happens. The generator returns a value, the property runs, and the tail of the
/// batch is a run of identical all-zero stacks: shape zero, address zero, port zero. It looks like
/// coverage and is not.
///
/// That matters more here than for the single-value generators elsewhere in the tree, because a
/// batch draws a configuration *and* sixteen header stacks from one input. Measured by
/// [`the_generators_fit_the_input_budget`], `acl::Batch` wanted a median of 3001 bytes and a
/// maximum of 7272 -- so at the default more than half of its inputs were being cut short, and the
/// half being cut were the rich ones: deep chains, extension headers, ipv4 options. The fuzzer was
/// being steered away from complexity at exactly the point complexity begins.
///
/// Sized with room to grow rather than to the measurement: the driver only truncates, so a budget
/// larger than any generator wants costs nothing at all, and a budget that has to be revisited
/// every time a shape is added is a budget nobody will revisit.
///
/// The engine has a separate limit of its own. See `just fuzz` -- raising this constant alone
/// changes nothing under libfuzzer, which will not offer an input longer than its `-max_len`.
pub(crate) const MAX_INPUT_LEN: usize = 65536;

/// The largest number of bytes `generator` drew across `SAMPLES` runs against an unlimited budget.
///
/// Not an exact figure -- a generator's demand is a distribution and this is the top of a sample --
/// which is why [`MAX_INPUT_LEN`] is sized well above what it reports rather than to it.
#[cfg(test)]
fn largest_draw<G: bolero::ValueGenerator>(generator: &G) -> usize {
    use bolero::generator::bolero_generator::driver::{Options, bytes::Driver};

    const SAMPLES: usize = 64;
    /// Larger than any plausible demand, so the measurement is of the generator and not of this.
    const UNLIMITED: usize = 1 << 20;

    let options = Options::default().with_max_len(UNLIMITED);
    // A deterministic stream rather than a random one: the generator needs bytes that vary, and a
    // test whose reported figure moves between runs is one nobody can act on.
    let mut state: u64 = 0x243f_6a88_85a3_08d3;
    let mut bytes = vec![0u8; UNLIMITED];
    (0..SAMPLES)
        .map(|_| {
            for byte in &mut bytes {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                // Truncation is the point: the top bits of an LCG are the ones worth keeping.
                #[allow(clippy::cast_possible_truncation)]
                {
                    *byte = (state >> 33) as u8;
                }
            }
            let mut driver = Driver::new(&bytes[..], &options);
            assert!(
                generator.generate(&mut driver).is_some(),
                "the generator gave up on a budget it cannot exhaust"
            );
            UNLIMITED - driver.as_slice().len()
        })
        .max()
        .unwrap_or_else(|| unreachable!("SAMPLES is not zero"))
}

/// No generator here draws more than [`MAX_INPUT_LEN`], with room to spare.
///
/// The failure this guards against is silent, which is the only reason it is worth a test. A
/// generator that outgrows the budget does not error -- it starts getting zeros, and the property
/// built on it goes on passing while testing less than it says. Enriching a shape is exactly the
/// kind of change that would do it, and exactly the kind nobody would think to re-measure after.
///
/// Called from each module rather than centrally so that each `Batch` can stay private to the
/// module that owns it.
#[cfg(test)]
fn assert_within_budget<G: bolero::ValueGenerator>(name: &str, generator: &G) {
    let largest = largest_draw(generator);
    eprintln!("{name}: largest draw {largest} of {MAX_INPUT_LEN} bytes");
    assert!(
        largest * 2 <= MAX_INPUT_LEN,
        "{name} drew {largest} bytes, over half of the {MAX_INPUT_LEN} budget. Raise \
         MAX_INPUT_LEN and `just fuzz`'s `-l`, or the tail of every batch will be zeros."
    );
}

/// Assert a coverage guard, naming the one way it fails that is not a defect.
///
/// These guards say a property was not vacuous -- that the inputs actually reached the behaviour
/// under test. There is one benign way to fail them, and it costs an afternoon to work out from
/// first principles: a `__fuzz__` corpus sitting beside this file, left by `just fuzz`.
///
/// `bolero` replays that corpus before it explores randomly, and a coverage-guided corpus is
/// selected for the *unusual* -- entries earn their place by reaching an edge nothing else reached,
/// which in a pipeline means error paths. A large one can consume the whole time budget before the
/// random phase starts, and a run made entirely of interesting inputs can contain no ordinary ones
/// at all. That is the corpus working as designed, and it is not this property failing.
#[cfg(test)]
fn assert_covered(covered: bool, what: &str) {
    assert!(
        covered,
        "{what}. Check for a `__fuzz__` corpus beside this test before reading further: replaying \
         one can spend the budget on inputs chosen for being unusual. Move it aside and re-run to \
         tell that apart from a real gap."
    );
}

/// A stage that changes nothing and checks something.
///
/// The pipeline is a chain of [`NetworkFunction`]s and nothing says a stage has to *do* anything,
/// so a contract between two stages can be a stage. What that buys over asserting at the end of
/// the pipeline is three things: attribution, because a violation names the boundary it happened
/// at; reach, because facts a later stage destroys are visible here and nowhere else -- the inner
/// packet exists only between decapsulation and re-encapsulation, and `dst_vpcd` is set by
/// `FlowFilter` and consumed by `IpForwarder`; and leverage, because a contract asserted here is
/// asserted on every packet of every property in this module rather than needing a property of its
/// own.
///
/// # Two rules, both structural
///
/// **A checkpoint is lazy.** `FlowFilter::process` collects its whole input, and that barrier is
/// what decides which packets can see each other's effects -- it is the mechanism behind the
/// allocation defect in `a_burst_of_one_flow_allocates_once`. A checkpoint that collected would
/// introduce a second barrier and change the behaviour it is supposed to be observing.
///
/// **A checkpoint cannot drop or modify a packet.** Hence `inspect` rather than the `filter_map`
/// and `enforce` every real stage uses: the signature is what enforces it, not a comment. A checkpoint must also not
/// serialize a packet, because `Packet::serialize` recomputes checksums -- an observer that
/// repaired what it was watching for.
pub(crate) struct Checkpoint<F> {
    at: &'static str,
    check: F,
}

impl<F> Checkpoint<F> {
    pub(crate) fn new(at: &'static str, check: F) -> Self {
        Self { at, check }
    }
}

impl<Buf: PacketBufferMut, F: Fn(&str, &Packet<Buf>) + 'static> NetworkFunction<Buf>
    for Checkpoint<F>
{
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        // `inspect` rather than `map`: the signature is the guarantee. A checkpoint is handed a
        // shared reference and returns nothing, so it cannot modify a packet, and `inspect` cannot
        // drop one.
        input.inspect(move |packet| (self.check)(self.at, packet))
    }
}

/// The contracts every routed fabric checks at every stage boundary.
///
/// Each is a promise made by the stage before it, taken from that stage's code rather than from
/// what it would be nice for it to do -- a contract a stage does not actually make turns a working
/// pipeline into a failing test, which is worse than no contract at all.
mod contract {
    use super::*;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// How many packets each contract has actually judged, as opposed to waved past its guard.
    ///
    /// A contract is a property, and it goes vacuous the same way: every one here begins by
    /// excusing packets it does not apply to, and a guard that excuses *everything* is a contract
    /// that has never once been evaluated while looking exactly like one that always holds.
    /// [`every_contract_is_reached`] is what says otherwise.
    pub(super) static JUDGED: LazyLock<[AtomicU64; 4]> =
        LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

    pub(super) const DECAPSULATED: usize = 0;
    pub(super) const PLACED: usize = 1;
    pub(super) const READY: usize = 2;
    pub(super) const FINISHED: usize = 3;

    fn judged(which: usize) {
        JUDGED[which].fetch_add(1, Ordering::Relaxed);
    }

    /// `IpForwarder` decapsulates and annotates. A frame it has made overlay traffic knows which
    /// vpc it came from and which fib to route it in; the overlay stages downstream read both, and
    /// `arrive` in this module fakes exactly this stamp for the fabrics that skip the forwarder.
    /// So this is also what says that fake is faithful.
    pub(super) fn decapsulated<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().is_overlay() {
            return;
        }
        judged(DECAPSULATED);
        assert!(
            packet.meta().src_vpcd.is_some(),
            "{at}: overlay traffic with no source vpc discriminant"
        );
        assert!(
            packet.meta().vrf.is_some(),
            "{at}: overlay traffic with no vrf to route it in"
        );
    }

    /// `FlowFilter` is what decides where a packet goes. A packet it lets past has been given a
    /// destination; one it could not place is dropped, not forwarded.
    ///
    /// `shapes::every_shape_leaves_the_pipeline_with_a_verdict` asserts this at the *end* of the
    /// pipeline, which is weaker: a later stage setting `dst_vpcd` would satisfy it. Here it is a
    /// claim about the stage that owes it.
    pub(super) fn placed<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().is_overlay() {
            return;
        }
        judged(PLACED);
        assert!(
            packet.meta().dst_vpcd.is_some(),
            "{at}: forwarded without a destination vpc: nothing chose where this packet goes"
        );
    }

    /// What `Masquerade::process_packet` calls a bug in a `debug_assert` and then drops.
    ///
    /// **This one has no reachable violation today, and that is worth saying rather than leaving
    /// to be discovered.** Every way of removing a discriminant before masquerade is caught by a
    /// stage in between -- `StaticNat` and `PortForwarder` finish such a packet, so it arrives here
    /// already `done` and the guard correctly excuses it. Clearing `src_vpcd` in
    /// `FlowFilter` produces `done=true, masq=true, src=None` at this boundary.
    ///
    /// Two different things get confused here and the distinction matters. It is *not vacuous* --
    /// [`super::smoke::every_contract_is_reached`] shows it judges ordinary traffic, so its guard
    /// is not excusing everything. It is *unfalsifiable*, which is a claim about the pipeline
    /// rather than about the contract: no current arrangement of stages can violate it.
    ///
    /// Kept, because what it guards is a reordering. Move masquerade ahead of the stages that
    /// currently catch this, or drop their checks, and this is what notices.
    pub(super) fn ready_to_translate<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        if packet.is_done() || !packet.meta().requires_masquerade() {
            return;
        }
        judged(READY);
        assert!(
            packet.meta().src_vpcd.is_some() && packet.meta().dst_vpcd.is_some(),
            "{at}: a packet is to be masqueraded without both discriminants, which masquerade \
             itself calls a bug"
        );
    }

    /// `Egress` frames a packet and finishes it, one way or another. A packet leaving it unfinished
    /// is one nothing further will look at and nothing has sent.
    pub(super) fn finished<Buf: PacketBufferMut>(at: &str, packet: &Packet<Buf>) {
        judged(FINISHED);
        assert!(
            packet.is_done(),
            "{at}: a packet left the last stage of the pipeline without a verdict"
        );
    }
}

/// The underlay the routed fabric sits on.
///
/// One uplink, carrying tunnelled traffic in both directions. The addresses are the ones
/// `net`'s vxlan fixture already uses, so that a frame built by
/// `build_test_vxlan_ipv4_packet_carrying` is addressed to this gateway without the test having to
/// rewrite the outer header -- and, more usefully, so that a test that *does* rewrite it is saying
/// something.
pub(crate) const UPLINK: u32 = 1;
/// The address the fixture's tunnelled frames are sent to: this gateway's vtep.
pub(crate) const LOCAL_VTEP: &str = "5.6.7.8";
/// The vtep on the other end, which is both where frames come from and where they go back to.
pub(crate) const PEER_VTEP: &str = "1.2.3.4";
/// This gateway's mac, used as the uplink's and as the vtep's.
pub(crate) const GATEWAY_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xaa]);
/// The peer's mac, which is what an adjacency for [`PEER_VTEP`] resolves to.
pub(crate) const PEER_MAC: Mac = Mac([0x02, 0, 0, 0, 0, 0xbb]);

/// The vrf a tunnelled frame arrives in, before it is anybody's overlay traffic.
const UNDERLAY_VRF: u32 = 0;

pub(crate) fn uplink() -> InterfaceIndex {
    InterfaceIndex::try_new(UPLINK).unwrap_or_else(|_| unreachable!())
}

/// Build the tables the underlay stages read.
///
/// Three fibs. The underlay one has a single host route for this gateway's vtep whose instruction
/// is `Local`, which is what makes `IpForwarder` decapsulate rather than route onward -- the
/// tunnel endpoint is not a special case in the forwarding path, it is a route.
///
/// The two overlay fibs are reached by vni and are deliberately symmetric: each carries an
/// encapsulation back out towards [`PEER_VTEP`]. Both vpcs living behind one remote endpoint is a
/// simplification -- a real fabric would have a vtep per host -- but it is the simplification that
/// keeps the *asymmetry under test* in the pipeline rather than in the topology. A fixture that
/// could only encapsulate one way would make a reply fail for a reason no property is about.
pub(crate) fn topology(vnis: &[Vni]) -> RouterTables {
    let mut tables = RouterTables::new();

    tables.vrf(UNDERLAY_VRF, None);
    tables.interface(
        uplink(),
        "uplink",
        SourceMac::new(GATEWAY_MAC).unwrap_or_else(|_| unreachable!()),
    );
    tables.attach(uplink(), UNDERLAY_VRF);
    tables.route_via(
        UNDERLAY_VRF,
        Prefix::expect_from((LOCAL_VTEP, 32)),
        nhop(&LOCAL_VTEP.parse().unwrap_or_else(|_| unreachable!())),
        &FibGroup::with_entry(FibEntry::with_inst(PktInstruction::Local(uplink()))),
    );

    // One fib per vni, each numbered by it: a fib is reached by vni, so a vrf id that is the vni
    // keeps the two from having to be kept in step by hand.
    for reachable in vnis {
        tables.vrf(reachable.as_u32(), Some(*reachable));
        encapsulate_out_of(&mut tables, reachable.as_u32(), *reachable);
    }

    tables.adjacency(
        PEER_VTEP.parse().unwrap_or_else(|_| unreachable!()),
        uplink(),
        PEER_MAC,
    );

    tables
}

/// Give `vrfid` a vtep and a route that tunnels everything leaving it towards [`PEER_VTEP`].
///
/// A default route rather than the peering's translated range: what a masquerading expose turns an
/// address into is the nat stages' business, and a topology that had to agree with them would be a
/// second copy of the translation to keep correct.
fn encapsulate_out_of(tables: &mut RouterTables, vrfid: u32, out_vni: Vni) {
    tables.vtep(
        vrfid,
        Vtep::with_ip_and_mac(
            LOCAL_VTEP.parse().unwrap_or_else(|_| unreachable!()),
            GATEWAY_MAC,
        ),
    );
    let peer: IpAddr = PEER_VTEP.parse().unwrap_or_else(|_| unreachable!());
    let mut out = FibEntry::with_inst(PktInstruction::Encap(ResolvedEncapsulation::Vxlan(
        ResolvedVxlan {
            vni: out_vni,
            remote: peer,
            dmac: PEER_MAC,
        },
    )));
    out.add(PktInstruction::Egress(EgressObject::new(
        Some(uplink()),
        Some(peer),
    )));
    tables.route_via(vrfid, Prefix::root_v4(), nhop(&peer), &FibGroup::with_entry(out));
}

/// A next hop is only an identity here: it names the group a route resolves to, and the tests
/// install one group per route, so an address is enough to keep them apart.
fn nhop(address: &IpAddr) -> NhopKey {
    NhopKey::new(
        RouteOrigin::default(),
        Some(*address),
        None,
        None,
        FwAction::Forward,
    )
}

fn vni(raw: u32) -> Vni {
    Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
}

#[cfg(test)]
mod smoke {
    use super::*;
    use lpm::prefix::Prefix;
    use net::packet::test_utils::build_test_udp_ipv4_packet;

    fn masquerade_expose() -> VpcExpose {
        VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("1.1.0.0/16".parse::<Prefix>().unwrap().into())
            .as_range("2.2.0.0/16".parse::<Prefix>().unwrap().into())
            .unwrap()
    }

    /// Every contract is actually evaluated by an ordinary routed fabric.
    ///
    /// Each contract begins by excusing packets it does not apply to, so each can go vacuous
    /// without saying so: a guard that excuses everything looks exactly like a contract that always
    /// holds. This runs one packet all the way through and requires all four to have judged it.
    ///
    /// It is also what caught the one that was not being reached. `ready_to_translate` guards on
    /// `requires_masquerade()`, and a fabric whose peering does not masquerade never sets it -- so
    /// the contract sat in the pipeline judging nothing.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn every_contract_is_reached() {
        use net::packet::test_utils::build_test_udp_ipv4_packet;

        let before: Vec<u64> = contract::JUDGED
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .collect();

        let mut fabric = Fabric::routed(&routed::exposes(), None).expect("a valid configuration");
        let inner = build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80);
        let out = fabric.send(routed::tunnelled(&inner));
        assert!(
            matches!(verdict(&out), Verdict::Delivered { .. }),
            "the fixture packet did not reach the wire: {:?}",
            verdict(&out)
        );

        for (i, name) in [
            "decapsulated",
            "placed",
            "ready_to_translate",
            "finished",
        ]
        .iter()
        .enumerate()
        {
            let after = contract::JUDGED[i].load(std::sync::atomic::Ordering::Relaxed);
            assert!(
                after > before[i],
                "the `{name}` contract judged no packet of an ordinary delivered flow: its guard \
                 excuses everything, so it holds without ever having been evaluated"
            );
        }
    }

    /// The harness wires a pipeline that behaves like the one in `start_router`.
    ///
    /// Not a property: it is the fixture for the properties, and a fixture that quietly stopped
    /// translating would make every property below vacuously true. Asserting the translation here
    /// is what stops that.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn the_harness_builds_a_pipeline_that_translates() {
        let mut fabric = Fabric::build(&[masquerade_expose()]).expect("a valid configuration");

        let mut packet = build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80);
        arrive(&mut packet, local());
        let out = fabric.send(packet);

        match verdict(&out) {
            Verdict::Forwarded { dst_vpcd, src, dst } => {
                assert_eq!(dst_vpcd, Some(remote()), "the flow filter chose no peer");
                let IpAddr::V4(src) = src.expect("no source") else {
                    panic!("came out IPv6")
                };
                assert_eq!(src.octets()[..2], [2, 2], "not masqueraded into the range");
                assert_eq!(dst, Some("3.3.3.1".parse().unwrap()));
            }
            Verdict::Dropped(reason) => panic!("the packet was dropped: {reason:?}"),
            Verdict::Delivered { .. } => {
                unreachable!("the overlay slice has no egress stage")
            }
        }
    }
}

/// Header shapes fed through the whole pipeline.
///
/// The generator here is reused by [`super::routed`], which runs the same shapes through the full
/// pipeline inside a tunnel.
///
/// Deliberately not "arbitrary bytes". The interesting shapes are the ones that parse into
/// something legal and unusual -- a tag, an extension header chain, a transport nobody has a
/// parser for -- because those are what a stage reaches into and reads wrong. Random bytes mostly
/// fail to parse and never reach a stage at all.
#[cfg(test)]
mod shapes {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
    use lpm::prefix::Prefix;
    use net::headers::builder::ChainBase;
    use net::headers::{Headers, TryIpv4Mut, TryIpv6Mut};
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_EXPOSES: u8 = 2;

    /// The shapes generated, named so coverage can be required for each.
    ///
    /// `Vlan*` and `*Ext*` are the two that motivated this harness: both were legal, both were
    /// read wrong, and neither was reachable from a single stage's own generator.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Shape {
        V4Tcp,
        V4Udp,
        V4Icmp,
        VlanV4Tcp,
        V4ExoticProto,
        V6Tcp,
        V6HopByHopTcp,
        V6FragmentUdp,
        NoIp,
    }

    impl Shape {
        pub(super) const ALL: [Shape; 9] = [
            Shape::V4Tcp,
            Shape::V4Udp,
            Shape::V4Icmp,
            Shape::VlanV4Tcp,
            Shape::V4ExoticProto,
            Shape::V6Tcp,
            Shape::V6HopByHopTcp,
            Shape::V6FragmentUdp,
            Shape::NoIp,
        ];
    }

    /// How many stacks share one built pipeline.
    ///
    /// Building one costs an `rte_acl` table compile, which dwarfs the cost of pushing a packet
    /// through it -- a fabric per stack spends the whole budget on configuration. A batch also
    /// buys something the single-packet form cannot: the stages share a flow table, so later
    /// packets meet the state earlier ones created, which is the pipeline's actual behaviour.
    const STACKS_PER_FABRIC: usize = 16;

    struct AnyStack;

    impl ValueGenerator for AnyStack {
        type Output = (Shape, Headers);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<(Shape, Headers)> {
            let shape = Shape::ALL[usize::from(driver.produce::<u8>()?) % Shape::ALL.len()];
            let headers = match shape {
                Shape::NoIp => ChainBase::new().eth(|_| {}).generate(driver),
                Shape::V4Tcp => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                Shape::V4Udp => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .udp(|_| {})
                    .generate(driver),
                Shape::V4Icmp => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .generate(driver),
                Shape::VlanV4Tcp => ChainBase::new()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                // A protocol number with no transport parser: the chain ends at the IP header.
                Shape::V4ExoticProto => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.set_next_header(net::ip::NextHeader::new(132));
                    })
                    .generate(driver),
                Shape::V6Tcp => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                Shape::V6HopByHopTcp => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                Shape::V6FragmentUdp => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .fragment(|_| {})
                    .udp(|_| {})
                    .generate(driver),
            }?;
            Some((shape, headers))
        }
    }

    /// One configuration and the stacks to run against it.
    pub(super) struct Batch;

    impl ValueGenerator for Batch {
        type Output = (Vec<VpcExpose>, Vec<(Shape, Headers)>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;
            let mut stacks = Vec::with_capacity(STACKS_PER_FABRIC);
            for _ in 0..STACKS_PER_FABRIC {
                stacks.push(AnyStack.generate(driver)?);
            }
            Some((exposes, stacks))
        }
    }

    /// Point a generated stack at the configuration, so it has a chance of being forwarded.
    ///
    /// Addresses drawn independently of the overlay miss every table, and a property driven by one
    /// explores the miss path and nothing else -- the argument `nat::static_nat::probe` makes about
    /// packets, applied to whole stacks.
    pub(super) fn aim(headers: &mut Headers, private: Option<Prefix>) {
        let Some(private) = private else { return };
        match private.as_address() {
            IpAddr::V4(addr) => {
                if let Some(ip) = headers.try_ipv4_mut() {
                    ip.set_source(
                        UnicastIpv4Addr::new(addr).unwrap_or_else(|_| unreachable!("prefix base")),
                    );
                    ip.set_destination(
                        "3.3.3.1"
                            .parse::<Ipv4Addr>()
                            .unwrap_or_else(|_| unreachable!()),
                    );
                }
            }
            IpAddr::V6(addr) => {
                if let Some(ip) = headers.try_ipv6_mut() {
                    ip.set_source(
                        UnicastIpv6Addr::new(addr).unwrap_or_else(|_| unreachable!("prefix base")),
                    );
                    ip.set_destination(
                        "2001:db8:ffff::1"
                            .parse::<Ipv6Addr>()
                            .unwrap_or_else(|_| unreachable!()),
                    );
                }
            }
        }
    }

    pub(super) fn wire(headers: &Headers) -> Option<Packet<TestBuffer>> {
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("shapes::Batch", &Batch);
    }

    /// Every packet leaves the pipeline with a verdict, whatever shape it arrived in.
    ///
    /// The weakest thing worth saying end to end, and the one both of this week's defects would
    /// have failed differently: a forwarded packet must have been given a destination VPC by the
    /// flow filter, and a dropped one must carry the reason of whichever stage refused it. A stage
    /// that reaches into a chain it did not account for produces neither -- it produces a packet
    /// forwarded on the strength of fields somebody read out of the wrong place.
    ///
    /// It does not say the verdict is *right*; the oracle for that is the next property. It says
    /// that one was reached, by a stage that meant to reach it.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn every_shape_leaves_the_pipeline_with_a_verdict() {
        static FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DROPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static BY_SHAPE: LazyLock<[AtomicU64; Shape::ALL.len()]> =
            LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(|(exposes, stacks)| {
                // The pipeline holds rte_acl tables and a flow table, neither of which is safe to
                // carry across bolero's unwind boundary; build one per batch.
                let Some(mut fabric) = Fabric::build(exposes) else {
                    return;
                };
                let private = exposes.first().and_then(|e| {
                    e.ips
                        .first()
                        .map(lpm::prefix::PrefixWithOptionalPorts::prefix)
                });

                for (shape, headers) in stacks {
                    let mut headers = headers.clone();
                    aim(&mut headers, private);
                    let Some(mut packet) = wire(&headers) else {
                        continue;
                    };
                    BY_SHAPE[*shape as usize].fetch_add(1, Ordering::Relaxed);

                    arrive(&mut packet, local());
                    let out = fabric.send(packet);

                    match verdict(&out) {
                        Verdict::Forwarded { dst_vpcd, .. } => {
                            assert_eq!(
                                dst_vpcd,
                                Some(remote()),
                                "forwarded without a destination VPC, on a {shape:?} stack: \
                                 nothing chose where this packet goes"
                            );
                            FORWARDED.fetch_add(1, Ordering::Relaxed);
                        }
                        Verdict::Dropped(_) => {
                            DROPPED.fetch_add(1, Ordering::Relaxed);
                        }
                        Verdict::Delivered { .. } => {
                            unreachable!("the overlay slice has no egress stage")
                        }
                    }
                }
            });

        let forwarded = FORWARDED.load(Ordering::Relaxed);
        let dropped = DROPPED.load(Ordering::Relaxed);
        let by_shape: Vec<_> = Shape::ALL
            .iter()
            .map(|s| format!("{s:?}={}", BY_SHAPE[*s as usize].load(Ordering::Relaxed)))
            .collect();
        eprintln!(
            "forwarded={forwarded} dropped={dropped}; {}",
            by_shape.join(" ")
        );

        super::assert_covered(
            forwarded > 0,
            "no packet was ever forwarded: the harness is exercising the drop path only",
        );
        super::assert_covered(dropped > 0, "no packet was ever dropped");
        for shape in Shape::ALL {
            super::assert_covered(
                BY_SHAPE[shape as usize].load(Ordering::Relaxed) > 0,
                &format!("no {shape:?} packet ever reached the pipeline"),
            );
        }
    }
}

/// Flows driven out and back through the whole pipeline.
///
/// The shape property above says a verdict was reached. This says the verdict was *right*, using
/// the only end-to-end oracle that does not restate the code: a translation the pipeline applied
/// on the way out has to be undone on the way back, by a different path through the same stages.
/// Nothing in the harness computes what the translation should be -- it is read off the outgoing
/// packet and required to reverse.
#[cfg(test)]
mod round_trip {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
    use net::headers::builder::HeaderStack;
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use net::udp::UdpPort;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_EXPOSES: u8 = 2;
    const FLOWS_PER_FABRIC: usize = 8;

    /// A flow to try: which private prefix it comes from, and the ports it uses.
    #[derive(Debug, Clone, Copy)]
    struct FlowSpec {
        prefix: u8,
        host: u8,
        sport: u16,
        dport: u16,
    }

    struct Batch;

    impl ValueGenerator for Batch {
        type Output = (Vec<VpcExpose>, Vec<FlowSpec>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;
            let mut flows = Vec::with_capacity(FLOWS_PER_FABRIC);
            for _ in 0..FLOWS_PER_FABRIC {
                flows.push(FlowSpec {
                    prefix: driver.produce()?,
                    host: driver.produce()?,
                    // Port 0 is not a port; masquerade would refuse it for reasons that have
                    // nothing to do with whether a translation reverses.
                    sport: driver.produce::<u16>()?.max(1),
                    dport: driver.produce::<u16>()?.max(1),
                });
            }
            Some((exposes, flows))
        }
    }

    /// The private addresses a configuration exposes, one per prefix.
    ///
    /// One address per prefix rather than every address: masquerade puts many private addresses
    /// behind few public ones, so the prefixes are large and enumerating them buys no new
    /// behaviour. What matters is that distinct sources contend for the same public range.
    fn private_addresses(exposes: &[VpcExpose]) -> Vec<Prefix> {
        exposes
            .iter()
            .flat_map(|e| e.ips.iter().map(PrefixWithOptionalPorts::prefix))
            .collect()
    }

    /// The far side of the peering, which `overlay_with_exposes` fixes by address family.
    fn peer(family_of: IpAddr) -> IpAddr {
        match family_of {
            IpAddr::V4(_) => IpAddr::V4(
                "3.3.3.1"
                    .parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
            IpAddr::V6(_) => IpAddr::V6(
                "2001:db8:ffff::1"
                    .parse::<Ipv6Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
        }
    }

    /// A UDP packet, ready to be routed.
    ///
    /// The hop count is set because `Ipv4::default()` and `Ipv6::default()` leave it at zero, and
    /// a packet with no hops left is not traffic anybody sends -- it is a packet that has already
    /// expired. The overlay slice does not care, having no forwarding stage to decrement it, which
    /// is exactly why the omission survived here: `routed`'s properties put the same packets
    /// through `IpForwarder` and every one of them died at the first decrement.
    pub(super) fn udp(
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
    ) -> Option<Packet<TestBuffer>> {
        // Validated out here: the header-stack closures cannot fail, so anything that can reject
        // an input has to reject it before the stack is built.
        let sport = UdpPort::new_checked(sport).ok()?;
        let dport = UdpPort::new_checked(dport).ok()?;
        let headers = match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let src = UnicastIpv4Addr::new(src).ok()?;
                HeaderStack::new()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.set_source(src);
                        ip.set_destination(dst);
                        ip.set_ttl(64);
                    })
                    .udp(|udp| {
                        udp.set_source(sport);
                        udp.set_destination(dport);
                    })
                    .build_headers()
                    .ok()?
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let src = UnicastIpv6Addr::new(src).ok()?;
                HeaderStack::new()
                    .eth(|_| {})
                    .ipv6(|ip| {
                        ip.set_source(src);
                        ip.set_destination(dst);
                        ip.set_hop_limit(64);
                    })
                    .udp(|udp| {
                        udp.set_source(sport);
                        udp.set_destination(dport);
                    })
                    .build_headers()
                    .ok()?
            }
            _ => return None,
        };
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    /// A translation applied on the way out is undone on the way back.
    ///
    /// The reply is built from what came out, not from what went in: its source is the peer the
    /// request reached, its destination the public tuple the request was given. That is the packet
    /// the far side would actually send, and nothing in this test knows what the public tuple
    /// should have been -- only that whatever it was has to reverse.
    ///
    /// Five stages have to agree for this to hold: the flow filter has to find the peering in both
    /// directions, the flow table has to still hold the state masquerade created, and masquerade
    /// has to invert its own allocation. A single-stage harness can check the last of those and
    /// none of the rest.
    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("round_trip::Batch", &Batch);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_translated_flow_comes_back_to_where_it_started() {
        static ROUND_TRIPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static NOT_FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(|(exposes, flows)| {
                let Some(mut fabric) = Fabric::build(exposes) else {
                    return;
                };
                let privates = private_addresses(exposes);
                if privates.is_empty() {
                    return;
                }

                for flow in flows {
                    let prefix = privates[usize::from(flow.prefix) % privates.len()];
                    // The prefix base plus a small offset, so several flows share a prefix and
                    // contend for the same public range.
                    let src = match prefix.as_address() {
                        IpAddr::V4(a) => {
                            let mut o = a.octets();
                            o[3] = o[3].wrapping_add(flow.host % 8);
                            IpAddr::V4(Ipv4Addr::from(o))
                        }
                        IpAddr::V6(a) => {
                            let mut o = a.octets();
                            o[15] = o[15].wrapping_add(flow.host % 8);
                            IpAddr::V6(Ipv6Addr::from(o))
                        }
                    };
                    let dst = peer(src);

                    let Some(mut request) = udp(src, dst, flow.sport, flow.dport) else {
                        continue;
                    };
                    arrive(&mut request, local());
                    let out = fabric.send(request);

                    let Verdict::Forwarded {
                        src: public_src,
                        dst: reached,
                        ..
                    } = verdict(&out)
                    else {
                        NOT_FORWARDED.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let (Some(public_src), Some(reached)) = (public_src, reached) else {
                        continue;
                    };
                    let public_port = out
                        .transport_src_port()
                        .unwrap_or_else(|| unreachable!("a udp packet has a source port"))
                        .get();

                    // The reply the far side would send, addressed to what it actually saw.
                    let Some(mut reply) = udp(reached, public_src, flow.dport, public_port) else {
                        continue;
                    };
                    arrive(&mut reply, remote());
                    let back = fabric.send(reply);

                    match verdict(&back) {
                        Verdict::Forwarded { src: s, dst: d, .. } => {
                            assert_eq!(
                                d,
                                Some(src),
                                "the reply did not come back to the host that sent the request"
                            );
                            assert_eq!(s, Some(dst), "the reply's source was rewritten");
                            assert_eq!(
                                back.transport_dst_port().map(std::num::NonZero::get),
                                Some(flow.sport),
                                "the reply did not get the original source port back"
                            );
                            ROUND_TRIPPED.fetch_add(1, Ordering::Relaxed);
                        }
                        Verdict::Dropped(reason) => panic!(
                            "the reply of a forwarded flow was dropped: {reason:?} \
                             (request {src} -> {dst} became {public_src}:{public_port})"
                        ),
                        Verdict::Delivered { .. } => {
                            unreachable!("the overlay slice has no egress stage")
                        }
                    }
                }
            });

        let round_tripped = ROUND_TRIPPED.load(Ordering::Relaxed);
        eprintln!(
            "round-tripped={round_tripped} not-forwarded={}",
            NOT_FORWARDED.load(Ordering::Relaxed)
        );
        super::assert_covered(
            round_tripped > 0,
            "no flow was ever forwarded, so nothing was ever checked to come back",
        );
    }
}

/// ACL verdicts, read at the end of the pipeline rather than at the filter.
///
/// The configuration is shaped so its answer is knowable without evaluating it: one rule, matching
/// all of the peering's traffic in the request direction, discriminating only on protocol. The
/// oracle is then "does this packet's protocol match the rule's", and the packet's protocol is
/// known because the test built it -- not read back through the accessor the filter uses.
///
/// That narrowness is the point. The extension-header bypass was a stage reading the protocol out
/// of a field that names something else, and no property whose oracle asks the same accessor the
/// same question can see it.
#[cfg(test)]
mod acl {
    use super::*;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use config::external::overlay::acl::{AclAction, AclProtoMatch};
    use config::external::overlay::vpcpeering::contract::{MasqueradeExposes, peering_acl};
    use lpm::prefix::{Prefix, PrefixWithOptionalPorts};
    use net::headers::builder::ChainBase;
    use net::headers::{Headers, TryIpv4Mut, TryIpv6Mut};
    use net::ip::NextHeader;
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::parse::DeParse;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MAX_EXPOSES: u8 = 2;
    const PACKETS_PER_FABRIC: usize = 12;

    /// What the packet actually carries, and how it is wrapped.
    ///
    /// `behind_extension` is the whole reason this property exists: the protocol is the same, the
    /// rule's answer must be the same, and the field a careless reader would look at is different.
    #[derive(Debug, Clone, Copy, TypeGenerator)]
    struct PacketSpec {
        proto: Proto,
        behind_extension: bool,
        host: u8,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, TypeGenerator)]
    enum Proto {
        Tcp,
        Udp,
        Icmp,
    }

    impl Proto {
        /// The rule shape that names this protocol.
        fn as_match(self) -> AclProtoMatch {
            match self {
                Proto::Tcp => AclProtoMatch::Tcp,
                Proto::Udp => AclProtoMatch::Udp,
                // ICMP is not a first-class variant; it is matched by number, and the number
                // differs by address family.
                Proto::Icmp => AclProtoMatch::Other(NextHeader::ICMP.as_u8()),
            }
        }
    }

    /// Which protocol the generated rule names.
    #[derive(Debug, Clone, Copy, TypeGenerator)]
    enum RuleProto {
        Tcp,
        Udp,
        Icmp,
        Icmp6,
        Any,
    }

    impl RuleProto {
        fn as_match(self) -> AclProtoMatch {
            match self {
                RuleProto::Tcp => AclProtoMatch::Tcp,
                RuleProto::Udp => AclProtoMatch::Udp,
                RuleProto::Icmp => AclProtoMatch::Other(NextHeader::ICMP.as_u8()),
                RuleProto::Icmp6 => AclProtoMatch::Other(NextHeader::ICMP6.as_u8()),
                RuleProto::Any => AclProtoMatch::Any,
            }
        }
    }

    struct Batch;

    impl ValueGenerator for Batch {
        type Output = (Vec<VpcExpose>, bool, RuleProto, Vec<(PacketSpec, Headers)>);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let exposes = MasqueradeExposes(MAX_EXPOSES).generate(driver)?;
            // The packets have to be the family the exposes are, or they miss every table and the
            // ACL is never consulted.
            let v6 = exposes
                .first()
                .and_then(|e| e.ips.first())
                .is_some_and(|p| p.prefix().as_address().is_ipv6());
            let default_allow = driver.produce()?;
            let rule_proto = RuleProto::generate(driver)?;
            let mut packets = Vec::with_capacity(PACKETS_PER_FABRIC);
            for _ in 0..PACKETS_PER_FABRIC {
                let spec = PacketSpec::generate(driver)?;
                packets.push((spec, stack(driver, spec, v6)?));
            }
            Some((exposes, default_allow, rule_proto, packets))
        }
    }

    /// The protocol number a packet of this spec carries, in this address family.
    fn carried(proto: Proto, v6: bool) -> AclProtoMatch {
        match (proto, v6) {
            (Proto::Icmp, true) => AclProtoMatch::Other(NextHeader::ICMP6.as_u8()),
            (p, _) => p.as_match(),
        }
    }

    /// Whether the generated rule matches a packet carrying `carried`.
    fn rule_matches(rule: AclProtoMatch, carried: AclProtoMatch) -> bool {
        matches!(rule, AclProtoMatch::Any) || rule == carried
    }

    /// Build a header stack carrying `proto`, optionally behind an extension header.
    ///
    /// Done in the generator because that is where a driver exists; the address family is decided
    /// here too, since an IPv4 chain and an IPv6 chain are different types.
    fn stack<D: Driver>(driver: &mut D, spec: PacketSpec, v6: bool) -> Option<Headers> {
        if v6 {
            let chain = ChainBase::new().eth(|_| {}).ipv6(|_| {});
            if spec.behind_extension {
                let chain = chain.hop_by_hop(|_| {});
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp6(|_| {}).generate(driver),
                }
            } else {
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp6(|_| {}).generate(driver),
                }
            }
        } else {
            let chain = ChainBase::new().eth(|_| {}).ipv4(|_| {});
            if spec.behind_extension {
                // RFC 4302 Authentication Header: an IPv4 packet whose protocol field names the
                // extension rather than the transport, which is the v4 shape of the bug.
                let chain = chain.ipv4_auth(|_| {});
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp4(|_| {}).generate(driver),
                }
            } else {
                match spec.proto {
                    Proto::Tcp => chain.tcp(|_| {}).generate(driver),
                    Proto::Udp => chain.udp(|_| {}).generate(driver),
                    Proto::Icmp => chain.icmp4(|_| {}).generate(driver),
                }
            }
        }
    }

    fn wire(
        headers: &Headers,
        spec: PacketSpec,
        src: IpAddr,
        dst: IpAddr,
    ) -> Option<Packet<TestBuffer>> {
        let mut headers = headers.clone();
        aim(&mut headers, src, dst, spec.host);
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        Packet::new(buffer).ok()
    }

    fn aim(headers: &mut Headers, src: IpAddr, dst: IpAddr, host: u8) {
        match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                if let Some(ip) = headers.try_ipv4_mut() {
                    let mut o = src.octets();
                    o[3] = o[3].wrapping_add(host % 8);
                    if let Ok(src) = UnicastIpv4Addr::new(Ipv4Addr::from(o)) {
                        ip.set_source(src);
                    }
                    ip.set_destination(dst);
                }
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                if let Some(ip) = headers.try_ipv6_mut() {
                    let mut o = src.octets();
                    o[15] = o[15].wrapping_add(host % 8);
                    if let Ok(src) = UnicastIpv6Addr::new(Ipv6Addr::from(o)) {
                        ip.set_source(src);
                    }
                    ip.set_destination(dst);
                }
            }
            _ => {}
        }
    }

    fn peer(family_of: IpAddr) -> IpAddr {
        match family_of {
            IpAddr::V4(_) => IpAddr::V4(
                "3.3.3.1"
                    .parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
            IpAddr::V6(_) => IpAddr::V6(
                "2001:db8:ffff::1"
                    .parse::<Ipv6Addr>()
                    .unwrap_or_else(|_| unreachable!()),
            ),
        }
    }

    /// A packet the ACL denies never leaves, and one it permits is never dropped by the ACL.
    ///
    /// Two one-way claims rather than "forwarded iff permitted", because the ACL is not the only
    /// stage with an opinion and the ones ahead of it are allowed to have theirs. A generated
    /// ICMP error whose embedded packet does not parse is refused by `IcmpErrorHandler` before the
    /// ACL is consulted; a permitted packet can still fail to find a translation. Neither is the
    /// ACL letting something through.
    ///
    /// So: the deny direction is stated as "not forwarded", which is what a bypass violates, and
    /// the permit direction as "not `AclDropped`", which is what an over-strict filter violates.
    /// The counters below then have to show that some denial actually came *from* the ACL --
    /// otherwise a pipeline that dropped everything early would satisfy the deny direction
    /// vacuously.
    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("acl::Batch", &Batch);
    }

    #[tokio::test]
    #[dpdk::with_eal]
    async fn the_acl_verdict_follows_the_protocol_the_packet_carries() {
        static DENIED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PERMITTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static BEHIND_EXT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PERMITTED_OUT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DENIED_BY_ACL: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(
            |(exposes, default_allow, rule_proto, packets)| {
                let default = if *default_allow {
                    AclAction::Allow
                } else {
                    AclAction::Deny
                };
                let rule = rule_proto.as_match();
                let Some(mut fabric) =
                    Fabric::build_with_acl(exposes, Some(&peering_acl(default, rule)))
                else {
                    return;
                };
                let Some(private) = exposes
                    .iter()
                    .flat_map(|e| e.ips.iter().map(PrefixWithOptionalPorts::prefix))
                    .next()
                    .map(|p: Prefix| p.as_address())
                else {
                    return;
                };
                let v6 = private.is_ipv6();
                let dst = peer(private);

                for (spec, headers) in packets {
                    let Some(mut packet) = wire(headers, *spec, private, dst) else {
                        continue;
                    };
                    arrive(&mut packet, local());
                    let out = fabric.send(packet);

                    let permitted = rule_matches(rule, carried(spec.proto, v6)) != *default_allow;
                    if spec.behind_extension {
                        BEHIND_EXT.fetch_add(1, Ordering::Relaxed);
                    }

                    let seen = verdict(&out);
                    let acl_dropped = seen == Verdict::Dropped(DoneReason::AclDropped);
                    let forwarded = matches!(seen, Verdict::Forwarded { .. });
                    if permitted {
                        assert!(
                            !acl_dropped,
                            "the acl dropped a {:?} packet it permits (rule={rule:?} \
                             default={default:?} behind_extension={})",
                            spec.proto, spec.behind_extension
                        );
                        PERMITTED.fetch_add(1, Ordering::Relaxed);
                        if forwarded {
                            PERMITTED_OUT.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        assert!(
                            !forwarded,
                            "a {:?} packet the acl denies was forwarded (rule={rule:?} \
                             default={default:?} behind_extension={})",
                            spec.proto, spec.behind_extension
                        );
                        DENIED.fetch_add(1, Ordering::Relaxed);
                        if acl_dropped {
                            DENIED_BY_ACL.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            },
        );

        let (permitted, permitted_out, denied, denied_by_acl, behind) = (
            PERMITTED.load(Ordering::Relaxed),
            PERMITTED_OUT.load(Ordering::Relaxed),
            DENIED.load(Ordering::Relaxed),
            DENIED_BY_ACL.load(Ordering::Relaxed),
            BEHIND_EXT.load(Ordering::Relaxed),
        );
        eprintln!(
            "permitted={permitted} (forwarded {permitted_out}) denied={denied} \
             (by the acl {denied_by_acl}) behind-extension={behind}"
        );
        super::assert_covered(permitted > 0, "no packet was ever permitted");
        super::assert_covered(denied > 0, "no packet was ever denied");
        super::assert_covered(
            permitted_out > 0,
            "no permitted packet was ever forwarded: the permit direction is vacuous",
        );
        super::assert_covered(
            denied_by_acl > 0,
            "no denial ever came from the acl: the deny direction is being satisfied by stages \
             ahead of it, and would hold with the acl removed",
        );
        super::assert_covered(
            behind > 0,
            "no packet was ever sent behind an extension header, which is the shape this exists for",
        );
    }
}

/// Traffic arriving on a forwarded port, which nothing else here exercises.
///
/// Every routed property above configures masquerade, so the whole port-forwarding path -- an
/// outside host reaching a service inside a vpc, and that service's replies getting back out under
/// the address the outside host used -- has no end-to-end test at all.
///
/// It is also the only direction in this harness that starts outside. Masquerade traffic
/// originates in the local vpc and is answered; this originates in the peer.
#[cfg(test)]
mod port_forward {
    use super::routed::{inside, tunnelled_from};
    use super::round_trip::udp;
    use super::*;
    use config::external::overlay::vpcpeering::VpcExpose;
    use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithOptionalPorts};
    use net::headers::TryVxlan;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The service range inside the vpc, and the range the outside world reaches it on.
    ///
    /// Sized so that "the right one" is a real question: sixteen hosts and eight ports is 128
    /// distinct targets, and an implementation that ignored either offset would land on the wrong
    /// one almost every time. A /32 and a single port would be satisfied by a rule that forwarded
    /// everything to the only place there is.
    const INTERNAL_NET: &str = "10.0.5.0/28";
    const EXTERNAL_NET: &str = "172.16.5.0/28";
    const HOSTS: u8 = 16;
    const INTERNAL_PORT: u16 = 8000;
    const EXTERNAL_PORT: u16 = 9000;
    const PORTS: u16 = 8;

    fn expose() -> VpcExpose {
        VpcExpose::empty()
            .make_port_forwarding(None, Some(L4Protocol::Udp))
            .unwrap_or_else(|_| unreachable!("udp port forwarding is a valid flavour"))
            .ip(PrefixWithOptionalPorts::new(
                INTERNAL_NET
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!()),
                Some(
                    PortRange::new(INTERNAL_PORT, INTERNAL_PORT + PORTS - 1)
                        .unwrap_or_else(|_| unreachable!()),
                ),
            ))
            .as_range(PrefixWithOptionalPorts::new(
                EXTERNAL_NET
                    .parse::<Prefix>()
                    .unwrap_or_else(|_| unreachable!()),
                Some(
                    PortRange::new(EXTERNAL_PORT, EXTERNAL_PORT + PORTS - 1)
                        .unwrap_or_else(|_| unreachable!()),
                ),
            ))
            .unwrap_or_else(|_| unreachable!("the two ranges are the same size"))
    }

    /// Somewhere outside to reach in from.
    fn outside() -> IpAddr {
        "3.3.3.7".parse().unwrap_or_else(|_| unreachable!())
    }

    /// One attempt to reach the service.
    #[derive(Debug, Clone, Copy)]
    struct Reach {
        host: u8,
        port: u16,
        src_port: u16,
        /// Aimed at a port the expose does not declare, which must not be forwarded.
        past_the_range: bool,
    }

    struct Reaches;

    const REACHES_PER_FABRIC: usize = 8;

    impl bolero::ValueGenerator for Reaches {
        type Output = Vec<Reach>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Reach>> {
            (0..REACHES_PER_FABRIC)
                .map(|_| {
                    let choice = driver.produce::<u8>()?;
                    Some(Reach {
                        host: driver.produce::<u8>()? % HOSTS,
                        port: driver.produce::<u16>()? % PORTS,
                        src_port: driver.produce::<u16>()?.max(1),
                        // One in four past the range, so the negative half is exercised without
                        // swamping the positive half.
                        past_the_range: choice % 4 == 3,
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("port_forward::Reaches", &Reaches);
    }

    /// The service answers, from the tuple the request arrived on.
    ///
    /// Split out because the property that calls it is one loop making four assertions and clippy
    /// counts lines rather than claims. Returns whether a reply was checked, so the caller's
    /// coverage guard still counts what happened rather than what was attempted.
    fn answers(
        fabric: &mut Fabric,
        host: IpAddr,
        reach: Reach,
        external: IpAddr,
        dport: u16,
    ) -> bool {
        let Some(reply) = udp(
            host,
            outside(),
            INTERNAL_PORT + reach.port,
            reach.src_port,
        ) else {
            return false;
        };
        let back = fabric.send(tunnelled_from(vni(LOCAL_VNI), &reply));
        assert!(
            matches!(verdict(&back), Verdict::Delivered { .. }),
            "the service's reply did not get out: {:?}",
            verdict(&back)
        );
        assert_eq!(
            back.try_vxlan().map(net::vxlan::Vxlan::vni),
            Some(vni(REMOTE_VNI)),
            "the reply went back into the wrong vpc"
        );
        let answered = inside(&back).expect("a delivered reply was not tunnelled");
        assert_eq!(
            answered.ip_source(),
            Some(external),
            "the reply was sourced from the internal address, which the outside host never \
             addressed"
        );
        assert_eq!(
            answered.transport_src_port().map(std::num::NonZero::get),
            Some(dport),
            "the reply came from the right address on the wrong port"
        );
        assert_eq!(
            answered.ip_destination(),
            Some(outside()),
            "the reply did not reach the host that made the request"
        );
        true
    }

    /// A forwarded port reaches the host behind it, and answers from the address it was reached on.
    ///
    /// # The oracle
    ///
    /// The mapping is offset-preserving -- external host `k` port `j` is internal host `k` port
    /// `j` -- so the expected internal tuple is arithmetic on the offsets *this test chose*, not a
    /// lookup in the table the stage reads. Same move as `destination`: let the input carry the
    /// answer.
    ///
    /// # Three claims
    ///
    /// - **Forward.** A packet to a declared external address and port arrives at the internal
    ///   address and port that correspond to it. Both offsets are asserted, because a stage that
    ///   translated the address and forgot the port would satisfy either one alone.
    /// - **Back out.** The service's reply leaves under the *external* tuple the outside host
    ///   addressed. This is what makes port forwarding usable rather than merely reachable: a reply
    ///   sourced from the internal address would arrive at an outside host that never spoke to it.
    /// - **Past the range.** A packet to a port the expose does not declare is not forwarded. The
    ///   port is past the top of the range while the address is inside the prefix, so anything
    ///   matching on address alone would forward it. Refused by the *flow filter* rather than the
    ///   port forwarder -- `DoneReason::Filtered`, before nat is consulted -- which is the right
    ///   place for it and is what this half pins down: a lowering that dropped the port dimension
    ///   of a port-forwarding expose would let it through, and the two positive claims above would
    ///   not notice.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_forwarded_port_reaches_the_host_behind_it() {
        static FORWARDED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ANSWERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static REFUSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Reaches)
            .for_each(|reaches| {
                let Some(mut fabric) = Fabric::routed(&[expose()], None) else {
                    unreachable!("the port-forwarding fixture does not configure")
                };

                for reach in reaches {
                    let external: IpAddr = format!("172.16.5.{}", reach.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    let dport = if reach.past_the_range {
                        EXTERNAL_PORT + PORTS + (reach.port % PORTS)
                    } else {
                        EXTERNAL_PORT + reach.port
                    };

                    let Some(inbound) = udp(outside(), external, reach.src_port, dport) else {
                        continue;
                    };
                    let out = fabric.send(tunnelled_from(vni(REMOTE_VNI), &inbound));

                    if reach.past_the_range {
                        assert!(
                            !matches!(verdict(&out), Verdict::Delivered { .. }),
                            "a packet to {external}:{dport}, past the declared range, was \
                             forwarded anyway"
                        );
                        REFUSED.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    assert!(
                        matches!(verdict(&out), Verdict::Delivered { .. }),
                        "a packet to the declared {external}:{dport} was not forwarded: {:?}",
                        verdict(&out)
                    );
                    let arrived = inside(&out).expect("a forwarded packet was not tunnelled");
                    let expected_host: IpAddr = format!("10.0.5.{}", reach.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    assert_eq!(
                        arrived.ip_destination(),
                        Some(expected_host),
                        "{external}:{dport} reached the wrong host"
                    );
                    assert_eq!(
                        arrived.transport_dst_port().map(std::num::NonZero::get),
                        Some(INTERNAL_PORT + reach.port),
                        "{external}:{dport} reached the right host on the wrong port"
                    );
                    FORWARDED.fetch_add(1, Ordering::Relaxed);

                    if answers(&mut fabric, expected_host, *reach, external, dport) {
                        ANSWERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let (forwarded, answered, refused) = (
            FORWARDED.load(Ordering::Relaxed),
            ANSWERED.load(Ordering::Relaxed),
            REFUSED.load(Ordering::Relaxed),
        );
        eprintln!("forwarded={forwarded} answered={answered} refused={refused}");
        super::assert_covered(forwarded > 0, "no packet was ever forwarded to the service");
        super::assert_covered(answered > 0, "the service never answered");
        super::assert_covered(
            refused > 0,
            "no packet was ever aimed past the declared range, so the negative half is vacuous",
        );
    }
}

/// A burst, against the same packets sent one at a time.
///
/// The driver hands the pipeline one bounded rx burst per poll, and `FlowFilter::process` collects
/// that burst before doing anything so it can pool its classifications into batched `rte_acl`
/// calls. Every property above sends one packet at a time, so none of them has ever exercised the
/// shape the dataplane actually runs in.
#[cfg(test)]
mod burst {
    use super::routed::{exposes, inside, tunnelled, tunnelled_from};
    use super::round_trip::udp;
    use super::*;
    use net::headers::TryVxlan;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    const BURST: usize = 8;

    /// A flow to send. Distinct by construction -- see the property.
    #[derive(Debug, Clone, Copy)]
    struct Member {
        host: u8,
        dport: u16,
    }

    struct Burst;

    impl bolero::ValueGenerator for Burst {
        type Output = Vec<Member>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Member>> {
            (0..BURST)
                .map(|_| {
                    Some(Member {
                        host: driver.produce()?,
                        dport: driver.produce::<u16>()?.max(1),
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("burst::Burst", &Burst);
    }

    /// What a packet is treated as, in enough detail to compare two runs.
    #[derive(Debug, PartialEq, Eq)]
    struct Treatment {
        verdict: Verdict,
        vni: Option<u32>,
        inner_src: Option<IpAddr>,
        inner_dst: Option<IpAddr>,
        inner_sport: Option<u16>,
    }

    fn treatment(packet: &Packet<TestBuffer>) -> Treatment {
        let carried = inside(packet);
        Treatment {
            verdict: verdict(packet),
            vni: packet.try_vxlan().map(|v| v.vni().as_u32()),
            inner_src: carried.as_ref().and_then(Packet::ip_source),
            inner_dst: carried.as_ref().and_then(Packet::ip_destination),
            inner_sport: carried
                .as_ref()
                .and_then(Packet::transport_src_port)
                .map(std::num::NonZero::get),
        }
    }

    /// A burst carrying several packets of one flow allocates once for it.
    ///
    /// The case [`a_burst_is_treated_the_same_as_one_packet_at_a_time`] excludes by construction,
    /// and the one that was broken. `FlowLookup` stamps each packet with the flow state it found,
    /// `FlowFilter` collects the whole burst before anything downstream runs, so every packet of a
    /// burst is stamped before any of them is masqueraded. Masquerade read only the stamp, so a
    /// burst of sixteen UDP packets of one flow took sixteen ports out of the pool, left the far
    /// side seeing sixteen sources, and put sixteen reverse entries in the flow table. A TCP SYN
    /// and its first data segment in one burst had the data dropped as "TCP without SYN".
    ///
    /// Two things are asserted rather than one, because a fix that translated consistently while
    /// still allocating each time would satisfy the first alone:
    ///
    /// - every packet of the burst leaves with the **same** public source;
    /// - the flow table holds exactly what one flow needs, whatever the size of the burst.
    ///
    /// The second is the one that says the pool is not being drained. It is stated as a
    /// *comparison with a single packet* rather than a number, so it says "a burst costs what one
    /// packet costs" without this test having to know how many entries a flow is made of.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_burst_of_one_flow_allocates_once() {
        static CHECKED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Burst)
            .for_each(|members| {
                // One flow, drawn: which flow varies, that it is one flow does not.
                let m = members[0];
                let src: IpAddr = format!("1.1.0.{}", m.host)
                    .parse()
                    .unwrap_or_else(|_| unreachable!());
                let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                let packet = || udp(src, dst, 4000, m.dport).map(|p| tunnelled(&p));

                // What one packet of this flow costs, as the baseline the burst must match.
                let (Some(mut alone), Some(mut burst)) = (
                    Fabric::routed(&exposes(), None),
                    Fabric::routed(&exposes(), None),
                ) else {
                    return;
                };
                let Some(one) = packet() else { return };
                let single = treatment(&alone.send(one));
                if !matches!(single.verdict, Verdict::Delivered { .. }) {
                    return;
                }
                let cost_of_one = alone.flows();

                let Some(together) = (0..BURST).map(|_| packet()).collect::<Option<Vec<_>>>()
                else {
                    return;
                };
                let out = burst.send_batch(together);

                for (i, packet) in out.iter().enumerate() {
                    let t = treatment(packet);
                    assert_eq!(
                        t.inner_sport, single.inner_sport,
                        "packet {i} of a burst of one flow was given a different public port \
                         from the same packet sent alone: the burst allocated more than once"
                    );
                    assert_eq!(
                        t.inner_src, single.inner_src,
                        "packet {i} of a burst of one flow left under a different public address"
                    );
                    assert_eq!(
                        t.verdict, single.verdict,
                        "packet {i} of a burst of one flow reached a different verdict"
                    );
                }
                assert_eq!(
                    burst.flows(),
                    cost_of_one,
                    "a burst of {BURST} packets of one flow cost more flow-table entries than \
                     one packet of it did"
                );
                CHECKED.fetch_add(1, Ordering::Relaxed);
            });

        let checked = CHECKED.load(Ordering::Relaxed);
        eprintln!("single-flow-bursts={checked}");
        super::assert_covered(checked > 0, "no burst of a single flow was ever delivered");
    }

    /// A burst is treated the same as the same packets sent one at a time.
    ///
    /// # Why the flows are distinct
    ///
    /// This property is about whether batching preserves *per-packet* behaviour. Several packets
    /// of one flow in a burst is a different question -- how a burst handles a flow it is itself
    /// establishing -- and it has its own property, [`a_burst_of_one_flow_allocates_once`], which
    /// is where the defect that shape hid turned up.
    ///
    /// So the members of a burst are made distinct by construction: one host and one destination
    /// port each, assigned by position rather than drawn. A generator that could draw a collision
    /// would make this property fail intermittently for a reason that is not a defect.
    ///
    /// # What it catches
    ///
    /// The batched `rte_acl` path disagreeing with the single-lookup one, which `flow_filter`'s
    /// own `batched_lookup_matches_single_lookup` checks against a reference and this checks
    /// against the assembled pipeline; a stage that indexes into a burst by position and gets the
    /// position wrong; and any stage that starts leaking state between packets that have nothing
    /// to do with each other.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_burst_is_treated_the_same_as_one_packet_at_a_time() {
        static COMPARED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DELIVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Burst)
            .for_each(|members| {
                let packets = || {
                    members
                        .iter()
                        .enumerate()
                        .map(|(i, m)| {
                            // Position decides the flow, so no two members of a burst collide.
                            // The drawn values still vary which flows a run explores.
                            let src: IpAddr = format!("1.1.{i}.{}", m.host)
                                .parse()
                                .unwrap_or_else(|_| unreachable!());
                            let dst: IpAddr =
                                "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                            udp(src, dst, 1024 + u16::try_from(i).unwrap_or(0), m.dport)
                                .map(|p| tunnelled(&p))
                        })
                        .collect::<Option<Vec<_>>>()
                };
                let (Some(singly), Some(together)) = (packets(), packets()) else {
                    return;
                };

                // Two fabrics rather than one: a fabric that has already seen the packets is not
                // the same fabric, so reusing one would compare a cold pipeline with a warm one
                // and call the difference a batching bug.
                let (Some(mut a), Some(mut b)) = (
                    Fabric::routed(&exposes(), None),
                    Fabric::routed(&exposes(), None),
                ) else {
                    return;
                };

                let one_at_a_time: Vec<_> =
                    singly.into_iter().map(|p| treatment(&a.send(p))).collect();
                let in_a_burst: Vec<_> = b
                    .send_batch(together)
                    .iter()
                    .map(treatment)
                    .collect();

                assert_eq!(
                    one_at_a_time.len(),
                    in_a_burst.len(),
                    "a burst did not return as many packets as it was given"
                );
                for (i, (alone, batched)) in
                    one_at_a_time.iter().zip(in_a_burst.iter()).enumerate()
                {
                    assert_eq!(
                        alone, batched,
                        "packet {i} of the burst was treated differently from the same packet \
                         sent on its own"
                    );
                    COMPARED.fetch_add(1, Ordering::Relaxed);
                    if matches!(alone.verdict, Verdict::Delivered { .. }) {
                        DELIVERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let (compared, delivered) = (
            COMPARED.load(Ordering::Relaxed),
            DELIVERED.load(Ordering::Relaxed),
        );
        eprintln!("compared={compared} delivered={delivered}");
        super::assert_covered(compared > 0, "no burst was ever compared");
        // Without this the property is satisfied by two pipelines that drop everything
        // identically, which they would agree about perfectly and say nothing.
        super::assert_covered(
            delivered > 0,
            "no packet of any burst ever reached the wire, so the comparison is between drops",
        );
    }
}

/// Where a packet goes, when there is more than one place it could.
///
/// Every property above runs against one peering, so "was this routed to the right vpc" has only
/// one answer and cannot be got wrong. This module gives the pipeline three destinations and a
/// reason to choose between them.
#[cfg(test)]
mod destination {
    use super::routed::{inside, tunnelled};
    use super::round_trip::udp;
    use super::*;
    use config::external::overlay::vpcpeering::contract::{overlay_with_peers, peer_vni};
    use lpm::prefix::Prefix;
    use net::headers::TryVxlan;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// How many peer vpcs the local one is peered with.
    ///
    /// Three rather than two, so that a stage picking the wrong peer has somewhere wrong to go
    /// that is not simply "the other one" -- an off-by-one in a table walk lands on peer 1 whether
    /// the answer was 0 or 2, and with two peers that is indistinguishable from a swap.
    const PEERS: u8 = 3;

    /// The prefix the local vpc exposes, which every packet here is sent from.
    fn local_prefix() -> Prefix {
        "1.1.0.0/16"
            .parse()
            .unwrap_or_else(|_| unreachable!("a well-formed prefix"))
    }

    /// A packet to send: which peer it is addressed to, and where from.
    #[derive(Debug, Clone, Copy)]
    struct Aim {
        /// `Some(n)` addresses peer `n`; `None` addresses a range no peering covers.
        peer: Option<u8>,
        host: u8,
        third: u8,
        sport: u16,
        dport: u16,
    }

    struct Aims;

    const AIMS_PER_FABRIC: usize = 12;

    impl bolero::ValueGenerator for Aims {
        type Output = Vec<Aim>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Aim>> {
            (0..AIMS_PER_FABRIC)
                .map(|_| {
                    let choice = driver.produce::<u8>()?;
                    Some(Aim {
                        // One in four aimed nowhere, so the negative half of the claim is
                        // exercised without swamping the positive half.
                        peer: (choice % 4 != 3).then_some(choice % PEERS),
                        host: driver.produce()?,
                        third: driver.produce()?,
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("destination::Aims", &Aims);
    }

    /// A packet leaves for the vpc that exposes its destination, and for no vpc at all otherwise.
    ///
    /// # Why the oracle is not the flow filter written twice
    ///
    /// The temptation here is to ask the configuration which peering covers the destination, and
    /// that would be worthless: it is the flow filter's own decision procedure, so a filter that
    /// consulted the wrong table would be agreed with rather than caught.
    ///
    /// Instead the answer is built into the address. Peer `n` exposes `10.<n+1>.0.0/16`, so a
    /// destination _names_ the vpc it belongs to, and the expected vni is read off the address the
    /// test itself chose before the pipeline saw it. Nothing here looks at a peering table.
    ///
    /// # What each half catches
    ///
    /// The positive half -- addressed to peer `n`, leaves under peer `n`'s vni -- catches a filter
    /// that finds *a* peering rather than the right one: prefixes loaded into the wrong peering's
    /// table, a lookup returning the first match instead of the longest, a table walk off by one.
    ///
    /// The negative half -- addressed outside every peering, reaches no vpc -- is what stops the
    /// positive half being satisfied by a filter that says yes to everything. Together they are
    /// the claim; either alone is much weaker than it looks.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_packet_leaves_for_the_vpc_that_exposes_its_destination() {
        static REACHED: LazyLock<[AtomicU64; PEERS as usize]> =
            LazyLock::new(|| std::array::from_fn(|_| AtomicU64::new(0)));
        static REFUSED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Aims)
            .for_each(|aims| {
                let vnis: Vec<_> = std::iter::once(vni(LOCAL_VNI))
                    .chain((0..PEERS).map(|n| vni(peer_vni(n))))
                    .collect();
                let overlay = overlay_with_peers(local_prefix(), PEERS)
                    .unwrap_or_else(|e| unreachable!("the multi-peer contract does not build: {e}"));
                let Some(mut fabric) = Fabric::routed_over(&overlay, topology(&vnis)) else {
                    unreachable!("the multi-peer contract does not validate")
                };

                for aim in aims {
                    let src: IpAddr = format!("1.1.0.{}", aim.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    // Addressed either inside one peer's advertised /16 or into 172.16/12, which
                    // no peering here covers.
                    let dst: IpAddr = match aim.peer {
                        Some(n) => format!("10.{}.{}.{}", n + 1, aim.third, aim.host),
                        None => format!("172.16.{}.{}", aim.third, aim.host),
                    }
                    .parse()
                    .unwrap_or_else(|_| unreachable!());

                    let Some(packet) = udp(src, dst, aim.sport, aim.dport) else {
                        continue;
                    };
                    let out = fabric.send(tunnelled(&packet));
                    let left = matches!(verdict(&out), Verdict::Delivered { .. });

                    if let Some(n) = aim.peer {
                        assert!(
                            left,
                            "a packet to {dst}, which peer {n} exposes, did not leave: {:?}",
                            verdict(&out)
                        );
                        assert_eq!(
                            out.try_vxlan().map(net::vxlan::Vxlan::vni),
                            Some(vni(peer_vni(n))),
                            "a packet to {dst} left for the wrong vpc"
                        );
                        // The destination must survive too: leaving for the right vpc with a
                        // rewritten address would be a different packet arriving correctly.
                        let carried = inside(&out).expect("a delivered packet was not tunnelled");
                        assert_eq!(
                            carried.ip_destination(),
                            Some(dst),
                            "the destination was rewritten on the way out"
                        );
                        REACHED[n as usize].fetch_add(1, Ordering::Relaxed);
                    } else {
                        assert!(
                            !left,
                            "a packet to {dst}, which no peering covers, was sent to {:?}",
                            out.try_vxlan().map(net::vxlan::Vxlan::vni)
                        );
                        REFUSED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let reached: Vec<u64> = REACHED.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        let refused = REFUSED.load(Ordering::Relaxed);
        eprintln!("reached-per-peer={reached:?} refused={refused}");

        // Per peer rather than in total: a run that only ever reached peer 0 would satisfy a total
        // and say nothing about choosing between destinations, which is the whole property.
        for (n, count) in reached.iter().enumerate() {
            super::assert_covered(*count > 0, &format!("peer {n} was never reached"));
        }
        super::assert_covered(
            refused > 0,
            "no packet was ever aimed outside every peering, so the negative half is vacuous",
        );
    }
}

/// The whole pipeline, over a tunnel.
///
/// Everything above this point hands the overlay slice a bare packet and stamps the metadata that
/// decapsulation would have produced. That is the right trade for a property about the overlay
/// stages -- it makes them cheap to run and keeps the failure attributable -- but it means the
/// stamp is an assumption, and the two stages that produce it in production are untested by it.
///
/// This module removes the assumption. A frame arrives on an interface, addressed to this
/// gateway's vtep, and every annotation the overlay stages read is one that `Ingress` and
/// `IpForwarder` actually made.
#[cfg(test)]
mod routed {
    use super::*;
    use super::shapes::{Batch, Shape, aim, wire};
    use net::buffer::{PacketBufferMut, TestBuffer};
    use net::headers::{TryEth, TryHeaders, TryHeadersMut, TryIpv4, TryVxlan};
    use net::parse::DeParse;
    use net::ip::dscp::Dscp;
    use net::ip::ecn::Ecn;
    use net::packet::test_utils::{
        build_test_udp_ipv4_packet, build_test_vxlan_ipv4_packet_carrying_vni,
    };
    use net::vlan::Vid;
    use super::round_trip::udp;
    use std::collections::BTreeMap;
    use std::sync::LazyLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A flow to try, as a host in the private range and the ports it uses.
    #[derive(Debug, Clone, Copy)]
    struct Flow {
        host: u8,
        sport: u16,
        dport: u16,
    }

    /// A batch of flows to run against one fabric.
    ///
    /// One configuration rather than a generated one: this property is about the journey, and a
    /// generated peering mostly varies which translation is applied -- which
    /// `round_trip::a_translated_flow_comes_back_to_where_it_started` already explores far more
    /// cheaply at the overlay slice. What is scarce here is executions, so they are spent on flows.
    struct Flows;

    const FLOWS_PER_FABRIC: usize = 8;

    impl bolero::ValueGenerator for Flows {
        type Output = Vec<Flow>;

        fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Vec<Flow>> {
            (0..FLOWS_PER_FABRIC)
                .map(|_| {
                    Some(Flow {
                        host: driver.produce()?,
                        // Port 0 is not a port; masquerade would refuse it for reasons that have
                        // nothing to do with whether a translation reverses.
                        sport: driver.produce::<u16>()?.max(1),
                        dport: driver.produce::<u16>()?.max(1),
                    })
                })
                .collect()
        }
    }

    #[test]
    fn the_generator_fits_the_input_budget() {
        super::assert_within_budget("routed::Flows", &Flows);
    }

    /// The one peering every test here uses: a private range masqueraded into a public one.
    pub(super) fn exposes() -> Vec<VpcExpose> {
        vec![
            VpcExpose::empty()
                .make_masquerade(None)
                .unwrap()
                .ip("1.1.0.0/16".parse::<Prefix>().unwrap().into())
                .as_range("2.2.0.0/16".parse::<Prefix>().unwrap().into())
                .unwrap(),
        ]
    }

    /// Wrap `inner` in a vxlan frame addressed to this gateway, arriving on the uplink from the
    /// vpc named by `from`.
    ///
    /// The outer addresses come from the fixture rather than from here, and the topology was
    /// chosen to match them. Deliberately: a helper that rewrote the outer header to whatever the
    /// topology wanted could not be used to build a frame the topology should *refuse*.
    pub(super) fn tunnelled_from(from: Vni, inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
        let bytes = inner.clone().serialize().expect("the inner frame serializes");
        let mut packet = build_test_vxlan_ipv4_packet_carrying_vni(
            from,
            Dscp::default(),
            Ecn::default(),
            bytes.as_ref(),
        )
        .expect("a well-formed tunnelled frame");
        packet
            .set_eth_destination(GATEWAY_MAC)
            .expect("the frame has an ethernet header");
        packet.meta_mut().iif = Some(uplink());
        // Kept so a drop can be attributed rather than swallowed by `enforce`, as elsewhere here.
        packet.meta_mut().set_keep(true);
        packet
    }

    /// [`tunnelled_from`] for traffic originating in the local vpc, which is most of it.
    pub(super) fn tunnelled(inner: &Packet<TestBuffer>) -> Packet<TestBuffer> {
        tunnelled_from(vni(LOCAL_VNI), inner)
    }

    /// Peel the tunnel off a delivered frame to see the tenant packet inside it.
    ///
    /// Everything a property here wants to say is about the inner packet, and everything the
    /// gateway hands to the wire is an outer one. Returns `None` if what came back was not
    /// tunnelled at all, which is a finding rather than a filter -- callers say so.
    pub(super) fn inside(delivered: &Packet<TestBuffer>) -> Option<Packet<TestBuffer>> {
        let mut copy = delivered.clone();
        matches!(copy.vxlan_decap(), Some(Ok(_))).then_some(copy)
    }

    /// A tenant packet from the private range to somewhere outside it.
    fn inner() -> Packet<TestBuffer> {
        build_test_udp_ipv4_packet("1.1.0.1", "3.3.3.1", 1234, 80)
    }

    /// The fixture: the topology forwards, so a test that expects a drop is saying something.
    ///
    /// Every negative test in this module is only as good as this one. A topology with a wrong
    /// route, a missing adjacency or an unattached interface drops *everything*, and each of those
    /// failures reads exactly like the refusal the tests below are looking for.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tunnelled_frame_is_decapsulated_translated_and_sent_back_out_tunnelled() {
        let mut fabric = Fabric::routed(&exposes(), None).expect("a valid configuration");

        let out = fabric.send(tunnelled(&inner()));

        match verdict(&out) {
            Verdict::Delivered { oif, src, dst } => {
                assert_eq!(oif, Some(uplink()), "delivered over the wrong interface");
                assert_eq!(
                    src,
                    Some(LOCAL_VTEP.parse().unwrap()),
                    "the outer source is not this gateway's vtep: it did not get re-encapsulated"
                );
                assert_eq!(dst, Some(PEER_VTEP.parse().unwrap()));
                assert_eq!(
                    out.try_vxlan().map(net::vxlan::Vxlan::vni),
                    Some(vni(REMOTE_VNI)),
                    "encapsulated towards the wrong vpc"
                );
                assert_eq!(
                    out.try_eth().map(|eth| eth.destination().inner()),
                    Some(PEER_MAC),
                    "the frame was not addressed to the resolved next hop"
                );
            }
            other => panic!("the frame did not leave the gateway: {other:?}"),
        }
    }

    /// A VLAN tag inside the tunnel is refused at decapsulation, by `IpForwarder`.
    ///
    /// Two stages down to the boundary, so that the refusal is attributed. Reading the code says
    /// the guard is there; what this says is that it is *reached* -- that `Ingress` accepts the
    /// frame, that decapsulation gets far enough to see the inner headers, and that no earlier
    /// stage has already made the decision.
    ///
    /// Removing the `vlan().is_empty()` guard fails this.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_vlan_tag_is_refused_at_decapsulation() {
        let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
        let mut pipeline = DynPipeline::new()
            .add_stage(Ingress::new("ingress", tables.interfaces()))
            .add_stage(IpForwarder::new("ip-forward-1", tables.fibs()));

        let plain = one(&mut pipeline, tunnelled(&inner()));
        assert_eq!(
            verdict(&plain),
            Verdict::Forwarded {
                dst_vpcd: None,
                src: Some("1.1.0.1".parse().unwrap()),
                dst: Some("3.3.3.1".parse().unwrap()),
            },
            "an untagged frame did not survive decapsulation: the fixture is refusing everything"
        );

        let tagged = one(&mut pipeline, tunnelled(&tagged_inner()));
        assert_eq!(
            verdict(&tagged),
            Verdict::Dropped(DoneReason::Unhandled),
            "a tagged frame survived decapsulation"
        );
    }

    /// And, whatever refuses it, it does not leave the gateway.
    ///
    /// Deliberately weaker than the test above and kept anyway, because it is the claim that
    /// matters: the concern was a tag chosen by whoever built the inner frame being carried out
    /// onto whatever segment it names. The two tests differ in what they would survive -- removing
    /// the guard in `IpForwarder` fails the one above and *not* this one, because the overlay
    /// stages match with `Headers::pat` and refuse a shape they were not taught. That redundancy
    /// is the design working (see `development/code/header-chain-matching.md`), and it is also
    /// exactly why a single end-to-end assertion could not have told anyone the guard was gone.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_vlan_tag_inside_the_tunnel_never_leaves_the_gateway() {
        let mut fabric = Fabric::routed(&exposes(), None).expect("a valid configuration");

        let out = fabric.send(tunnelled(&tagged_inner()));

        assert!(
            !matches!(verdict(&out), Verdict::Delivered { .. }),
            "a tagged frame was sent out onto the wire: {:?}",
            verdict(&out)
        );
    }

    /// [`inner`], with a VLAN tag on it.
    ///
    /// Read back through a serialise/parse round trip rather than trusting `push_vlan`'s effect on
    /// the header struct: what reaches the pipeline is bytes, and a tag that the builder recorded
    /// but did not write would make both tests above pass for the wrong reason.
    fn tagged_inner() -> Packet<TestBuffer> {
        let mut inner = inner();
        inner
            .headers_mut()
            .push_vlan(Vid::new(42).expect("a valid vlan id"))
            .expect("the inner frame has an ethernet header");

        let bytes = inner.serialize().expect("a tagged frame serializes");
        let reparsed = Packet::new(TestBuffer::from_raw_data(bytes.as_ref()))
            .expect("a tagged frame parses back");
        assert!(
            !reparsed.headers().vlan().is_empty(),
            "the fixture did not actually tag the frame"
        );
        reparsed
    }

    /// No shape carrying a VLAN tag ever reaches the wire, whatever the configuration.
    ///
    /// The two tests above are one tag, one peering, one route. This is the class: every shape the
    /// [`shapes`] generator produces, tunnelled, over a generated set of exposes. It is the claim
    /// the VLAN work was actually making -- not "this frame is refused" but "a tag chosen by
    /// whoever built the inner frame does not get carried out onto a segment nobody chose".
    ///
    /// What it would take to fail this is losing the class defence entirely, not losing one layer
    /// of it: with the `IpForwarder` guard removed a tagged frame still dies in the filters, with
    /// `DoneReason::Unhandled`, because their patterns do not name a VLAN. The realistic way to
    /// fail it is somebody naming one there to make a drop go away -- step five of the checklist in
    /// `development/code/header-chain-matching.md` without steps two through four.
    ///
    /// [`shapes`]: super::shapes
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tagged_shape_never_reaches_the_wire() {
        static DELIVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static TAGGED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Batch)
            .for_each(|(exposes, stacks)| {
                let Some(mut fabric) = Fabric::routed(exposes, None) else {
                    return;
                };
                let private = exposes.first().and_then(|e| {
                    e.ips
                        .first()
                        .map(lpm::prefix::PrefixWithOptionalPorts::prefix)
                });

                for (shape, headers) in stacks {
                    let mut headers = headers.clone();
                    aim(&mut headers, private);
                    let Some(frame) = wire(&headers) else {
                        continue;
                    };
                    // The tag is read off the shape rather than off the packet that comes back:
                    // a delivered packet has been re-encapsulated, so its headers are the outer
                    // ones and any inner tag is no longer visible from here. Asking the output
                    // would be asking the wrong packet.
                    let tagged = *shape == Shape::VlanV4Tcp;
                    if tagged {
                        TAGGED.fetch_add(1, Ordering::Relaxed);
                    }

                    let out = fabric.send(tunnelled(&frame));
                    if matches!(verdict(&out), Verdict::Delivered { .. }) {
                        assert!(!tagged, "a tagged frame was sent out onto the wire");
                        DELIVERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

        let delivered = DELIVERED.load(Ordering::Relaxed);
        let tagged = TAGGED.load(Ordering::Relaxed);
        eprintln!("delivered={delivered} tagged={tagged}");

        // Both guards, because either alone can be satisfied by the pipeline doing nothing: a
        // fabric that refused everything would never deliver, and a generator that never drew a
        // tag would make the assertion above unreachable.
        super::assert_covered(delivered > 0, "nothing ever reached the wire");
        super::assert_covered(tagged > 0, "no tagged shape was ever generated");
    }

    /// A tunnelled flow comes back through the tunnel to where it started.
    ///
    /// The same claim as `round_trip::a_translated_flow_comes_back_to_where_it_started`, made where
    /// the packet has to earn every step. There, both directions had their arrival stamped by
    /// hand; here the request is decapsulated, translated, re-encapsulated and framed, and the
    /// reply arrives as a real tunnelled frame carrying the *peer's* vni and has to make the whole
    /// journey back. The reply-side decapsulation has no other test at all.
    ///
    /// The oracle costs nothing, which is why this is the property worth having: the reply is built
    /// from what came out rather than from what went in, so nothing here knows or computes what the
    /// translation should have been -- only that whatever it was has to reverse. Every address and
    /// port asserted below is one the test itself chose before the pipeline saw it.
    ///
    /// Three riders come free once a packet is followed end to end, and each is a separate claim:
    ///
    /// - **The tenant payload survives.** Decapsulate, translate, re-encapsulate -- the bytes
    ///   behind the headers must be the bytes that arrived. This is the class the doubled VXLAN
    ///   header in the fixtures belonged to, and byte comparison is the only thing that sees it.
    /// - **The tenant packet is charged exactly one hop.** Narrower than it first looks, and worth
    ///   stating precisely: the two `IpForwarder` passes act on *different* headers -- the first on
    ///   the outer frame, which decapsulation then discards, the second on the inner one -- so this
    ///   does not catch the first pass decrementing when it should not, in either direction.
    ///   What it does catch is a forwarder that stops decrementing at all, and decapsulation moving
    ///   to where the inner packet would be charged twice.
    /// - **It leaves tunnelled to the right vpc.** A reply is only correct if it went back into the
    ///   vni it came from.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_tunnelled_flow_comes_back_through_the_tunnel() {
        static ROUND_TRIPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static NOT_DELIVERED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Flows)
            .for_each(|flows| {
                let Some(mut fabric) = Fabric::routed(&exposes(), None) else {
                    return;
                };

                for flow in flows {
                    let src: IpAddr = format!("1.1.0.{}", flow.host)
                        .parse()
                        .unwrap_or_else(|_| unreachable!());
                    let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
                    let Some(request) = udp(src, dst, flow.sport, flow.dport) else {
                        continue;
                    };
                    let sent_payload = payload_of(&request);
                    let ttl_sent = ttl_of(&request);

                    let out = fabric.send(tunnelled(&request));
                    if !matches!(verdict(&out), Verdict::Delivered { .. }) {
                        NOT_DELIVERED.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    assert_eq!(
                        out.try_vxlan().map(net::vxlan::Vxlan::vni),
                        Some(vni(REMOTE_VNI)),
                        "the request left tunnelled towards the wrong vpc"
                    );

                    let translated = inside(&out).expect("a delivered request was not tunnelled");
                    assert_eq!(
                        payload_of(&translated),
                        sent_payload,
                        "the tenant payload did not survive the round of decap, nat and encap"
                    );
                    assert_eq!(
                        ttl_of(&translated).map(|t| t + 1),
                        ttl_sent,
                        "the tenant packet was not charged exactly one hop"
                    );

                    // What the far side saw, and so what it would answer.
                    let (Some(public_src), Some(reached)) =
                        (translated.ip_source(), translated.ip_destination())
                    else {
                        continue;
                    };
                    let public_port = translated
                        .transport_src_port()
                        .unwrap_or_else(|| unreachable!("a udp packet has a source port"))
                        .get();

                    let Some(reply) = udp(reached, public_src, flow.dport, public_port) else {
                        continue;
                    };
                    let back = fabric.send(tunnelled_from(vni(REMOTE_VNI), &reply));

                    let verdict = verdict(&back);
                    assert!(
                        matches!(verdict, Verdict::Delivered { .. }),
                        "the reply of a delivered flow did not reach the wire: {verdict:?} \
                         (request {src}:{sport} -> {dst}:{dport} left as \
                         {public_src}:{public_port})",
                        sport = flow.sport,
                        dport = flow.dport
                    );
                    assert_eq!(
                        back.try_vxlan().map(net::vxlan::Vxlan::vni),
                        Some(vni(LOCAL_VNI)),
                        "the reply went back into the wrong vpc"
                    );

                    let returned = inside(&back).expect("a delivered reply was not tunnelled");
                    assert_eq!(
                        returned.ip_destination(),
                        Some(src),
                        "the reply did not come back to the host that sent the request"
                    );
                    assert_eq!(
                        returned.ip_source(),
                        Some(dst),
                        "the reply's source was rewritten"
                    );
                    assert_eq!(
                        returned.transport_dst_port().map(std::num::NonZero::get),
                        Some(flow.sport),
                        "the reply did not get the original source port back"
                    );
                    ROUND_TRIPPED.fetch_add(1, Ordering::Relaxed);
                }
            });

        let round_tripped = ROUND_TRIPPED.load(Ordering::Relaxed);
        eprintln!(
            "tunnelled-round-trips={round_tripped} not-delivered={}",
            NOT_DELIVERED.load(Ordering::Relaxed)
        );
        super::assert_covered(
            round_tripped > 0,
            "no flow ever reached the wire, so no reply was ever checked to come back",
        );
    }

    /// Every packet of a flow is translated the same way, and no two flows are translated onto
    /// each other.
    ///
    /// Two claims about the same round, because the data for both falls out of it.
    ///
    /// **Stability.** A flow's second packet has to be given the translation its first was given.
    /// If it is not, the far side sees the connection change source port mid-conversation and the
    /// pool leaks an allocation per packet. What makes this hold is that the flow table is
    /// consulted before a new allocation is made, and a refactor of either is what would break it.
    ///
    /// The two rounds are deliberately **interleaved rather than back to back**: every other flow
    /// in the batch is established in between, and the second round runs in reverse order. A
    /// weaker version -- send the same packet twice in a row -- is satisfied by an implementation
    /// that remembers only the last translation it made, and would say nothing about a table.
    ///
    /// Two discriminations, and the second is what says the claim is about state rather than
    /// arithmetic. Dropping the line in `flow_entry`'s `FlowLookup` that attaches flow state fails
    /// this, with the second packet a port further along the pool cursor than the first. Turning
    /// masquerade's randomised port selection back *on* -- which the harness disables so two runs
    /// of one configuration agree -- does **not** fail it: a randomly chosen port comes back
    /// identically the second time, because the table is what is consulted. A property that merely
    /// noticed a deterministic allocator would have failed that.
    ///
    /// **Injectivity.** Two distinct flows must not be given a public tuple that makes their
    /// replies indistinguishable. A reply is matched on what the far side saw, so if two flows to
    /// the same destination share a public address *and* port, no stage downstream can tell whose
    /// reply is whose. `nat::masquerade::apalloc` checks its own pool for this; what is checked
    /// here is the allocation the assembled pipeline actually handed out.
    ///
    /// Neither claim computes a translation. The oracle for the first is equality with what came
    /// back earlier, and for the second that a map has no two keys sharing a value.
    #[tokio::test]
    #[dpdk::with_eal]
    async fn a_flow_keeps_its_translation_and_does_not_share_it() {
        static STABLE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DISTINCT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        bolero::check!()
            .with_max_len(MAX_INPUT_LEN)
            .with_generator(Flows)
            .for_each(|flows| {
                let Some(mut fabric) = Fabric::routed(&exposes(), None) else {
                    return;
                };

                // Keyed by the flow, so that a batch which happens to draw the same flow twice is
                // one flow rather than a false counterexample to either claim.
                let mut first: BTreeMap<(u8, u16, u16), (IpAddr, u16)> = BTreeMap::new();
                for flow in flows {
                    if let Some(public) = translation_of(&mut fabric, *flow) {
                        first.insert((flow.host, flow.sport, flow.dport), public);
                    }
                }

                // Distinct flows to one destination must not collide. The destination is the same
                // for every flow here, so the public tuple alone has to separate them.
                let mut seen: BTreeMap<(IpAddr, u16), (u8, u16, u16)> = BTreeMap::new();
                for (flow, public) in &first {
                    if let Some(other) = seen.insert(*public, *flow) {
                        assert_eq!(
                            other, *flow,
                            "two flows were given the same public tuple {public:?}: a reply to it \
                             cannot be attributed to either"
                        );
                    }
                    DISTINCT.fetch_add(1, Ordering::Relaxed);
                }

                // Reverse order, so a flow's two packets are separated by every other flow in the
                // batch rather than adjacent to each other.
                for flow in flows.iter().rev() {
                    let key = (flow.host, flow.sport, flow.dport);
                    let Some(expected) = first.get(&key) else {
                        continue;
                    };
                    let again = translation_of(&mut fabric, *flow)
                        .expect("a flow that was translated once stopped being translated");
                    assert_eq!(
                        again, *expected,
                        "flow {key:?} was translated differently the second time: the established \
                         flow was not found, so a fresh allocation was made"
                    );
                    STABLE.fetch_add(1, Ordering::Relaxed);
                }
            });

        let (stable, distinct) = (
            STABLE.load(Ordering::Relaxed),
            DISTINCT.load(Ordering::Relaxed),
        );
        eprintln!("stable={stable} distinct-flows={distinct}");
        super::assert_covered(stable > 0, "no flow was ever sent a second packet");
        super::assert_covered(distinct > 0, "no flow was ever translated");
    }

    /// Send one packet of `flow` and report the public source it was given, or `None` if it did
    /// not reach the wire.
    fn translation_of(fabric: &mut Fabric, flow: Flow) -> Option<(IpAddr, u16)> {
        let src: IpAddr = format!("1.1.0.{}", flow.host)
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let dst: IpAddr = "3.3.3.1".parse().unwrap_or_else(|_| unreachable!());
        let request = udp(src, dst, flow.sport, flow.dport)?;

        let out = fabric.send(tunnelled(&request));
        if !matches!(verdict(&out), Verdict::Delivered { .. }) {
            return None;
        }
        let translated = inside(&out).expect("a delivered request was not tunnelled");
        Some((
            translated.ip_source()?,
            translated.transport_src_port()?.get(),
        ))
    }

    /// The tenant payload: what is left once every header has been accounted for.
    fn payload_of(packet: &Packet<TestBuffer>) -> Vec<u8> {
        let bytes = packet
            .clone()
            .serialize()
            .expect("a packet in hand serializes");
        let headers = packet.headers().size().get() as usize;
        bytes.as_ref().get(headers..).unwrap_or_default().to_vec()
    }

    fn ttl_of(packet: &Packet<TestBuffer>) -> Option<u8> {
        packet.try_ipv4().map(net::ipv4::Ipv4::ttl)
    }

    /// Push one packet through a bare pipeline and take back the one that comes out.
    fn one(
        pipeline: &mut DynPipeline<TestBuffer>,
        packet: Packet<TestBuffer>,
    ) -> Packet<TestBuffer> {
        let mut out: Vec<_> = pipeline.process(std::iter::once(packet)).collect();
        assert_eq!(out.len(), 1, "the pipeline did not return the packet");
        out.pop().unwrap_or_else(|| unreachable!())
    }
}

