// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Apalloc: Address and port allocator for masquerade.
//!
//! The allocator is safe to access concurrently between threads.
//!
//! Here is an attempt to visualize the allocator structure:
//!
//! ```text
//!                        ┌────────────┐
//!                        │NatAllocator│
//!                        └──────┬─────┘
//!                 ┌─────────────┴─────────────┐
//!       ┌─────────▼───────┐         ┌─────────▼───────┐
//!       │PoolTable (src44)│         │PoolTable (src66)│   one per address family
//!       └─────────┬───────┘         └─────────────────┘
//!                 │  keyed by
//!       ┌─────────▼──┐
//!       │PoolTableKey│  protocol, source VPC, dest VPC, public range
//!       └─────────┬──┘
//!                 │  which an expose may draw from
//!         ┌───────▼─┐
//!         │PoolSet  │  the regions this expose's ranges cover, exclusive ones first
//!         └───────┬─┘
//!                 │
//!        ┌────────▼──┐        ┌───────────┐
//!        │PoolRegion ├────────►AddrInterval│  the slice of public space it owns
//!        └────────┬──┘        └───────────┘
//!                 │  one allocator per region, shared by every expose over it
//!       ┌─────────▼─┐
//!       │IpAllocator│◄───────────────────────────────┐
//!       └─────────┬─┘                                │
//!            ┌────▼──┐                               │
//!    ┌───────┤NatPool├──────────┐                    │
//!    │       └───────┘          │                    │
//! ┌──▼──────────────┐  ┌────────▼───────────┐        │
//! │<collection>     │  │PoolBitmap          │        │
//! │(weak references)│  │(map free addresses)│        │
//! └──┬──────────────┘  └────────────────────┘        │
//! ┌──▼────────┐                                      │
//! │AllocatedIp│──────────────────────────────────────┘
//! └─▲───────┬─┘         back-reference, for deallocation
//!   │ ┌─────▼───────┐
//!   │ │PortAllocator│
//!   │ └─────┬───────┘
//!  *│       │
//!   │ ┌─────▼───────────────┐           ┌─────────────────────┐
//!   │ │AllocatedPortBlockMap├───────────►AllocatorPortBlock   │
//!   │ │(weak references)    │           │(metadata for blocks)│
//!   │ └─────────────────────┘           └─────────────────────┘
//!   │       │
//! ┌─┴───────▼────────┐              ┌──────────────────────────┐
//! │AllocatedPortBlock├──────────────►Bitmap256                 │
//! └─▲───────┬────────┘              │(map ports within a block)│
//!  *│       │                       └──────────────────────────┘
//! ┌─┴───────▼─────┐
//! │┌─────────────┐│
//! ││AllocatedPort││                           *: back references
//! │└─────────────┘│
//! └───────────────┘
//! Returned object
//! ```
//!
//! Overlapping public ranges are divided into disjoint [`PoolRegion`](alloc::PoolRegion)s. Exposes
//! share the allocator for each common region, ensuring a public tuple is leased only once.
//!
//! Allocation objects hold back-references to their owning block, address, and pool. Dropping the
//! outer allocation therefore releases the tuple.

#![allow(rustdoc::private_intra_doc_links)]

use super::allocation::{AllocationResult, AllocatorError};
use crate::NatPort;
use crate::masquerade::MasqueradeConfig;
pub use crate::masquerade::apalloc::natip_with_bitmap::NatIpWithBitmap;
use crate::masquerade::natip::NatIp;
use concurrency::sync::atomic::{AtomicI64, Ordering};
use config::GenId;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, error, warn};

use tracectl::trace_target;
trace_target!("nat-allocation", LevelFilter::ERROR, &["masquerade"]);

mod alloc;
mod concurrent_fuzz;
mod display;
mod natip_with_bitmap;
mod pool_fuzz;
mod port_alloc;
mod region;
mod reserved;
mod setup;
mod test_alloc;

pub use port_alloc::AllocatedPort;

///////////////////////////////////////////////////////////////////////////////
// PoolTableKey
///////////////////////////////////////////////////////////////////////////////

/// Identifies the pool serving a private source address.
///
/// Both VPC discriminants precede the address so range lookup stays within one VPC pair.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PoolTableKey<I: NatIp> {
    protocol: NextHeader,
    src_vpcd: VpcDiscriminant,
    dst_vpcd: VpcDiscriminant,
    addr: I,
    addr_range_end: I,
}

impl<I: NatIp> PoolTableKey<I> {
    fn new(
        protocol: NextHeader,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        addr: I,
        addr_range_end: I,
    ) -> Self {
        Self {
            protocol,
            src_vpcd,
            dst_vpcd,
            addr,
            addr_range_end,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// PoolTable
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub(crate) struct PoolTable<I: NatIpWithBitmap, J: NatIpWithBitmap>(
    BTreeMap<PoolTableKey<I>, alloc::PoolSet<J>>,
);

impl<I: NatIpWithBitmap, J: NatIpWithBitmap> PoolTable<I, J> {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Find the longest matching private prefix within one protocol and VPC pair.
    ///
    /// Walking backwards must skip nested prefixes that start later but end before the queried
    /// address. Once a match is found, only entries with the same start can be narrower.
    fn get(&self, key: &PoolTableKey<I>) -> Option<&alloc::PoolSet<J>> {
        let mut best: Option<(&PoolTableKey<I>, &alloc::PoolSet<J>)> = None;
        for (candidate, pool_set) in self.0.range(..=key).rev() {
            // The keys of one protocol and pair of VPCs are contiguous, so leaving that run means
            // there is nothing further back to find.
            if candidate.protocol != key.protocol
                || candidate.src_vpcd != key.src_vpcd
                || candidate.dst_vpcd != key.dst_vpcd
            {
                break;
            }
            // Walking back, prefixes start further from the address as we go. Once one covering it
            // has been found, only another starting at the same address can be narrower.
            if let Some((found, _)) = best
                && candidate.addr < found.addr
            {
                break;
            }
            if candidate.addr_range_end >= key.addr {
                // Entries sharing a start address are visited widest first, so a later one is
                // always the narrower match.
                best = Some((candidate, pool_set));
            }
        }
        best.map(|(_, pool_set)| pool_set)
    }

    fn get_entry(
        &self,
        protocol: NextHeader,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        addr: I,
    ) -> Option<&alloc::PoolSet<J>> {
        let key = PoolTableKey::new(protocol, src_vpcd, dst_vpcd, addr, max_range::<I>());
        self.get(&key)
    }

    fn add_entry(&mut self, key: PoolTableKey<I>, pool_set: alloc::PoolSet<J>) {
        if self.0.contains_key(&key) {
            warn!(
                "Overwriting NAT pool entry {key:?}: within one VPC, the same private prefix is \
                 masqueraded by more than one expose towards the same peer VPC"
            );
        }
        self.0.insert(key, pool_set);
    }
}

///////////////////////////////////////////////////////////////////////////////
// NatAllocator
///////////////////////////////////////////////////////////////////////////////

/// [`Allocation`] is the non-generic object representing an allocation, be it IPv4 or IPv6
#[derive(Debug)]
pub enum Allocation {
    V4(AllocatedPort<Ipv4Addr>),
    V6(AllocatedPort<Ipv6Addr>),
}

impl Allocation {
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::V4(a) => IpAddr::V4(a.ip()),
            Self::V6(a) => IpAddr::V6(a.ip()),
        }
    }

    #[must_use]
    pub fn port(&self) -> NatPort {
        match self {
            Self::V4(a) => a.port(),
            Self::V6(a) => a.port(),
        }
    }
}

impl Display for Allocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Allocation::V4(a) => write!(f, "{a}"),
            Allocation::V6(a) => write!(f, "{a}"),
        }
    }
}

/// [`NatAllocator`] is the IP addresses and ports allocator for masquerade.
///
/// Internally, it contains various bitmap-based IP pools, and each IP address allocated from these
/// pools contains a port allocator.
#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub struct NatAllocator {
    config: MasqueradeConfig,
    genid: AtomicI64,
    pools_src44: PoolTable<Ipv4Addr, Ipv4Addr>,
    pools_src66: PoolTable<Ipv6Addr, Ipv6Addr>,
}

impl NatAllocator {
    #[must_use]
    pub(crate) fn new(config: MasqueradeConfig, genid: GenId) -> Self {
        debug!("Building NAT allocator for genid {genid}");
        let pools_src44 = NatAllocator::build_pool44(&config);
        let pools_src66 = NatAllocator::build_pool66(&config);
        Self {
            config,
            genid: AtomicI64::new(genid),
            pools_src44,
            pools_src66,
        }
    }

    pub(crate) fn config(&self) -> &MasqueradeConfig {
        &self.config
    }

    /// The configuration generation this allocator currently serves.
    pub(crate) fn genid(&self) -> GenId {
        self.genid.load(Ordering::Relaxed)
    }

    /// Advance the genid served, for a config update that left the NAT peerings untouched and
    /// therefore kept this allocator
    pub(crate) fn set_genid(&self, genid: GenId) {
        self.genid.store(genid, Ordering::Relaxed);
    }

    //= https://www.rfc-editor.org/rfc/rfc5382#section-8
    //= type=todo
    //# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior
    //# for TCP.
    //
    // Not held, and measured rather than reasoned about. An earlier reading of this code blamed
    // `dst_vpcd` and concluded the deviation only showed up across destination VPCs, which would
    // have made it defensible. `fuzz::an_internal_endpoint_keeps_one_public_address` was written
    // to check that and refuted it on the first input it drew.
    //
    // Holding the internal endpoint at 10.0.0.0:1 and moving only the *destination port*, from
    // 3.3.3.1:1 to 3.3.3.1:2, moves the public port from 1024 to 1025. Same destination address,
    // same VPC, different mapping. In RFC 4787's taxonomy (section 4.1) that is
    // "Address and Port-Dependent Mapping" -- the most restrictive of the three classes, and the
    // one REQ-1 exists to forbid.
    //
    // The signature above is what made the earlier reading plausible: `allocate_v4` takes no
    // destination address and no destination port, so it looks endpoint-independent. The
    // dependence is not in its arguments, it is in being called again for every new flow. Nothing
    // at the allocator level can see that, which is why the property lives at the stage.
    //
    // What this costs is UNSAF traversal, which is the entire justification RFC 4787 gives for
    // REQ-1: a peer learns its public tuple by talking to a third party, and here that tuple is
    // worth nothing for talking to anybody else. Whether this gateway intends to carry
    // peer-to-peer traffic is a product question, and it is a much sharper one than the
    // destination-VPC question it replaces.
    //
    // Still `todo` rather than `exception`, on the same grounds as before: an exception asserts
    // somebody weighed this and accepted it. Now that the cost is stated precisely, that decision
    // is worth asking for.
    //
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
    //= type=todo
    //# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior.
    //
    // The same deviation, for UDP, on the same code, and the measurement above was taken over UDP
    // probes. RFC 4787 states it without the "for TCP" qualifier. One decision settles both.
    //
    // The half that *is* held is REQ-2, cited in `alloc.rs`: the public address is stable across
    // destinations even though the port is not. That is the partial-conformance case in its
    // clearest form -- one requirement met, its neighbour missed, by the same two lines of code.
    //
    // RFC 4787 REQ-3 and RFC 5382 REQ-7 -- "MUST NOT have a Port assignment behavior of Port
    // overloading" -- were cited here, and now sit on `Bitmap256::allocate_port_from_bitmap`,
    // which is what would have to hand a port out twice for either to break. This function only
    // forwards to `allocate_from_tables`; there is nothing here to get wrong, which is why
    // `just spec-interlock` could not check the citation while it was here.
    fn allocate_v4(
        &self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv4Addr,
        next_header: NextHeader,
    ) -> Result<AllocationResult<AllocatedPort<Ipv4Addr>>, AllocatorError> {
        Self::allocate_from_tables(
            src_ip.into(),
            src_vpcd,
            dst_vpcd,
            next_header,
            &self.pools_src44,
        )
    }

    fn allocate_v6(
        &self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv6Addr,
        next_header: NextHeader,
    ) -> Result<AllocationResult<AllocatedPort<Ipv6Addr>>, AllocatorError> {
        Self::allocate_from_tables(
            src_ip.into(),
            src_vpcd,
            dst_vpcd,
            next_header,
            &self.pools_src66,
        )
    }

    /// Allocate an IP address and port for the given source IP, dispatching on IP version.
    pub(crate) fn allocate(
        &self,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        next_header: NextHeader,
    ) -> Result<AllocationResult<Allocation>, AllocatorError> {
        match src_ip {
            IpAddr::V4(ip) => self
                .allocate_v4(src_vpcd, dst_vpcd, ip, next_header)
                .map(|r| AllocationResult {
                    allocation: Allocation::V4(r.allocation),
                    idle_timeout: r.idle_timeout,
                }),
            IpAddr::V6(ip) => self
                .allocate_v6(src_vpcd, dst_vpcd, ip, next_header)
                .map(|r| AllocationResult {
                    allocation: Allocation::V6(r.allocation),
                    idle_timeout: r.idle_timeout,
                }),
        }
    }

    fn allocate_from_tables<I: NatIpWithBitmap>(
        src_ip: IpAddr,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        next_header: NextHeader,
        pools_src: &PoolTable<I, I>,
    ) -> Result<AllocationResult<AllocatedPort<I>>, AllocatorError> {
        // TODO: here we should only allow next-header to be TCP/UDP/ICMP/ICMP6 as a SANITY.
        // This can be done by a transparent wrapper of NextHeader that can only exist for that set

        // If we could not find an address pool for the source address, the user has not exposed
        // and configured NAT for that source address. Drop the packet instead of creating a session.
        let pool = pools_src
            .get_entry(
                next_header,
                src_vpcd,
                dst_vpcd,
                NatIp::try_from_addr(src_ip).map_err(|()| {
                    AllocatorError::InternalIssue("Failed to convert src IP address".to_string())
                })?,
            )
            .ok_or_else(|| {
                // Given that we mark packets that require NAT, this case should never happen.
                error!("No address pool found for src ip {src_ip}. This is a bug");
                AllocatorError::Denied
            })?;

        let allow_null = next_header == NextHeader::ICMP || next_header == NextHeader::ICMP6;
        let allocation = pool.allocate(allow_null)?;
        let idle_timeout = pool.idle_timeout();

        Ok(AllocationResult {
            allocation,
            idle_timeout,
        })
    }

    fn reserve_ipv4_port(
        &self,
        protocol: NextHeader,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv4Addr,
        ip: Ipv4Addr,
        port: NatPort,
    ) -> Result<AllocatedPort<Ipv4Addr>, AllocatorError> {
        let Some(pool) = self
            .pools_src44
            .get_entry(protocol, src_vpcd, dst_vpcd, src_ip)
        else {
            warn!(
                "No pool found for proto:{protocol} src-vpcd:{src_vpcd} dst-vpcd:{dst_vpcd} and src:{src_ip}"
            );
            return Err(AllocatorError::NoPoolFound);
        };

        debug!("Pool found for {protocol} {src_vpcd} {dst_vpcd} {src_ip}");
        pool.reserve(ip, port)
            .inspect_err(|e| error!("Failed to reserve ip {ip} port {port}: {e}"))
    }
    fn reserve_ipv6_port(
        &self,
        protocol: NextHeader,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_ip: Ipv6Addr,
        ip: Ipv6Addr,
        port: NatPort,
    ) -> Result<AllocatedPort<Ipv6Addr>, AllocatorError> {
        let Some(pool) = self
            .pools_src66
            .get_entry(protocol, src_vpcd, dst_vpcd, src_ip)
        else {
            warn!(
                "No pool found for proto:{protocol} src-vpcd:{src_vpcd} dst-vpcd:{dst_vpcd} and src:{src_ip}"
            );
            return Err(AllocatorError::NoPoolFound);
        };

        debug!("Pool found for {protocol} {src_vpcd} {dst_vpcd} {src_ip}");
        pool.reserve(ip, port)
            .inspect_err(|e| error!("Failed to reserve ip {ip} port {port}: {e}"))
    }
    /// Re-reserve a specific IP and port in the new allocator during a config change
    /// depending on the ip version of the address
    pub(crate) fn reserve_port(
        &self,
        protocol: NextHeader,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        src_ip: IpAddr,
        ip: IpAddr,
        port: NatPort,
    ) -> Result<Allocation, AllocatorError> {
        debug!("Re-reserving {ip} {protocol}:{port}, src_vpcd:{src_vpcd} dst_vpcd:{dst_vpcd}");
        let allocation = match (src_ip, ip) {
            (IpAddr::V4(src), IpAddr::V4(allocated)) => self
                .reserve_ipv4_port(protocol, src_vpcd, dst_vpcd, src, allocated, port)
                .map(Allocation::V4)?,
            (IpAddr::V6(src), IpAddr::V6(allocated)) => self
                .reserve_ipv6_port(protocol, src_vpcd, dst_vpcd, src, allocated, port)
                .map(Allocation::V6)?,
            _ => {
                return Err(AllocatorError::InternalIssue(format!(
                    "IP version mismatch: src={src_ip} allocated={ip}"
                )));
            }
        };
        Ok(allocation)
    }
}

// This method is for setting a range end field that is not usually relevant for table lookups, for
// example for PoolTable lookups. The only case the resulting field is considered is when all other
// fields from the lookup key match exactly with the fields from a key in a table. To make sure we
// pick the entry in this case, we need to ensure the value is always greater or equal to the one of
// the key from the PoolTable. So we set it to the largest possible value.
fn max_range<I: NatIp>() -> I {
    I::try_from_bits(u128::MAX)
        .or(I::try_from_bits(u32::MAX.into()))
        .unwrap_or_else(|()| unreachable!()) // IPv4/IPv6 can always be built from u32::MAX
}

///////////////////////////////////////////////////////////////////////////////
// Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod bolero_tests {
    use super::*;
    use bolero::{Driver, TypeGenerator};
    use net::vxlan::Vni;
    use std::time::Duration;

    // Prefixes are drawn from a narrow window so that nesting and overlap are the common case
    // rather than astronomically unlikely, and so that every address in the window can be checked
    // rather than a sampled few.
    const BASE: u32 = 0x0A00_0000; // 10.0.0.0
    const WINDOW: u32 = 24;
    const MAX_ENTRIES: u8 = 6;
    const MAX_LEN: u8 = 12;

    // Which entry a lookup landed on, as a value a `PoolSet` can carry.
    //
    // Both bounds, because either alone loses entries. Marking by end made two entries ending
    // together indistinguishable however far apart they start -- and "nearest start" is half of
    // the rule under test, so a walk preferring the farther of the two passed.
    const SPAN: u32 = WINDOW + MAX_LEN as u32 + 1;
    fn marker(start: u32, end: u32) -> u32 {
        (start - BASE) * SPAN + (end - start)
    }

    fn vpcd(id: u32) -> VpcDiscriminant {
        VpcDiscriminant::VNI(Vni::new_checked(id).unwrap())
    }

    /// A set of entries, each an offset into the window and a length, and each in one of two
    /// groups so that the walk's refusal to cross between groups is exercised too.
    ///
    /// The foreign group sorts *before* the queried one, which is what makes that last part true:
    /// keys order by destination VPC before address, so a group sorting after is cut off by
    /// `range(..=key)` and never reaches the guard at all.
    #[derive(Debug, Clone)]
    struct Scenario {
        entries: Vec<(u8, u8, bool)>,
    }

    impl TypeGenerator for Scenario {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let count = usize::from(driver.produce::<u8>()? % MAX_ENTRIES + 1);
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                entries.push((
                    driver.produce::<u8>()? % u8::try_from(WINDOW).ok()?,
                    driver.produce::<u8>()? % MAX_LEN + 1,
                    driver.produce::<bool>()?,
                ));
            }
            Some(Self { entries })
        }
    }

    impl Scenario {
        // The entries of the group under test, as inclusive address bounds.
        fn ranges(&self) -> Vec<(u32, u32)> {
            self.entries
                .iter()
                .filter(|(_, _, other_group)| !other_group)
                .map(|&(offset, length, _)| {
                    let start = BASE + u32::from(offset);
                    (start, start + u32::from(length) - 1)
                })
                .collect()
        }

        fn table(&self) -> PoolTable<Ipv4Addr, Ipv4Addr> {
            let mut table = PoolTable::new();
            for &(offset, length, other_group) in &self.entries {
                let start = BASE + u32::from(offset);
                let end = start + u32::from(length) - 1;
                table.add_entry(
                    PoolTableKey::new(
                        NextHeader::TCP,
                        vpcd(1),
                        // Below the queried group, so the walk has to refuse to enter it.
                        if other_group { vpcd(2) } else { vpcd(3) },
                        Ipv4Addr::from(start),
                        Ipv4Addr::from(end),
                    ),
                    alloc::PoolSet::new(Duration::from_secs(u64::from(marker(start, end)))),
                );
            }
            table
        }

        // The oracle: among the entries covering the address, the one starting nearest to it, and
        // of those the narrowest. Straight from the inputs, with no walking.
        fn expected(&self, address: u32) -> Option<u32> {
            self.ranges()
                .into_iter()
                .filter(|&(start, end)| start <= address && address <= end)
                .min_by_key(|&(start, end)| (std::cmp::Reverse(start), end))
                .map(|(start, end)| marker(start, end))
        }
    }

    /// Compare lookup with a nearest-start, then narrowest-range oracle.
    #[test]
    fn pool_table_lookup_matches_an_interval_oracle() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|scenario: Scenario| {
                let table = scenario.table();
                // A margin either side, so addresses below and above every entry are covered.
                for offset in 0..WINDOW + u32::from(MAX_LEN) + 2 {
                    let address = BASE + offset;
                    let found = table
                        .get_entry(NextHeader::TCP, vpcd(1), vpcd(3), Ipv4Addr::from(address))
                        .map(|pool_set| u32::try_from(pool_set.idle_timeout().as_secs()).unwrap());
                    assert_eq!(
                        found,
                        scenario.expected(address),
                        "lookup for {} disagreed with the oracle, entries {:?}",
                        Ipv4Addr::from(address),
                        scenario.ranges()
                    );
                }
            });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::ip_constant)]

    use super::*;
    use net::vxlan::Vni;

    fn vpcd(vpc_id: u32) -> VpcDiscriminant {
        VpcDiscriminant::VNI(Vni::new_checked(vpc_id).unwrap())
    }
    fn vpcd1() -> VpcDiscriminant {
        vpcd(1)
    }
    fn vpcd2() -> VpcDiscriminant {
        vpcd(2)
    }
    fn vpcd3() -> VpcDiscriminant {
        vpcd(3)
    }

    // A pool set carrying nothing but a distinguishable idle timeout, so a lookup can be told
    // which entry it landed on.
    fn marked_pool_set(marker: u64) -> alloc::PoolSet<Ipv4Addr> {
        alloc::PoolSet::new(std::time::Duration::from_secs(marker))
    }

    // Not the lowest group, so boundary tests can place foreign entries before it.
    fn queried_group() -> (NextHeader, VpcDiscriminant, VpcDiscriminant) {
        (NextHeader::TCP, vpcd2(), vpcd3())
    }

    fn table_with(entries: &[(&str, &str, u64)]) -> PoolTable<Ipv4Addr, Ipv4Addr> {
        let (protocol, src, dst) = queried_group();
        let mut table = PoolTable::new();
        for &(start, end, marker) in entries {
            table.add_entry(
                PoolTableKey::new(
                    protocol,
                    src,
                    dst,
                    start.parse().unwrap(),
                    end.parse().unwrap(),
                ),
                marked_pool_set(marker),
            );
        }
        table
    }

    fn lookup(table: &PoolTable<Ipv4Addr, Ipv4Addr>, addr: &str) -> Option<u64> {
        let (protocol, src, dst) = queried_group();
        table
            .get_entry(protocol, src, dst, addr.parse().unwrap())
            .map(|pool_set| pool_set.idle_timeout().as_secs())
    }

    // A nested prefix must not hide later addresses covered by its parent.
    #[test]
    fn test_a_nested_prefix_does_not_hide_the_one_containing_it() {
        let table = table_with(&[
            ("10.0.0.0", "10.0.255.255", 16), // 10.0.0.0/16
            ("10.0.1.0", "10.0.1.255", 24),   // 10.0.1.0/24, nested inside it
        ]);

        // Below the nested prefix, and inside it: unambiguous either way.
        assert_eq!(lookup(&table, "10.0.0.5"), Some(16));
        // Past the nested prefix, but still inside the wider one. This is the case that failed.
        assert_eq!(
            lookup(&table, "10.0.2.5"),
            Some(16),
            "an address covered by the wider prefix was not served"
        );
        // Well past both.
        assert_eq!(lookup(&table, "10.1.0.1"), None);
    }

    // Where both cover an address, the more specific prefix serves it, as it does everywhere else
    // in routing.
    #[test]
    fn test_the_most_specific_prefix_wins() {
        let table = table_with(&[
            ("10.0.0.0", "10.0.255.255", 16),
            ("10.0.1.0", "10.0.1.255", 24),
        ]);
        assert_eq!(lookup(&table, "10.0.1.5"), Some(24));
    }

    // Several prefixes nested one inside the next, to check the walk does not stop early.
    #[test]
    fn test_deeply_nested_prefixes() {
        let table = table_with(&[
            ("10.0.0.0", "10.255.255.255", 8),
            ("10.0.0.0", "10.0.255.255", 16),
            ("10.0.0.0", "10.0.0.255", 24),
        ]);
        assert_eq!(lookup(&table, "10.0.0.1"), Some(24));
        assert_eq!(lookup(&table, "10.0.1.1"), Some(16));
        assert_eq!(lookup(&table, "10.1.0.1"), Some(8));
        assert_eq!(lookup(&table, "11.0.0.1"), None);
    }

    // Foreign groups sort before the queried group, forcing lookup to reach and reject them.
    #[test]
    fn test_the_walk_does_not_cross_into_another_group() {
        let (protocol, src, dst) = queried_group();
        // One boundary at a time, each a group immediately below the queried one.
        let foreign = [
            (NextHeader::ICMP, src, dst),
            (protocol, vpcd1(), dst),
            (protocol, src, vpcd2()),
        ];

        for (index, &(f_protocol, f_src, f_dst)) in foreign.iter().enumerate() {
            let mut table = table_with(&[("10.0.1.0", "10.0.1.255", 24)]);
            // A wider prefix, covering everything the queried group's entry does and more, but
            // reached only by walking out of the queried group.
            table.add_entry(
                PoolTableKey::new(
                    f_protocol,
                    f_src,
                    f_dst,
                    "10.0.0.0".parse().unwrap(),
                    "10.0.255.255".parse().unwrap(),
                ),
                marked_pool_set(99),
            );
            // An address only the foreign entry covers is not served at all...
            assert_eq!(
                lookup(&table, "10.0.2.5"),
                None,
                "foreign group {index} served an address of its own"
            );
            // ...and one both cover is served by the queried group's entry.
            assert_eq!(
                lookup(&table, "10.0.1.5"),
                Some(24),
                "foreign group {index} displaced the entry that should serve"
            );
        }
    }

    // PoolTable lookup relies on protocol/VPC groups being contiguous before address ordering.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_key_order() {
        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert_eq!(key1, key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(2, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 255, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 > key2);

        // Mixing protocols

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);

        // Mixing source VPCs. The source discriminant outranks both the destination and the
        // address, so the entries of one source VPC never interleave with those of another.

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        );
        assert!(key1 < key2);

        // ... but it does not outrank the protocol.

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd3(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::UDP,
            vpcd1(),
            vpcd2(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert!(key1 < key2);

        // Two source VPCs using the same private address are distinct keys, which is the whole
        // point of carrying the source discriminant: a private address only means something
        // within the VPC it belongs to.

        let key1 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd1(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 255, 255),
        );
        let key2 = PoolTableKey::new(
            NextHeader::TCP,
            vpcd2(),
            vpcd3(),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 255, 255),
        );
        assert_ne!(key1, key2);
    }
}
