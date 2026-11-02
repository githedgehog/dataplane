// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! This module contains the backlog of packets waiting for ARP/ND resolution.
//! This module keeps no async code; just the storage of state and packets and
//! the helper logic to deal with it: the resolving task of the ARP/ND daemon
//! owns this backlog and dictates how/when its methods are used.
//!
//! The backlog is organized as a collection of target entries.
//! A target represents an IP to resolve. An entry, keyed by a target, represents
//! the current resolution state of the target. When the ARP/ND daemon gets a packet
//! to resolve, the required target is determined and an entry created, if it
//! does not exist already (it could exist if the target was already being resolved).
//! The incoming packet is stored in the entry for its target.
//! Both the number of targets and the number of packets per target are bounded.
//! If, when admitting a packet, either limit is exceeded, the backlog will reject
//! it: the packet will be marked as dropped and sent to the outq. Even if admitted,
//! the packet may be rejected later; e.g. if the kernel fails to resolve its target,
//! or if resolution does not happen within some time bound.
//!
//!
//! ```text
//!                              packets per target (bounded)
//!                         <-------------------------------------->
//!        +----------+     +----+ +----+ +----+ +----+ +----+
//!   |    |  target  |     |    | |    | |    | |    | |    |
//!   |    +----------+     +----+ +----+ +----+ +----+ +----+
//!   |    +----------+     +----+ +----+
//!   |    |  target  |     |    | |    |
//!   |    +----------+     +----+ +----+
//!   |    +----------+     +----+ +----+ +----+ +----+
//!   |    |  target  |     |    | |    | |    | |    |
//!   |    +----------+     +----+ +----+ +----+ +----+
//!   |         .
//!   |    +----------+
//!   v    |  target  |
//!        +----------+
//! ```

//! All packets are stored in the backlog while their ARP/ND resolution takes place and
//! are ALWAYS sent to the outq (pipeline) at some point, resolved or not.
//! The backlog entries allow the daemon to know if a target needs to be queried or it
//! has already been and when that happened. The daemon checks the backlog periodically
//! and or when being notified by the netlink listener that the neighbor cache changed.
//! When detecting that a target (entry) can be resolved with the current neighbor cache,
//! the corresponding packets get resolved (their destination mac gets set) and returned.
//! The neighbor cache may indicate that a neighbor/target is unreachable after the daemon
//! queried it. In that case, the targets and packet get returned to the pipeline as unresolved.
//! Also, the daemon may detect that no entry in the cache exists for a given target, or,
//! if it does, that it has not been refreshed within a `RESOLUTION_TIMEOUT`. In this case,
//! the target is given up too and the corresponding packets returned.
//!
//! The backlog:
//!    - is owned by the ARP/ND resolving task.
//!    - owns a NeighCacheReader (to read the ARP/ND cache, written by the netlink listener).
//!    - has an [`Injector`] (the outq) to send resolved/unresolved packets back to the pipeline:
//!      each packet goes back to the endpoint (pipeline) that punted it.
//!    - if packets cannot be returned because the injection queue of their endpoint is full,
//!      the backlog stores them in a local "return buffer" until they can be returned. If that
//!      local buffer becomes full, packets may be dropped. The eviction of packets is such that
//!      unresolved packets get dropped first. Packets towards an endpoint that is gone are dropped.

use ahash::AHashMap;
use clock::{Duration, Instant, elapsed};
use net::eth::mac::DestinationMac;
use net::headers::TryEthMut;
use net::interface::InterfaceIndex;
use net::packet::DoneReason;
use pkt_io::{EndpointId, InjectError, Injector, PuntedPacket};
use std::collections::VecDeque;
use std::collections::hash_map::Entry;

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::cache::{NeighCacheReader, NeighEntry};
use crate::querier::Target;

/// An entry in the [`Backlog`] associated to a [`Target`] being resolved.
/// The entry contains the packets destined to that target that get cached during resolution.
struct TargetEntry {
    packets: VecDeque<PuntedPacket>, // the packets using this target
    queried: Option<Instant>,        // time when the target for this entry was last queried
}
impl TargetEntry {
    #[must_use]
    fn new() -> Self {
        Self {
            packets: VecDeque::new(),
            queried: None,
        }
    }

    /// Record when the target of this entry was queried
    fn register_query(&mut self) {
        self.queried = Some(clock::now());
    }
}

/// A limited-size private buffer used by the backlog to store packets that could not be
/// returned to the pipeline because the injection queue of their endpoint was full. Packets are
/// kept per endpoint, in order, so that a full endpoint does not hold back the packets for the
/// rest. If this buffer is exceeded, packets WILL be dropped.
struct ReturnBuffer {
    capacity: usize,
    len: usize,
    queues: AHashMap<EndpointId, VecDeque<PuntedPacket>>,
}

impl ReturnBuffer {
    #[must_use]
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            len: 0,
            queues: AHashMap::new(),
        }
    }

    #[must_use]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Tell if there are packets waiting to be returned to endpoint `origin`
    #[must_use]
    fn have_pkts_for(&self, origin: EndpointId) -> bool {
        self.queues
            .get(&origin)
            .is_some_and(|queue| !queue.is_empty())
    }

    /// Cache a packet that should be returned to the pipeline (endpoint) in case the queue
    /// is full. If the occupancy of the cache for the endpoint is also exceeded, then drop the
    /// packet. However, if the packet is resolved, evict instead one that wasn't.
    fn push_back(&mut self, packet: PuntedPacket) {
        let endpoint = packet.origin();
        let queue = self.queues.entry(endpoint).or_default();
        if queue.len() < self.capacity {
            queue.push_back(packet);
            self.len += 1;
        } else {
            warn!("Return buffer to endpoint {endpoint} is full. Packets will be dropped!");
            if packet.get_done() == Some(DoneReason::Delivered)
                && let Some(pos) = queue
                    .iter()
                    .position(|p| p.get_done() != Some(DoneReason::Delivered))
            {
                queue.remove(pos);
                queue.push_back(packet);
            }
        }
    }

    /// Return as many of the stored packets as possible with `outq`, in order, per endpoint.
    /// Packets for endpoints that are gone are dropped.
    fn flush(&mut self, outq: &Injector) {
        for (origin, queue) in &mut self.queues {
            while let Some(packet) = queue.pop_front() {
                match outq.inject(*origin, packet.into_packet()) {
                    Ok(()) => self.len -= 1,
                    Err(InjectError::FullQueue(packet)) => {
                        queue.push_front(PuntedPacket::new(*origin, packet));
                        break;
                    }
                    Err(InjectError::NoEndpoint(_)) => {
                        debug!("Endpoint {origin} is gone: dropping packet");
                        self.len -= 1;
                    }
                }
            }
        }
        self.queues.retain(|_, queue| !queue.is_empty());
    }

    #[cfg(test)]
    #[must_use]
    fn pop_front(&mut self, origin: EndpointId) -> Option<PuntedPacket> {
        let packet = self.queues.get_mut(&origin)?.pop_front()?;
        self.len -= 1;
        Some(packet)
    }
}

/// The ARP/ND backlog object. This objects contains most of the state
/// and the settings that the ARP/ND daemon keeps. This includes the
/// target addresses that need to be resolved, along with the packets
/// that are buffered while the target is resolved.
pub(crate) struct Backlog {
    entries: AHashMap<Target, TargetEntry>,
    cacher: NeighCacheReader,
    return_buffer: ReturnBuffer,
    outq: Injector,
}
impl Backlog {
    // the maximum number of targets that the backlog will admit
    const MAX_TARGETS: usize = 256;

    // the maximum number of packets that will be buffered per target
    const MAX_PACKETS_PER_TARGET: usize = 50;

    // the time after which a target that was queried and is not resolved is given up
    const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

    // the maximum number of packets that we will hold, per endpoint (worker), if we can't return them
    const RETURN_BUFF_CAPACITY: usize = 100;

    #[must_use]
    pub(crate) fn new(cacher: NeighCacheReader, outq: Injector) -> Self {
        Self {
            entries: AHashMap::new(),
            cacher,
            return_buffer: ReturnBuffer::new(Self::RETURN_BUFF_CAPACITY),
            outq,
        }
    }

    #[must_use]
    pub(crate) fn num_targets(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn num_packets(&self) -> usize {
        self.entries
            .values()
            .fold(0, |val, entry| val + entry.packets.len())
    }

    /// Return `packet` to the pipeline it came from, injecting it into its endpoint. The injection
    /// queue of the endpoint is bounded and might get full. If `packet` does not fit, it gets
    /// stored in a local `ReturnBuffer`, which also has a bounded capacity, to be able to return
    /// it later. Packets for an endpoint are returned in order: if some are waiting to be
    /// returned, `packet` waits after them.
    fn return_packet(&mut self, packet: PuntedPacket) {
        self.return_pending();
        if self.return_buffer.have_pkts_for(packet.origin()) {
            self.return_buffer.push_back(packet);
            return;
        }
        let origin = packet.origin();
        match self.outq.inject(origin, packet.into_packet()) {
            Ok(()) => {}
            Err(InjectError::FullQueue(packet)) => {
                self.return_buffer
                    .push_back(PuntedPacket::new(origin, packet));
            }
            Err(InjectError::NoEndpoint(_)) => debug!("{origin} is gone: dropping packet"),
        }
    }

    /// Attempt to return packets that could not be returned before
    pub(crate) fn return_pending(&mut self) {
        if !self.return_buffer.is_empty() {
            self.return_buffer.flush(&self.outq);
        }
    }

    /// Reject a packet setting its DoneReason and returning it.
    pub(crate) fn reject_packet(&mut self, mut packet: PuntedPacket, reason: DoneReason) {
        packet.done(reason);
        self.return_packet(packet);
    }

    /// Abandon (and consume) the entry for a target, returning all of its packets
    fn give_up_target(&mut self, target: &Target, mut entry: TargetEntry, reason: DoneReason) {
        let num_packets = entry.packets.len();
        for packet in entry.packets.drain(..) {
            self.reject_packet(packet, reason);
        }
        debug!("Target {target} was given up. {num_packets} packets were returned ({reason})");
    }

    // remove all the entries for the given targets, returning their packets with the given reason
    fn give_up_targets(&mut self, targets: &[Target], reason: DoneReason) {
        for target in targets {
            let entry = self.entries.remove(target);
            if let Some(entry) = entry {
                self.give_up_target(target, entry, reason);
            }
        }
    }

    /// Add a packet to the given target in the backlog. Create the target if it does not exist.
    /// If resource constraints are exceeded, target and packet will be rejected, causing packets
    /// to return unresolved to the outq (pipeline)
    pub(crate) fn add(&mut self, target: Target, packet: PuntedPacket) {
        let num_targets = self.num_targets();
        match self.entries.entry(target) {
            Entry::Occupied(mut occupied) => {
                let packets = &mut occupied.get_mut().packets;
                if packets.len() < Self::MAX_PACKETS_PER_TARGET {
                    packets.push_back(packet);
                } else {
                    warn!("Too many packets for target {target}. Dropping");
                    self.reject_packet(packet, DoneReason::ArpOutOfResources);
                }
            }
            Entry::Vacant(vacant) => {
                if num_targets < Self::MAX_TARGETS {
                    vacant.insert(TargetEntry::new()).packets.push_back(packet);
                } else {
                    warn!("Max number of targets reached! Will reject packet with target {target}");
                    self.reject_packet(packet, DoneReason::ArpOutOfResources);
                }
            }
        }
    }

    /// Set the [`DestinationMac`] MAC of a [`Packet`] and its metadata, and attempt to queue it back
    /// to the pipeline over the outq. If the packet cannot be queued, it will be cached.
    fn resolve_packet(&mut self, mut packet: PuntedPacket, dst_mac: DestinationMac) {
        match packet.try_eth_mut() {
            Some(eth) => {
                eth.set_destination(dst_mac);
                packet.done(DoneReason::Delivered);
                packet.meta_mut().set_need_arp_nd(false);
            }
            None => {
                warn!("Failed to read Ethernet header. This is a bug");
                packet.done_force(DoneReason::InternalFailure);
            }
        }
        // return to pipeline (whether we set the dst MAC or not)
        self.return_packet(packet);
    }

    /// Resolve the entries (and packets) with the given vector of resolutions
    fn resolve_target_packets(&mut self, resolutions: Vec<(Target, DestinationMac)>) {
        // pull out all of the entries for resolved targets and resolve their packets
        for (target, dst_mac) in resolutions {
            debug!("Target {target} is at {dst_mac}");
            if let Some(mut entry) = self.entries.remove(&target) {
                let num_packets = entry.packets.len();
                for packet in entry.packets.drain(..) {
                    self.resolve_packet(packet, dst_mac);
                }
                debug!("Resolved {num_packets} pkts for target {target}");
            }
        }
    }

    // check the resolution state of backlogged targets with the neigh cache.
    // We may find:
    //   - resolved targets: take all of their packets, resolve them and return them.
    //   - queried targets the listener/kernel report as failed: give them up.
    //   - queried targets for which no update in the cache happened in RESOLUTION_TIMEOUT.
    pub(crate) fn check_targets(&mut self) {
        let Some(cache) = self.cacher.enter() else {
            unreachable!("the neighbor cache writer is dropped only when the daemon ends");
        };

        // list of targets that can be resolved (with their mac) with the current cache
        let mut newly_resolved = vec![];

        // list of targets the kernel failed to resolve
        let mut failed = vec![];

        // list of targets not resolved in time
        let mut timed_out = vec![];

        for (target, entry) in &self.entries {
            let neigh = cache.get_entry(target.addr, target.ifindex);
            if let Some(dst_mac) = neigh.and_then(NeighEntry::usable_mac) {
                newly_resolved.push((*target, dst_mac));
                continue;
            }
            let Some(query_t) = entry.queried else {
                continue; // not queried yet
            };
            let kernel_failed = neigh.is_some_and(|n| n.failed() && n.updated() > query_t);
            if kernel_failed {
                // an explicit failure was reported by the kernel
                failed.push(*target);
            } else if elapsed(query_t) >= Self::RESOLUTION_TIMEOUT {
                // it was queried a long ago and no (usable) neighbor seems to exist
                timed_out.push(*target);
            }
        }
        drop(cache);

        // resolve the entries for all the newly-resolved targets
        self.resolve_target_packets(newly_resolved);

        // give up the targets the kernel explicitly marked as failed, and those not resolved in time
        self.give_up_targets(&failed, DoneReason::MissL2resolution);
        self.give_up_targets(&timed_out, DoneReason::MissL2resolution);
    }

    /// Scan the set of registered targets and build a list of those that the caller
    /// should query: those not queried yet. Targets are queried only once (the kernel makes
    /// several attempts on its own).
    ///
    /// N.B. The entries of the targets returned by this method get their query time recorded.
    #[must_use]
    pub(crate) fn targets_to_query(&mut self) -> Vec<Target> {
        let mut to_query = vec![];
        for (target, entry) in &mut self.entries {
            if entry.queried.is_none() {
                entry.register_query();
                to_query.push(*target);
            }
        }
        to_query
    }

    /// Give up all of the targets using some interface: their packets are returned as unresolved
    pub(crate) fn give_up_interface(&mut self, ifindex: InterfaceIndex) {
        let targets: Vec<Target> = self
            .entries
            .keys()
            .filter(|target| target.ifindex == ifindex)
            .copied()
            .collect();

        self.give_up_targets(&targets, DoneReason::MissL2resolution);
    }
}

#[cfg(test)]
mod tests {
    use super::{Backlog, ReturnBuffer};
    use crate::cache::{NeighCacheWriter, NeighEntry, NeighState};
    use crate::netlink::test_utils::{assert_given_up, assert_resolved};
    use crate::querier::Target;
    use clock::{Duration, Instant};
    use net::buffer::TestBuffer;
    use net::buffer::TestBufferPool;
    use net::eth::mac::{DestinationMac, SourceMac};
    use net::headers::TryUdp;
    use net::interface::InterfaceIndex;
    use net::packet::test_utils::build_test_udp_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use pipeline::NetworkFunction;
    use pkt_io::{EndpointId, Injector, PuntedPacket, TestPktIo};
    use std::net::IpAddr;
    use std::num::{NonZero, NonZeroUsize};
    use std::str::FromStr;

    /// An endpoint (pipeline) that the packets of the backlog come from, with an injection queue
    /// of `capacity` packets, and the injector to return packets to it.
    fn endpoint(capacity: usize) -> (Injector, TestPktIo) {
        let (factory, _punted, injector) = pkt_io::queues(
            "test",
            pkt_io::no_trap,
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(capacity).unwrap(),
        );
        (injector, factory.nf(TestBufferPool))
    }

    /// The packets returned to `endpoint`, as its pipeline sees them
    fn returned(endpoint: &mut TestPktIo) -> Vec<Packet<TestBuffer>> {
        let mut burst = vec![];
        endpoint.process_burst(&mut burst);
        burst
    }

    /// A packet from `origin` to `dst_ip` over `ifindex`, that needs resolution
    fn packet(origin: EndpointId, dst_ip: IpAddr, ifindex: InterfaceIndex) -> PuntedPacket {
        let mut packet = build_test_udp_ipv4_packet("1.2.3.4", &dst_ip.to_string(), 100, 200);
        packet.meta_mut().set_need_arp_nd(true);
        packet.meta_mut().oif = Some(ifindex);
        PuntedPacket::new(origin, packet)
    }

    /// Util: create a mapping (IP, mac, ifindex)
    #[track_caller]
    fn mapping(
        target_ip: &str,
        mac: &str,
        ifindex: u32,
    ) -> (IpAddr, DestinationMac, InterfaceIndex) {
        let ifindex = InterfaceIndex::try_new(ifindex).expect("Bad ifindex");
        let addr = IpAddr::from_str(target_ip).expect("Bad ip");
        let mac = SourceMac::try_from(mac).expect("Bad mac");
        let mac = DestinationMac::from(mac);
        (addr, mac, ifindex)
    }

    /// Build a packet from `origin` identified by `id` (its UDP source port), marked as done
    /// with `reason`
    fn returned_packet(origin: EndpointId, id: u16, reason: DoneReason) -> PuntedPacket {
        let mut packet = build_test_udp_ipv4_packet("1.2.3.4", "10.0.0.1", id, 200);
        packet.done(reason);
        PuntedPacket::new(origin, packet)
    }

    /// Get the id of a packet built by `returned_packet`
    fn packet_id(packet: &Packet<TestBuffer>) -> u16 {
        let udp = packet.try_udp().expect("not udp");
        NonZero::<u16>::from(udp.source()).get()
    }

    #[test]
    /// Test that the return buffer keeps the order of the packets and, when full, drops the
    /// new unresolved packets, and only admits a resolved one by evicting an unresolved one.
    fn test_return_buffer() {
        let (_outq, endpoint) = endpoint(1);
        let origin = endpoint.endpoint_id();
        let mut buffer = ReturnBuffer::new(3);

        // fill the buffer: the first packet is unresolved and the rest are resolved
        buffer.push_back(returned_packet(origin, 1, DoneReason::MissL2resolution));
        buffer.push_back(returned_packet(origin, 2, DoneReason::Delivered));
        buffer.push_back(returned_packet(origin, 3, DoneReason::Delivered));

        // an unresolved packet is dropped
        buffer.push_back(returned_packet(origin, 4, DoneReason::MissL2resolution));
        // a resolved packet evicts the unresolved one, and is put last
        buffer.push_back(returned_packet(origin, 5, DoneReason::Delivered));
        // another resolved packet is dropped, as there are no unresolved packets to evict
        buffer.push_back(returned_packet(origin, 6, DoneReason::Delivered));

        // packets are popped in order
        let ids: Vec<u16> = std::iter::from_fn(|| buffer.pop_front(origin))
            .map(|packet| packet_id(&packet))
            .collect();
        assert_eq!(ids, [2, 3, 5]);
        assert!(buffer.is_empty());
    }

    #[test]
    /// Test that packets that do not fit in the injection queue of their endpoint wait in the
    /// return buffer, without holding back the packets for other endpoints, and are returned
    /// in order once there is room
    fn test_backlog_returns_per_endpoint() {
        let (addr, mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        let target = Target::new(addr, ifindex);
        let (mut writer, reader) = NeighCacheWriter::new();

        // two endpoints of the same queues, each fitting a single packet
        let (factory, _punted, outq) = pkt_io::queues(
            "test",
            pkt_io::no_trap,
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        );
        let mut a: TestPktIo = factory.nf(TestBufferPool);
        let mut b: TestPktIo = factory.nf(TestBufferPool);
        let mut backlog = Backlog::new(reader, outq);

        // 3 packets from a and 1 from b, for the same target, which gets resolved
        for origin in [
            a.endpoint_id(),
            b.endpoint_id(),
            a.endpoint_id(),
            a.endpoint_id(),
        ] {
            backlog.add(target, packet(origin, addr, ifindex));
        }
        writer.add_entry(NeighEntry::reachable(addr, ifindex, mac));
        backlog.check_targets();

        // b gets its packet even if a is full
        assert_eq!(returned(&mut b).len(), 1);
        for _ in 0..3 {
            let back = returned(&mut a);
            assert_eq!(back.len(), 1, "a gets one packet per round, as it fits one");
            assert_resolved(&back[0], mac.inner());
            backlog.return_pending();
        }
        assert!(returned(&mut a).is_empty());
        assert!(backlog.return_buffer.is_empty());
    }

    #[test]
    /// Test that packets for an endpoint that is gone are dropped, rather than kept forever
    fn test_backlog_drops_packets_for_gone_endpoints() {
        let (addr, mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        let (mut writer, reader) = NeighCacheWriter::new();
        let (outq, endpoint) = endpoint(1);
        let mut backlog = Backlog::new(reader, outq);

        for _ in 0..3 {
            backlog.add(
                Target::new(addr, ifindex),
                packet(endpoint.endpoint_id(), addr, ifindex),
            );
        }
        drop(endpoint);

        writer.add_entry(NeighEntry::reachable(addr, ifindex, mac));
        backlog.check_targets();
        assert_eq!(backlog.num_targets(), 0);
        assert!(backlog.return_buffer.is_empty());
    }

    /// Build a cache entry for a neighbor that the kernel failed to resolve at time `updated`
    fn failed_entry(addr: IpAddr, ifindex: InterfaceIndex, updated: Instant) -> NeighEntry {
        let mut entry = NeighEntry::new(addr, ifindex, None, NeighState::Failed);
        entry.updated = updated;
        entry
    }

    #[test]
    /// Test that a target is given up when the kernel fails to resolve it after it was queried,
    /// but not because of an earlier failure (the query restarts the resolution).
    fn test_backlog_gives_up_failed_targets() {
        const NUM_PKTS: usize = 3;
        let (addr, _mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        let target = Target::new(addr, ifindex);

        // the kernel failed to resolve the target before
        let (mut writer, reader) = NeighCacheWriter::new();
        let earlier = clock::now() - Duration::from_secs(10);
        writer.add_entry(failed_entry(addr, ifindex, earlier));

        let (outq, mut endpoint) = endpoint(10);
        let mut backlog = Backlog::new(reader, outq);
        for _ in 1..=NUM_PKTS {
            backlog.add(target, packet(endpoint.endpoint_id(), addr, ifindex));
        }

        // the earlier failure does not give up the target, neither before nor after querying it
        backlog.check_targets();
        assert_eq!(backlog.targets_to_query(), vec![target]);
        backlog.check_targets();
        assert_eq!(
            backlog.num_packets(),
            NUM_PKTS,
            "the target should not be given up"
        );
        assert!(returned(&mut endpoint).is_empty());

        // the kernel fails to resolve it after the query: the target is given up
        let later = clock::now() + Duration::from_millis(1);
        writer.add_entry(failed_entry(addr, ifindex, later));
        backlog.check_targets();
        assert_eq!(backlog.num_targets(), 0, "the target should be given up");
        let back = returned(&mut endpoint);
        assert_eq!(back.len(), NUM_PKTS, "all packets should be returned");
        for packet in &back {
            assert_given_up(packet, DoneReason::MissL2resolution);
        }
    }

    #[test]
    /// Test that packets sent to the backlog get resolved if the cache has an entry
    /// and that get sent back to their endpoint with the proper MAC and flags
    fn test_backlog_basic_resolution() {
        // build tuple (Ip, mac, ifindex)
        let (addr, mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);

        // create cache and update entry
        let (mut writer, reader) = NeighCacheWriter::new();
        writer.add_entry(NeighEntry::reachable(addr, ifindex, mac));

        // build a backlog, with a reader to the cache
        let (outq, mut endpoint) = endpoint(10);
        let mut backlog = Backlog::new(reader, outq);

        // add packet to backlog and invoke check so that it gets resolved
        backlog.add(
            Target::new(addr, ifindex),
            packet(endpoint.endpoint_id(), addr, ifindex),
        );
        backlog.check_targets();

        assert_eq!(backlog.num_targets(), 0);
        let back = returned(&mut endpoint);
        assert_eq!(back.len(), 1, "the resolved packet was not output");
        assert_resolved(&back[0], mac.inner());
    }

    #[test]
    /// Test that the backlog keeps packets if they cannot be resolved and that
    /// once an entry in the cache is available, they get resolved at once and
    /// make it to their endpoint.
    fn test_backlog_resolves_multiple_packets() {
        // create cache and backlog
        let (mut writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(10);
        let mut backlog = Backlog::new(reader, outq);
        const NUM_PKTS: usize = 5;

        // feed the backlog with some packets. The cache has no entries
        let (addr, mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        for _ in 1..=NUM_PKTS {
            backlog.add(
                Target::new(addr, ifindex),
                packet(endpoint.endpoint_id(), addr, ifindex),
            );
        }
        backlog.check_targets();
        assert_eq!(backlog.num_targets(), 1, "Target should be in backlog");
        assert_eq!(backlog.num_packets(), NUM_PKTS, "Packets should be there");

        // feed the cache with an entry that should allow resolving the packets
        writer.add_entry(NeighEntry::reachable(addr, ifindex, mac));
        backlog.check_targets();

        assert_eq!(backlog.num_targets(), 0, "Target should be gone");
        assert_eq!(backlog.num_packets(), 0, "No packets should be there");

        // check successful resolution
        let back = returned(&mut endpoint);
        assert_eq!(back.len(), NUM_PKTS);
        for packet in &back {
            assert_resolved(packet, mac.inner());
        }
    }

    #[test]
    /// Test that targets not resolved in time are given up, and that the
    /// corresponding packets are sent to their endpoint, indicating done reason and with the
    /// mac unchanged.
    fn test_backlog_gives_up_unresolved_targets() {
        // create cache and backlog
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(10);
        let mut backlog = Backlog::new(reader, outq);
        const NUM_PKTS: usize = 5;

        // feed the backlog with some packets. The cache has no entries
        let (addr, _mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        for _ in 1..=NUM_PKTS {
            backlog.add(
                Target::new(addr, ifindex),
                packet(endpoint.endpoint_id(), addr, ifindex),
            );
        }
        // the target gets queried for the first time
        let target = Target::new(addr, ifindex);
        assert_eq!(backlog.targets_to_query(), vec![target]);

        assert_eq!(backlog.num_targets(), 1, "Target should be there");
        assert_eq!(backlog.num_packets(), NUM_PKTS, "Packets should be there");
        assert!(
            returned(&mut endpoint).is_empty(),
            "No packet should be expelled"
        );

        // pretend the query got no response in time
        expire_query(&mut backlog, target);
        backlog.check_targets();

        assert!(
            backlog.targets_to_query().is_empty(),
            "The target should not be queried again"
        );
        assert_eq!(backlog.num_targets(), 0, "Target should be gone");
        assert_eq!(backlog.num_packets(), 0, "No packets should be there");

        // check unsuccessful resolution
        let back = returned(&mut endpoint);
        assert_eq!(back.len(), NUM_PKTS, "All packets should be expelled");
        for packet in &back {
            assert_given_up(packet, DoneReason::MissL2resolution);
        }
    }

    const MAX_TARGETS: usize = Backlog::MAX_TARGETS;
    const MAX_PACKETS_PER_TARGET: usize = Backlog::MAX_PACKETS_PER_TARGET;

    /// The n-th distinct target, with the address and interface to build packets for it
    fn nth_target(n: usize) -> (Target, IpAddr, InterfaceIndex) {
        let ifindex = InterfaceIndex::try_new(2).expect("Bad ifindex");
        let [hi, lo] = u16::try_from(n)
            .expect("Too many targets for this helper")
            .to_be_bytes();
        let addr = IpAddr::from([10, 1, hi, lo]);
        (Target::new(addr, ifindex), addr, ifindex)
    }

    /// Pretend that a target was queried as many times as allowed, and that the last query was
    /// made long enough ago for the target to be given up
    fn expire_query(backlog: &mut Backlog, target: Target) {
        let entry = backlog
            .entries
            .get_mut(&target)
            .expect("Entry should be there");
        entry.queried = Some(clock::now() - Backlog::RESOLUTION_TIMEOUT - Duration::from_millis(1));
    }

    /// Add a packet from `origin` for the n-th target to the backlog
    fn add_packet_and_target(backlog: &mut Backlog, origin: EndpointId, n: usize) {
        let (target, addr, ifindex) = nth_target(n);
        backlog.add(target, packet(origin, addr, ifindex));
    }

    /// Check that `endpoint` got a single packet back, dropped by the backlog
    #[track_caller]
    fn assert_dropped(endpoint: &mut TestPktIo) {
        let back = returned(endpoint);
        assert_eq!(back.len(), 1, "the dropped packet was not output");
        assert_given_up(&back[0], DoneReason::ArpOutOfResources);
    }

    #[test]
    /// Test that a full backlog refuses packets for new targets, returning them to the pipeline
    /// marked as dropped, while it still admits packets for the targets it already has
    fn test_backlog_limits_targets() {
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(100);
        let origin = endpoint.endpoint_id();
        let mut backlog = Backlog::new(reader, outq);

        // fill the backlog with targets
        for n in 0..MAX_TARGETS {
            add_packet_and_target(&mut backlog, origin, n);
        }
        assert_eq!(backlog.num_targets(), MAX_TARGETS);
        assert!(
            returned(&mut endpoint).is_empty(),
            "No packet should be dropped"
        );

        // a packet for a new target does not fit
        add_packet_and_target(&mut backlog, origin, MAX_TARGETS);
        assert_eq!(
            backlog.num_targets(),
            MAX_TARGETS,
            "No target should be added"
        );
        assert_eq!(backlog.num_packets(), MAX_TARGETS);
        assert_dropped(&mut endpoint);

        // a packet for an existing target still fits
        add_packet_and_target(&mut backlog, origin, 0);
        assert_eq!(backlog.num_targets(), MAX_TARGETS);
        assert_eq!(backlog.num_packets(), MAX_TARGETS + 1);
        assert!(
            returned(&mut endpoint).is_empty(),
            "No packet should be dropped"
        );
    }

    #[test]
    /// Test that a target admits up to the maximum number of packets, and that further
    /// packets are returned to the pipeline marked as dropped
    fn test_backlog_limits_packets_per_target() {
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(100);
        let origin = endpoint.endpoint_id();
        let mut backlog = Backlog::new(reader, outq);

        for _ in 0..MAX_PACKETS_PER_TARGET {
            add_packet_and_target(&mut backlog, origin, 0);
        }
        assert_eq!(backlog.num_packets(), MAX_PACKETS_PER_TARGET);
        assert!(
            returned(&mut endpoint).is_empty(),
            "No packet should be dropped"
        );

        add_packet_and_target(&mut backlog, origin, 0);
        assert_eq!(backlog.num_targets(), 1);
        assert_eq!(backlog.num_packets(), MAX_PACKETS_PER_TARGET);
        assert_dropped(&mut endpoint);
    }

    #[test]
    /// Test that once targets are given up, a full backlog admits new targets
    fn test_backlog_admits_new_target_after_give_up() {
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(100);
        let origin = endpoint.endpoint_id();
        let mut backlog = Backlog::new(reader, outq);

        for n in 0..MAX_TARGETS {
            add_packet_and_target(&mut backlog, origin, n);
        }

        // all the targets get queried for the first time
        assert_eq!(backlog.targets_to_query().len(), MAX_TARGETS);

        // pretend the query for one of the targets got no response in time
        let (target, _, _) = nth_target(0);
        expire_query(&mut backlog, target);

        // give it up: no other target is due a query yet
        let num_targets = backlog.num_targets();
        let num_packets = backlog.num_packets();
        backlog.check_targets();
        assert!(backlog.targets_to_query().is_empty());
        assert_eq!(backlog.num_targets(), num_targets - 1);
        assert_eq!(backlog.num_packets(), num_packets - 1);

        // add packet for a new target: it fits since the backlog is no longer full
        add_packet_and_target(&mut backlog, origin, MAX_TARGETS);
        assert_eq!(backlog.num_targets(), MAX_TARGETS);
        assert_eq!(backlog.num_packets(), MAX_TARGETS);
        // only the given-up packet is output: the packet for the new target was not dropped
        let back = returned(&mut endpoint);
        assert_eq!(back.len(), 1, "The given-up packet should be output");
        assert_given_up(&back[0], DoneReason::MissL2resolution);
    }

    #[test]
    fn test_backlog_entry_records_queries() {
        let mut entry = super::TargetEntry::new();
        assert!(entry.queried.is_none());

        let before = clock::now();
        entry.register_query();
        assert!(entry.queried.is_some_and(|query| query >= before));
    }

    #[test]
    /// Test that new targets are to be queried once, no matter how many packets they have
    fn test_backlog_queries_new_targets_once() {
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, endpoint) = endpoint(100);
        let origin = endpoint.endpoint_id();
        let mut backlog = Backlog::new(reader, outq);

        for _ in 0..3 {
            add_packet_and_target(&mut backlog, origin, 0);
        }
        add_packet_and_target(&mut backlog, origin, 1);

        let mut due = backlog.targets_to_query();
        due.sort_by_key(|target| target.addr);
        assert_eq!(due, vec![nth_target(0).0, nth_target(1).0]);
        assert!(
            backlog.targets_to_query().is_empty(),
            "Targets just queried should not be queried again"
        );

        // packets for a target already queried don't cause new queries
        add_packet_and_target(&mut backlog, origin, 0);
        assert!(backlog.targets_to_query().is_empty());
    }

    #[test]
    /// Test that a target is queried only once, and given up if not resolved in time
    fn test_backlog_times_out_queries() {
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(100);
        let mut backlog = Backlog::new(reader, outq);
        let (target, _, _) = nth_target(0);
        add_packet_and_target(&mut backlog, endpoint.endpoint_id(), 0);
        assert_eq!(backlog.targets_to_query(), vec![target]);

        // the target is not queried again, nor given up before the timeout
        backlog.check_targets();
        assert!(backlog.targets_to_query().is_empty());
        assert_eq!(backlog.num_targets(), 1);
        assert!(returned(&mut endpoint).is_empty());

        // once the query was not answered in time, the target is given up (and not queried)
        expire_query(&mut backlog, target);
        backlog.check_targets();
        assert!(backlog.targets_to_query().is_empty());
        assert_eq!(backlog.num_targets(), 0, "The target should be given up");
        let back = returned(&mut endpoint);
        assert_eq!(back.len(), 1, "the packet was not output");
        assert_given_up(&back[0], DoneReason::MissL2resolution);
    }

    #[test]
    /// Test that giving up an interface gives up all of the targets over it, and only those
    fn test_backlog_gives_up_interface() {
        let (_writer, reader) = NeighCacheWriter::new();
        let (outq, mut endpoint) = endpoint(100);
        let origin = endpoint.endpoint_id();
        let mut backlog = Backlog::new(reader, outq);

        // two targets over interface 2 (with two packets for one of them), one over interface 3
        let (addr_a, _, if2) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        let (addr_b, _, _) = mapping("10.0.0.3", "02:ca:fe:ba:be:02", 2);
        let (addr_c, _, if3) = mapping("10.0.0.2", "02:ca:fe:ba:be:03", 3);
        backlog.add(Target::new(addr_a, if2), packet(origin, addr_a, if2));
        backlog.add(Target::new(addr_a, if2), packet(origin, addr_a, if2));
        backlog.add(Target::new(addr_b, if2), packet(origin, addr_b, if2));
        backlog.add(Target::new(addr_c, if3), packet(origin, addr_c, if3));

        backlog.give_up_interface(if2);

        assert_eq!(
            backlog.num_targets(),
            1,
            "Only the target over if3 should remain"
        );
        assert!(backlog.entries.contains_key(&Target::new(addr_c, if3)));
        assert_eq!(backlog.num_packets(), 1);
        let back = returned(&mut endpoint);
        assert_eq!(
            back.len(),
            3,
            "The packets for the targets over if2 should be output"
        );
        for packet in &back {
            assert_eq!(packet.meta().oif, Some(if2));
            assert_given_up(packet, DoneReason::MissL2resolution);
        }
    }
}
