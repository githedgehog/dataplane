// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! This module contains the backlog of packets waiting for ARP/ND resolution.
//! The module keeps no async code; just the storage of state and packets and
//! the helper logic to deal with it. The owning task ("backlog") governs
//! how the methods of this backlog are used.
//!
//! When the ARP/ND daemon gets a packet to resolve, it makes it to the backlog
//! task which adds the packet to this backlog along with the target to resolve.
//! The target may exit already (and be in the process of being resolved) or be
//! newly created. The backlog can be queried to know if the target should be
//! be queried (sending new ARP/ND requests) or not.
//!
//! Packets are stored in this backlog while the ARP/ND resolution takes place
//! and are ALWAYS sent to the outq at some point, resolved or not.
//!
//! Packets are arranged by target. A target represents the IP to resolve.
//! Packets destined to the same IP over an interface share the same target.
//! Both the number of targets and the number of packets per target are bounded.
//! If, when admitting a packet, either limit is exceeded, the backlog will reject
//! it: the packet will be marked as dropped and sent to the outq. Even if admitted,
//! the packet may be rejected later; e.g. if resolution does not happen after
//! a certain number of retries or after some time bound.
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
//!   |         .
//!   |    +----------+
//!   v    |  target  |
//!        +----------+
//! ```
//!
//! The daemon checks the backlog periodically to query again the targets not yet resolved
//! and to give up those that could not be resolved after a number of retries: a target is
//! given up when its last query (at most `MAX_RETRIES` after the first one) gets no response
//! within `RETRY_INTERVAL`. It also checks the backlog when being notified (by the netlink
//! listener) about ARP/ND cache additions. In that case, the daemon checks if any of the targets
//! can be resolved. If so, the corresponding awaiting packets get set the destination mac and
//! metadata and sent back to the outq.
//!
//! The backlog:
//!    - owns a NeighCacheReader (to read the ARP/ND cache, fed by the netlink listener)
//!    - has a handle to the outq to send resolved/unresolved packets back to the pipeline
//!    - is owned by the ARP/ND backlog task
//!    - when driven by the daemon task, it should always return packets to the outq

use ahash::AHashMap;
use net::buffer::PacketBufferMut;
use net::eth::mac::DestinationMac;
use net::headers::TryEthMut;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pkt_io::PktQueue;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::time::Duration;
use tokio::time::Instant;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use crate::cache::NeighCacheReader;
use crate::querier::Target;

/// An entry in the [`Backlog`] associated to a [`Target`] being
/// resolved, which contains the packets destined to that target.
struct TargetEntry<Buf: PacketBufferMut> {
    packets: VecDeque<Packet<Buf>>, // packets using this target
    last_query: Option<Instant>,    // time when we last queried the target for this entry
    retries: u8,                    // number of retries (queries from us)
}
impl<Buf: PacketBufferMut> TargetEntry<Buf> {
    #[must_use]
    fn new() -> Self {
        Self {
            last_query: None,
            retries: 0,
            packets: VecDeque::new(),
        }
    }

    /// Record when the target of this entry was last queried and
    /// track the number of retries after the first query.
    fn register_query(&mut self) {
        if self.last_query.is_some() {
            self.retries = self.retries.saturating_add(1);
        }
        self.last_query = Some(Instant::now());
    }
}

/// The backlog object
pub(crate) struct Backlog<Buf: PacketBufferMut> {
    entries: AHashMap<Target, TargetEntry<Buf>>,
    cacher: NeighCacheReader,
    outq: PktQueue<Buf>,
}
impl<Buf: PacketBufferMut> Backlog<Buf> {
    // the maximum number of targets that the backlog will admit
    const MAX_TARGETS: usize = 30;
    // the maximum number of packets that will be buffered per target
    const MAX_PACKETS_PER_TARGET: usize = 50;
    // minimum time between queries for a target that is not yet resolved
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);
    // the maximum number of queries for a target after the first one
    const MAX_RETRIES: u8 = 3;

    #[must_use]
    pub(crate) fn new(cacher: NeighCacheReader, outq: PktQueue<Buf>) -> Self {
        Self {
            entries: AHashMap::new(),
            cacher,
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

    /// Return a packet to the `outq`
    fn return_packet(packet: Packet<Buf>, outq: &PktQueue<Buf>) {
        if outq.push(packet).is_err() {
            // FIXME: the packet is lost and won't be accounted for by the pipeline
            warn!("Could not return dropped packet to pipeline: queue is full");
        }
    }

    /// Reject a packet setting its DoneReason and queueing it back in `outq` (back to pipeline)
    /// for accounting
    fn reject_packet(mut packet: Packet<Buf>, outq: &PktQueue<Buf>, reason: DoneReason) {
        packet.done(reason);
        Self::return_packet(packet, outq);
    }

    /// Abandon an entry by "rejecting" all of the packets that need it.
    /// The entry will be pruned later since it will be empty.
    fn target_give_up(
        target: &Target,
        entry: &mut TargetEntry<Buf>,
        outq: &PktQueue<Buf>,
        reason: DoneReason,
    ) {
        let num_packets = entry.packets.len();
        for packet in entry.packets.drain(..) {
            Self::reject_packet(packet, outq, reason);
        }
        debug!("Target {target} was given up and {num_packets} packets were dropped ({reason})");
    }

    /// Remove all of the entries that have no packets (since they were returned)
    fn prune_targets(&mut self) {
        self.entries
            .retain(|_target, entry| !entry.packets.is_empty());
    }

    /// Add a packet to the given target in the backlog. Create the target if it does not exist.
    /// If resource constraints are exceeded, target and packet will be rejected, causing packets
    /// to return unresolved to the outq (pipeline)
    pub(crate) fn add(&mut self, target: Target, packet: Packet<Buf>) {
        let num_targets = self.num_targets();
        match self.entries.entry(target) {
            Entry::Occupied(mut occupied) => {
                let packets = &mut occupied.get_mut().packets;
                if packets.len() < Self::MAX_PACKETS_PER_TARGET {
                    packets.push_back(packet);
                } else {
                    warn!("Too many packets for target {}. Dropping", target.addr);
                    Self::reject_packet(packet, &self.outq, DoneReason::ArpOutOfResources);
                }
            }
            Entry::Vacant(vacant) if num_targets < Self::MAX_TARGETS => {
                vacant.insert(TargetEntry::new()).packets.push_back(packet);
            }
            Entry::Vacant(_) => {
                warn!("Max number of targets reached!");
                Self::reject_packet(packet, &self.outq, DoneReason::ArpOutOfResources);
            }
        }
    }

    /// Set the [`DestinationMac`] MAC of a [`Packet`] and its metadata, and queue it back (to pipeline)
    fn resolve_packet(mut packet: Packet<Buf>, dst_mac: DestinationMac, outq: &PktQueue<Buf>) {
        // do the actual overwrite of the dst MAC.
        match packet.try_eth_mut() {
            Some(eth) => {
                eth.set_destination(dst_mac);
                // we assume here that mac resolution is the only action pending
                // therefore the packet is considered delivered
                packet.done(DoneReason::Delivered);
                packet.meta_mut().set_need_arp_nd(false);
            }
            None => {
                warn!("Failed to read Ethernet header. This is a bug");
                packet.done_force(DoneReason::InternalFailure);
            }
        }
        // send to pipeline (whether we set the dst MAC or not)
        Self::return_packet(packet, outq);
    }

    // check if targets can be resolved with the neigh cache. If so, take all of the backlogged
    // packets, resolve them and inject them back to the queue (pipeline)
    pub(crate) fn check_targets(&mut self) {
        let Some(cache) = self.cacher.enter() else {
            unreachable!("the neighbor cache writer is dropped only when the daemon ends");
        };
        for (target, entry) in self.entries.iter_mut() {
            debug!("Checking if target {target} has been resolved...");
            if let Some(dst_mac) = cache.get_mac(target.addr, target.ifindex) {
                let num_packets = entry.packets.len();
                for packet in entry.packets.drain(..) {
                    Self::resolve_packet(packet, dst_mac, &self.outq);
                }
                debug!("Target {target} is at {dst_mac}: {num_packets} packets were resolved");
            } else {
                debug!("Target {target} is still unresolved");
            }
        }
        drop(cache);
        self.prune_targets();
    }

    /// Scan the set of registered targets and build a list of those that the caller
    /// should query. Not all targets should be queried since some:
    ///    - may have been recently queried
    ///    - may have reached the max number of retries. If their last query got no
    ///      response within [`Self::RETRY_INTERVAL`], they are given up: their packets are
    ///      sent back to the outq as not resolved and they are removed.
    ///
    /// N.B. The entries of those targets returned by this method get their last time
    /// query updated.
    #[must_use]
    pub(crate) fn targets_to_query(&mut self) -> Vec<Target> {
        let mut to_query = vec![];

        for (target, entry) in &mut self.entries {
            // Only query a target if it has never been queried or, if it has, a retry interval
            // has elapsed since then. If a new retry would be allowed but the max number of
            // retries has been reached, give up the target instead.
            if entry
                .last_query
                .is_none_or(|last| last.elapsed() >= Self::RETRY_INTERVAL)
            {
                if entry.retries >= Self::MAX_RETRIES {
                    Self::target_give_up(target, entry, &self.outq, DoneReason::MissL2resolution);
                } else {
                    entry.register_query();
                    to_query.push(*target);
                }
            }
        }

        self.prune_targets();
        to_query
    }

    /// Give up all of the targets using some interface.
    /// Their packets are sent back to the outq as not resolved.
    pub(crate) fn give_up_interface(&mut self, ifindex: InterfaceIndex) {
        for (target, entry) in &mut self.entries {
            if target.ifindex == ifindex {
                Self::target_give_up(target, entry, &self.outq, DoneReason::MissL2resolution);
            }
        }
        self.prune_targets();
    }
}

#[cfg(test)]
mod test_backlog {
    use super::Backlog;
    use crate::cache::{NeighCacheWriter, NeighEntry};
    use crate::querier::Target;
    use net::buffer::TestBuffer;
    use net::eth::mac::{DestinationMac, SourceMac};
    use net::headers::TryEth;
    use net::interface::InterfaceIndex;
    use net::packet::test_utils::build_test_udp_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use pkt_io::PktQueue;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::time::Instant;

    fn packet(dst_ip: IpAddr, ifindex: InterfaceIndex) -> Packet<TestBuffer> {
        let mut packet = build_test_udp_ipv4_packet("1.2.3.4", &dst_ip.to_string(), 100, 200);
        packet.meta_mut().set_need_arp_nd(true);
        packet.meta_mut().oif = Some(ifindex);
        packet
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

    #[test]
    /// Test that packets sent to the backlog get resolved if the cache has an entry
    /// and that get sent back to the outq with the proper MAC and flags
    fn test_backlog_basic_resolution() {
        // build tuple (Ip, mac, ifindex)
        let (addr, mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);

        // create cache and update entry
        let (mut writer, reader) = NeighCacheWriter::new();
        writer.add_entry(NeighEntry::reachable(addr, ifindex, mac));

        // build a backlog, with a reader to the cache
        let outq = PktQueue::new(10);
        let mut backlog = Backlog::new(reader, outq.clone());

        // add packet to backlog and invoke check so that it gets resolved
        backlog.add(Target::new(addr, ifindex), packet(addr, ifindex));
        backlog.check_targets();

        assert_eq!(backlog.num_targets(), 0);
        let packet = outq.pop().expect("the resolved packet was not output");
        assert!(!packet.meta().need_arp_nd());
        assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
        assert_eq!(packet.try_eth().map(|eth| eth.destination()), Some(mac));
    }

    #[test]
    /// Test that the backlog keeps packets if they cannot be resolved and that
    /// once an entry in the cache is available, they get resolved at once and
    /// make it to the given outq.
    fn test_backlog_resolves_multiple_packets() {
        // create cache and backlog
        let (mut writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(10);
        let mut backlog = Backlog::<TestBuffer>::new(reader, outq.clone());
        const NUM_PKTS: usize = 5;

        // feed the backlog with some packets. The cache has no entries
        let (addr, mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        for _ in 1..=NUM_PKTS {
            backlog.add(Target::new(addr, ifindex), packet(addr, ifindex));
        }
        backlog.check_targets();
        assert_eq!(backlog.num_targets(), 1, "Target should be in backlog");
        assert_eq!(backlog.num_packets(), NUM_PKTS, "Packets should be there");

        // feed the cache with an entry that should allow resolving the packets
        writer.add_entry(NeighEntry::reachable(addr, ifindex, mac));
        backlog.check_targets();

        assert_eq!(backlog.num_targets(), 0, "Target should be gone");
        assert_eq!(backlog.num_packets(), 0, "No packets should be there");
        assert_eq!(outq.len(), NUM_PKTS);

        // check successful resolution
        for packet in outq.pop_ready() {
            assert!(!packet.meta().need_arp_nd());
            assert_eq!(packet.get_done(), Some(DoneReason::Delivered));
            assert_eq!(packet.try_eth().map(|eth| eth.destination()), Some(mac));
        }
    }

    #[test]
    /// Test that targets not resolved after all the retries are given up, and that the
    /// corresponding packets are sent to the outq, indicating done reason and with the
    /// mac unchanged.
    fn test_backlog_gives_up_unresolved_targets() {
        // create cache and backlog
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(10);
        let mut backlog = Backlog::new(reader, outq.clone());
        const NUM_PKTS: usize = 5;

        // feed the backlog with some packets. The cache has no entries
        let (addr, _mac, ifindex) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        let original_mac = packet(addr, ifindex).try_eth().map(|eth| eth.destination());
        for _ in 1..=NUM_PKTS {
            backlog.add(Target::new(addr, ifindex), packet(addr, ifindex));
        }
        // the target gets queried for the first time
        let target = Target::new(addr, ifindex);
        assert_eq!(backlog.targets_to_query(), vec![target]);

        assert_eq!(backlog.num_targets(), 1, "Target should be there");
        assert_eq!(backlog.num_packets(), NUM_PKTS, "Packets should be there");
        assert_eq!(outq.len(), 0, "No packet should be expelled");

        // pretend all the retries were made and the last one got no response in time
        exhaust_queries(&mut backlog, target);

        assert!(
            backlog.targets_to_query().is_empty(),
            "No retries should be left"
        );
        assert_eq!(backlog.num_targets(), 0, "Target should be gone");
        assert_eq!(backlog.num_packets(), 0, "No packets should be there");
        assert_eq!(outq.len(), NUM_PKTS, "All packets should be expelled");

        // check unsuccessful resolution
        for packet in outq.pop_ready() {
            assert!(packet.meta().need_arp_nd());
            assert_eq!(packet.get_done(), Some(DoneReason::MissL2resolution));
            // the destination MAC is left as it was
            assert_eq!(packet.try_eth().map(|eth| eth.destination()), original_mac);
        }
    }

    const MAX_TARGETS: usize = Backlog::<TestBuffer>::MAX_TARGETS;
    const MAX_PACKETS_PER_TARGET: usize = Backlog::<TestBuffer>::MAX_PACKETS_PER_TARGET;

    /// The n-th distinct target, with the address and interface to build packets for it
    fn nth_target(n: usize) -> (Target, IpAddr, InterfaceIndex) {
        let ifindex = InterfaceIndex::try_new(2).expect("Bad ifindex");
        let n = u8::try_from(n).expect("Too many targets for this helper");
        let addr = IpAddr::from([10, 0, 1, n]);
        (Target::new(addr, ifindex), addr, ifindex)
    }

    /// Pretend that a target was queried as many times as allowed, and that the last query was
    /// made long enough ago for the target to be given up
    fn exhaust_queries(backlog: &mut Backlog<TestBuffer>, target: Target) {
        let entry = backlog
            .entries
            .get_mut(&target)
            .expect("Entry should be there");
        entry.retries = Backlog::<TestBuffer>::MAX_RETRIES;
        entry.last_query =
            Some(Instant::now() - Backlog::<TestBuffer>::RETRY_INTERVAL - Duration::from_millis(1));
    }

    /// Add a packet for the n-th target to the backlog
    fn add_packet_and_target(backlog: &mut Backlog<TestBuffer>, n: usize) {
        let (target, addr, ifindex) = nth_target(n);
        backlog.add(target, packet(addr, ifindex));
    }

    /// Pop a packet from `outq`, checking that it was dropped by the backlog
    #[track_caller]
    fn assert_dropped(outq: &PktQueue<TestBuffer>) {
        let packet = outq.pop().expect("the dropped packet was not output");
        assert_eq!(packet.get_done(), Some(DoneReason::ArpOutOfResources));
    }

    #[test]
    /// Test that a full backlog refuses packets for new targets, returning them to the pipeline
    /// marked as dropped, while it still admits packets for the targets it already has
    fn test_backlog_limits_targets() {
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(100);
        let mut backlog = Backlog::<TestBuffer>::new(reader, outq.clone());

        // fill the backlog with targets
        for n in 0..MAX_TARGETS {
            add_packet_and_target(&mut backlog, n);
        }
        assert_eq!(backlog.num_targets(), MAX_TARGETS);
        assert!(outq.is_empty(), "No packet should be dropped");

        // a packet for a new target does not fit
        add_packet_and_target(&mut backlog, MAX_TARGETS);
        assert_eq!(
            backlog.num_targets(),
            MAX_TARGETS,
            "No target should be added"
        );
        assert_eq!(backlog.num_packets(), MAX_TARGETS);
        assert_dropped(&outq);

        // a packet for an existing target still fits
        add_packet_and_target(&mut backlog, 0);
        assert_eq!(backlog.num_targets(), MAX_TARGETS);
        assert_eq!(backlog.num_packets(), MAX_TARGETS + 1);
        assert!(outq.is_empty(), "No packet should be dropped");
    }

    #[test]
    /// Test that a target admits up to the maximum number of packets, and that further
    /// packets are returned to the pipeline marked as dropped
    fn test_backlog_limits_packets_per_target() {
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(100);
        let mut backlog = Backlog::<TestBuffer>::new(reader, outq.clone());

        for _ in 0..MAX_PACKETS_PER_TARGET {
            add_packet_and_target(&mut backlog, 0);
        }
        assert_eq!(backlog.num_packets(), MAX_PACKETS_PER_TARGET);
        assert!(outq.is_empty(), "No packet should be dropped");

        add_packet_and_target(&mut backlog, 0);
        assert_eq!(backlog.num_targets(), 1);
        assert_eq!(backlog.num_packets(), MAX_PACKETS_PER_TARGET);
        assert_dropped(&outq);
        assert!(outq.is_empty(), "Only one packet should be dropped");
    }

    #[test]
    /// Test that once targets are given up, a full backlog admits new targets
    fn test_backlog_admits_new_target_after_give_up() {
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(100);
        let mut backlog = Backlog::<TestBuffer>::new(reader, outq.clone());

        for n in 0..MAX_TARGETS {
            add_packet_and_target(&mut backlog, n);
        }

        // all the targets get queried for the first time
        assert_eq!(backlog.targets_to_query().len(), MAX_TARGETS);

        // pretend all the retries for one of the targets were made with no response
        let (target, _, _) = nth_target(0);
        exhaust_queries(&mut backlog, target);

        // give it up: no other target is due a query yet
        let num_targets = backlog.num_targets();
        let num_packets = backlog.num_packets();
        assert!(backlog.targets_to_query().is_empty());
        assert_eq!(backlog.num_targets(), num_targets - 1);
        assert_eq!(backlog.num_packets(), num_packets - 1);

        // add packet for a new target: it fits since the backlog is no longer full
        add_packet_and_target(&mut backlog, MAX_TARGETS);
        assert_eq!(backlog.num_targets(), MAX_TARGETS);
        assert_eq!(backlog.num_packets(), MAX_TARGETS);
        // only the given-up packet is output: the packet for the new target was not dropped
        assert_eq!(outq.len(), 1, "The given-up packet should be output");
        for packet in outq.pop_ready() {
            assert_eq!(packet.get_done(), Some(DoneReason::MissL2resolution));
        }
    }

    #[test]
    /// Test that the first query of a target is not a retry, and that later ones are
    fn test_backlog_entry_records_queries() {
        let mut entry = super::TargetEntry::<TestBuffer>::new();
        assert!(entry.last_query.is_none());
        assert_eq!(entry.retries, 0);

        entry.register_query();
        let first = entry.last_query.expect("the query was not recorded");
        assert_eq!(entry.retries, 0, "the first query is not a retry");

        entry.register_query();
        assert!(entry.last_query.is_some_and(|last| last >= first));
        assert_eq!(entry.retries, 1);
    }

    #[test]
    /// Test that new targets are to be queried once, no matter how many packets they have
    fn test_backlog_queries_new_targets_once() {
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(100);
        let mut backlog = Backlog::<TestBuffer>::new(reader, outq);

        for _ in 0..3 {
            add_packet_and_target(&mut backlog, 0);
        }
        add_packet_and_target(&mut backlog, 1);

        let mut due = backlog.targets_to_query();
        due.sort_by_key(|target| target.addr);
        assert_eq!(due, vec![nth_target(0).0, nth_target(1).0]);
        assert!(
            backlog.targets_to_query().is_empty(),
            "Targets just queried should not be queried again"
        );

        // packets for a target already queried don't cause new queries
        add_packet_and_target(&mut backlog, 0);
        assert!(backlog.targets_to_query().is_empty());
    }

    #[test]
    /// Test that unresolved targets are queried again after the retry interval, up to the
    /// maximum number of retries
    fn test_backlog_retries_queries() {
        type B = Backlog<TestBuffer>;
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(100);
        let mut backlog = B::new(reader, outq.clone());
        let (target, _, _) = nth_target(0);
        add_packet_and_target(&mut backlog, 0);
        assert_eq!(backlog.targets_to_query(), vec![target]);

        for retry in 1..=B::MAX_RETRIES {
            assert!(backlog.targets_to_query().is_empty(), "Too early to retry");

            // pretend the last query was made one retry interval ago
            let entry = backlog
                .entries
                .get_mut(&target)
                .expect("Entry should be there");
            entry.last_query = entry
                .last_query
                .map(|last| last - B::RETRY_INTERVAL - Duration::from_millis(1));

            assert_eq!(backlog.targets_to_query(), vec![target]);
            assert_eq!(backlog.entries[&target].retries, retry);
        }

        // no more retries: the last query still gets its retry interval to be answered
        assert!(
            backlog.targets_to_query().is_empty(),
            "Too early to give up"
        );
        assert_eq!(backlog.num_targets(), 1);
        assert!(outq.is_empty());

        // once the last query was not answered in time, the target is given up
        let entry = backlog
            .entries
            .get_mut(&target)
            .expect("Entry should be there");
        entry.last_query = entry
            .last_query
            .map(|last| last - B::RETRY_INTERVAL - Duration::from_millis(1));
        assert!(
            backlog.targets_to_query().is_empty(),
            "No retries should be left"
        );
        assert_eq!(backlog.num_targets(), 0, "The target should be given up");
        let packet = outq.pop().expect("the packet was not output");
        assert_eq!(packet.get_done(), Some(DoneReason::MissL2resolution));
        assert!(outq.is_empty());
    }

    #[test]
    /// Test that giving up an interface gives up all of the targets over it, and only those
    fn test_backlog_gives_up_interface() {
        let (_writer, reader) = NeighCacheWriter::new();
        let outq = PktQueue::new(100);
        let mut backlog = Backlog::<TestBuffer>::new(reader, outq.clone());

        // two targets over interface 2 (with two packets for one of them), one over interface 3
        let (addr_a, _, if2) = mapping("10.0.0.2", "02:ca:fe:ba:be:01", 2);
        let (addr_b, _, _) = mapping("10.0.0.3", "02:ca:fe:ba:be:02", 2);
        let (addr_c, _, if3) = mapping("10.0.0.2", "02:ca:fe:ba:be:03", 3);
        backlog.add(Target::new(addr_a, if2), packet(addr_a, if2));
        backlog.add(Target::new(addr_a, if2), packet(addr_a, if2));
        backlog.add(Target::new(addr_b, if2), packet(addr_b, if2));
        backlog.add(Target::new(addr_c, if3), packet(addr_c, if3));

        backlog.give_up_interface(if2);

        assert_eq!(
            backlog.num_targets(),
            1,
            "Only the target over if3 should remain"
        );
        assert!(backlog.entries.contains_key(&Target::new(addr_c, if3)));
        assert_eq!(backlog.num_packets(), 1);
        assert_eq!(
            outq.len(),
            3,
            "The packets for the targets over if2 should be output"
        );
        for packet in outq.pop_ready() {
            assert_eq!(packet.meta().oif, Some(if2));
            assert_eq!(packet.get_done(), Some(DoneReason::MissL2resolution));
        }
    }
}
