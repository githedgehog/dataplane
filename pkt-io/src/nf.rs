// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

use crate::queue::PktQueue;
use net::packet::Packet;
use net::{buffer::PacketBufferMut, packet::DoneReason};
use pipeline::NetworkFunction;

use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, trace};

const PKT_IO: &str = "pkt-io";
trace_target!(PKT_IO, LevelFilter::TRACE, &["pipeline"]);

/// Type for a network function that has two basic capabilities:
///    1) allow the injection of packets into a pipeline (e.g. to transmit them).
///    2) allow pulling packets out of a pipeline (e.g. "punt" or "trap" for extra processing
///       or local consumption).
///
/// The above is achieved using two queues/channels. One queue (injectq) holds packets to be
/// injected into the pipeline, and may be populated by other threads. This queue may be used
/// to transmit locally-generated packets. Another one (puntq) contains packets that have been
/// removed from the pipeline and are to be processed elsewhere, possibly by another thread.
/// Sample applications are: 1) processing traffic destined to the gateway 2) optional possibly costly post-
/// processing (slow path) of packets. An example of the latter is a packet that has to be routed
/// but whose next-hop mac address is not known and needs to be resolved via ARP/ND. Those packets need
/// to be pulled out of the pipeline and be temporarily cached while the L2 discovery takes place.
/// The two queues:
///   * have fixed capacities (bounded)
///   * hold packets by value: these are moved in and out of the queues, as in the pipeline
///   * are optional to accommodate for cases where only injection or punting are needed.
///
/// Lastly, in the case of punting traffic, the criterion to steer a packet into the puntq is
/// customizable via a [`TrapFunction`]. By default, [`TrapFunction`] selects packets destined to the gateway.
pub struct PktIo<Buf: PacketBufferMut> {
    #[allow(unused)]
    name: String,
    injectq: Option<PktQueue<Buf>>,
    puntq: Option<PktQueue<Buf>>,
    trap_function: TrapFunction<Buf>,
}
/// This is manually implemented because deriving it
/// would require Buf to implement Clone
impl<Buf: PacketBufferMut> Clone for PktIo<Buf> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            injectq: self.injectq.clone(),
            puntq: self.puntq.clone(),
            trap_function: self.trap_function,
        }
    }
}

/// A type that represents a criterion to select a packet.
/// We use this type to determine if a `Packet` is to be trapped/punted
pub type TrapFunction<Buf> = fn(&Packet<Buf>) -> bool;

/// A [`TrapFunction`] that returns false for all packets
#[allow(unused)]
pub fn no_trap<Buf: PacketBufferMut>(_packet: &Packet<Buf>) -> bool {
    false
}

/// A [`TrapFunction`] that returns true for all packets that are locally-destined, according to their
/// metadata. This function assumes that prior stages will have correctly identified and annotated those packets.
pub fn is_local<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> bool {
    packet.meta().is_local()
}

impl<Buf: PacketBufferMut> PktIo<Buf> {
    #[must_use]
    pub(crate) fn create_queue(capacity: usize) -> Option<PktQueue<Buf>> {
        match capacity {
            0 => None,
            n => Some(PktQueue::new(n)),
        }
    }
    #[must_use]
    pub fn new(name: &str, inject_capacity: usize, punt_capacity: usize) -> Self {
        Self {
            name: name.to_string(),
            injectq: Self::create_queue(inject_capacity),
            puntq: Self::create_queue(punt_capacity),
            trap_function: is_local, // default
        }
    }
    #[must_use]
    pub fn set_trap_function(mut self, trap_function: TrapFunction<Buf>) -> Self {
        self.trap_function = trap_function;
        self
    }
    pub fn set_injectq(&mut self, queue: PktQueue<Buf>) {
        self.injectq = Some(queue);
    }
    pub fn set_puntq(&mut self, queue: PktQueue<Buf>) {
        self.puntq = Some(queue);
    }

    #[must_use]
    pub fn get_injectq(&self) -> Option<PktQueue<Buf>> {
        self.injectq.clone()
    }

    #[must_use]
    pub fn get_puntq(&self) -> Option<PktQueue<Buf>> {
        self.puntq.clone()
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PktIo<Buf> {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        // if a punt queue is set up, attempt to punt each pkt in the burst
        // for which the trap function returns true
        if let Some(puntq) = &self.puntq {
            // packets that could not be punted are kept in the burst, marked as dropped.
            let trap = self.trap_function;
            let mut failed = vec![];
            for packet in burst.extract_if(.., |packet| trap(packet)) {
                if let Err(mut dropped) = puntq.push(packet) {
                    trace!("Unable to punt packet\n{dropped}");
                    dropped.done(DoneReason::InternalDrop);
                    failed.push(dropped);
                }
            }
            burst.append(&mut failed);
        }

        // injection path: fetch packets from the injection queue (if there) and add them to the input burst
        // Only packets queued at this point are injected, so that producers can't stall the pipeline.
        if let Some(injectq) = &self.injectq {
            burst.reserve(injectq.len());
            burst.extend(injectq.pop_ready());
        }
    }
}

#[cfg(test)]
mod test {
    use super::PktIo;
    use net::buffer::TestBuffer;
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use pipeline::NetworkFunction;

    // packets are identified by their TTL
    fn packet(ttl: u8, local: bool) -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet(ttl).unwrap();
        packet.meta_mut().set_local(local);
        packet
    }

    // build a vector of TTLs for the given iterator of packets
    fn ttls<'a>(packets: impl IntoIterator<Item = &'a Packet<TestBuffer>>) -> Vec<u8> {
        packets
            .into_iter()
            .map(|p| p.try_ipv4().unwrap().ttl())
            .collect()
    }

    #[test]
    fn test_process_burst_punts_and_keeps_order() {
        let mut pktio = PktIo::<TestBuffer>::new("test", 0, 10);
        let puntq = pktio.get_puntq().unwrap();

        // burst of packets (TTLs) and local annotations (booleans)
        let mut burst = vec![
            packet(1, true),
            packet(2, false),
            packet(3, true),
            packet(4, false),
        ];
        pktio.process_burst(&mut burst);

        assert_eq!(ttls(&burst), [2, 4]);
        assert!(burst.iter().all(|p| p.get_done().is_none()));
        let punted: Vec<_> = puntq.pop_ready().collect();
        assert_eq!(ttls(&punted), [1, 3]);
    }

    #[test]
    fn test_process_burst_full_puntq() {
        let mut pktio = PktIo::<TestBuffer>::new("test", 0, 1);
        let puntq = pktio.get_puntq().unwrap();

        let mut burst = vec![packet(1, true), packet(2, false), packet(3, true)];
        pktio.process_burst(&mut burst);

        // the packet that did not fit in the punt queue stays in the burst, marked as dropped
        assert_eq!(ttls(&burst), [2, 3]);
        assert_eq!(burst[0].get_done(), None);
        assert_eq!(burst[1].get_done(), Some(DoneReason::InternalDrop));
        assert_eq!(ttls(&puntq.pop_ready().collect::<Vec<_>>()), [1]);
    }

    #[test]
    fn test_process_burst_injects_after_punting() {
        let mut pktio = PktIo::<TestBuffer>::new("test", 10, 10);
        let injectq = pktio.get_injectq().unwrap();
        let puntq = pktio.get_puntq().unwrap();

        // injected packets are local too, but must not be punted
        injectq.push(packet(10, true)).unwrap();
        injectq.push(packet(11, true)).unwrap();

        let mut burst = vec![packet(1, true), packet(2, false)];
        pktio.process_burst(&mut burst);

        assert_eq!(ttls(&burst), [2, 10, 11]);
        assert!(injectq.is_empty());
        assert_eq!(ttls(&puntq.pop_ready().collect::<Vec<_>>()), [1]);
    }
}
