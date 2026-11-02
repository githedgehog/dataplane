// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! This module contains packet queues to punt packets from pipelines and inject packets into them.
//! All of the queues are MPSC and bounded in size:
//!   * punting allows sending packets from the pipeline to a single consumer (e.g. some daemon).
//!     When a packet is punted, the sending entity is specified along the packet so that, if needed,
//!     the packet can be returned to the same entity (e.g. a worker)
//!   * since multiple pipelines can exist (e.g. one per worker), injection requires specifying
//!     the targeted pipeline via an [`EndpointId`].
//!
//! The queues are created by [`NfEndpointFactory::new`]:
//!   * One punt queue, shared by all of the endpoints: a bounded multi-producer, single-consumer
//!     queue. The endpoints push to it and the consumer pops from it, with a [`PuntReceiver`].
//!   * One injection queue per endpoint: a bounded single-producer, single-consumer queue. The
//!     consumer pushes to them with an [`Injector`] and each endpoint pops from its own.
//!
//! An endpoint [`NfEndpoint`] holds the objects to punt and receive packets from a single entity.
//! Each endpoint has an [`EndpointId`], which is stamped on the packets that it punts, as a
//! [`PuntedPacket`]. The consumer can use it to inject each packet back, with the [`Injector`],
//! into the endpoint that punted it.
//!
//! Queued packets are always `Packet<TestBuffer>`, whatever the buffer type of the pipelines:
//! endpoints rebuffer the packets that they punt, and their users rebuffer the packets injected
//! into them. This way, buffers local to a pipeline (e.g. DPDK `Mbuf`s) never leave it.

use concurrency::slot::Slot;
use concurrency::sync::{Arc, Mutex};
use net::buffer::TestBuffer;
use net::packet::{Packet, Rebuffer};
use pipeline::SchedRun;
use std::fmt::{Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};

/// The identity of an endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(usize);
impl Display for EndpointId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "endpoint-{}", self.0)
    }
}

/// A packet punted, and the endpoint that it came from.
/// Punted packets are ALWAYS rebuffered to `TestBuffer` if they don't
/// use `TestBuffer`s. A `PuntedPacket` derefs to the packet that it holds.
#[derive(Debug)]
pub struct PuntedPacket {
    origin: EndpointId,
    packet: Packet<TestBuffer>,
}

impl PuntedPacket {
    /// Create a [`PuntedPacket`] for packet `packet` and endpoint `origin`.
    #[must_use]
    pub fn new(origin: EndpointId, packet: Packet<TestBuffer>) -> Self {
        Self { origin, packet }
    }

    /// The id of the endpoint the packet came from
    #[must_use]
    pub fn origin(&self) -> EndpointId {
        self.origin
    }

    /// Get the packet
    #[must_use]
    pub fn into_packet(self) -> Packet<TestBuffer> {
        self.packet
    }
}

impl Deref for PuntedPacket {
    type Target = Packet<TestBuffer>;
    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}
impl DerefMut for PuntedPacket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.packet
    }
}

/// The sending end towards an endpoint, and the [`SchedRun`] of the pipeline of the endpoint,
/// which the [`Injector`] sets after queuing a packet. The pipeline is only known once the user
/// of the endpoint is added to it: until then, the signal is one that nobody checks (see
/// [`NfEndpoint::set_sched_run`]).
#[derive(Clone)]
struct InjectTarget {
    sender: Sender<Packet<TestBuffer>>, // sender towards an endpoint
    sched: SchedRun,                    // schedule of runs of the pipeline of the endpoint
}

/// The injection queues to the endpoints, indexed by [`EndpointId`]. They are published in a
/// [`Slot`], so that the [`Injector`] reads them without locking: adding an endpoint publishes a
/// new copy, with the queue of the new endpoint (see [`NfEndpointFactory`]). Endpoints are only
/// added: the queue of an endpoint that is dropped is kept, and fails to send.
type InjectSenders = Arc<Slot<Vec<InjectTarget>>>;

/// Object that allows punting or injecting packets
pub(crate) struct NfEndpoint {
    id: EndpointId,
    puntq: Sender<PuntedPacket>,
    injectq: Receiver<Packet<TestBuffer>>,
    senders: InjectSenders,
    lock: Arc<Mutex<()>>,
}

impl NfEndpoint {
    /// The id of this endpoint
    #[must_use]
    pub(crate) fn id(&self) -> EndpointId {
        self.id
    }

    /// Punt a `packet` towards the single punt receiver
    ///
    /// # Errors
    ///
    /// If the punt queue is full, `packet` is returned as it was.
    #[allow(clippy::result_large_err)]
    pub(crate) fn punt<Buf: Rebuffer>(&self, packet: Packet<Buf>) -> Result<(), Packet<Buf>> {
        // Since the queue may have no room, we first attempt a reservation before rebuffering
        // packets, so that if packets don't fit, they keep their original buffer
        match self.puntq.try_reserve() {
            Ok(permit) => {
                permit.send(PuntedPacket::new(self.id, Buf::into_test_buffer(packet)));
                Ok(())
            }
            Err(_) => Err(packet),
        }
    }

    /// Fetch up to `num_pkts` from the injection queue
    pub(crate) fn inject_fetch(
        &mut self,
        num_pkts: usize,
    ) -> impl Iterator<Item = Packet<TestBuffer>> + '_ {
        (0..num_pkts).map_while(|_| self.injectq.try_recv().ok())
    }

    /// Tell how many packets may be read from the injection queue
    #[must_use]
    pub(crate) fn pending_injected(&self) -> usize {
        self.injectq.len()
    }

    /// Let the [`Injector`] request runs of `sched` for the packets that it queues to this endpoint, e.g.
    /// the [`SchedRun`] of the pipeline of the user of the endpoint. This republishes the
    /// injection queues, as adding an endpoint does.
    pub(crate) fn set_sched_run(&self, sched: SchedRun) {
        let lock = self.lock.lock();
        let mut senders = Vec::clone(&self.senders.load());
        if let Some(target) = senders.get_mut(self.id.0) {
            target.sched = sched;
        }
        self.senders.store(Arc::new(senders));
        drop(lock);
    }
}

/// Creates the endpoints of the queues created along with it, by [`Self::new`]. Clones create
/// endpoints of the same queues.
#[derive(Clone)]
pub(crate) struct NfEndpointFactory {
    punt: Sender<PuntedPacket>,
    senders: InjectSenders,
    lock: Arc<Mutex<()>>,
    inject_capacity: NonZeroUsize,
}

impl NfEndpointFactory {
    /// Create the queues to punt/inject packets for a number of endpoints, with the
    /// given capacities.
    ///
    /// Returns:
    ///   * the [`NfEndpointFactory`] to create the endpoints,
    ///   * the [`PuntReceiver`] to receive punted packets
    ///   * the [`Injector`] to inject packets
    #[must_use]
    pub(crate) fn new(
        punt_capacity: NonZeroUsize,
        inject_capacity: NonZeroUsize,
    ) -> (Self, PuntReceiver, Injector) {
        let (sender, receiver) = channel(punt_capacity.get());
        let senders = InjectSenders::new(Slot::from_pointee(vec![]));
        let factory = Self {
            punt: sender,
            senders: senders.clone(),
            lock: Arc::new(Mutex::new(())),
            inject_capacity,
        };
        (factory, PuntReceiver(receiver), Injector(senders))
    }

    /// Create a new endpoint, with an owned injection queue
    #[must_use]
    pub(crate) fn endpoint(&self) -> NfEndpoint {
        let (sender, receiver) = channel(self.inject_capacity.get());
        let lock = self.lock.lock();
        let mut senders = Vec::clone(&self.senders.load());
        senders.push(InjectTarget {
            sender,
            sched: SchedRun::default(),
        });
        let id = EndpointId(senders.len() - 1);
        self.senders.store(Arc::new(senders));
        drop(lock);
        NfEndpoint {
            id,
            puntq: self.punt.clone(),
            injectq: receiver,
            senders: self.senders.clone(),
            lock: self.lock.clone(),
        }
    }
}

/// The receiving end of the punt queue created by [`crate::queues`]. There is a single one.
pub struct PuntReceiver(Receiver<PuntedPacket>);

impl PuntReceiver {
    /// Get a packet from the queue. If there is none, return `None` without blocking.
    #[must_use]
    pub fn pop(&mut self) -> Option<PuntedPacket> {
        self.0.try_recv().ok()
    }

    /// Get the packets that are in the queue at the time of the call, without blocking.
    /// Packets pushed while the returned iterator is consumed are left in the queue, so that
    /// the endpoints cannot keep the caller draining the queue indefinitely.
    pub fn pop_ready(&mut self) -> impl Iterator<Item = PuntedPacket> {
        let ready = self.0.len();
        (0..ready).map_while(|_| self.0.try_recv().ok())
    }

    /// Get a packet from the queue. If empty, _asynchronously_ WAIT until there is one.
    /// Returns `None` only if all of the endpoints were dropped and the queue is empty.
    #[must_use]
    pub async fn pop_async(&mut self) -> Option<PuntedPacket> {
        self.0.recv().await
    }
}

/// Why an [`Injector`] could not inject a packet. The packet is handed back.
#[derive(Debug)]
pub enum InjectError {
    /// The injection queue of the endpoint is full. Injecting the packet may succeed later.
    FullQueue(Packet<TestBuffer>),
    /// There is no endpoint to take the packet: it was dropped, or the id is not of an endpoint
    /// of these queues. Injecting the packet will never succeed.
    NoEndpoint(Packet<TestBuffer>),
}

impl InjectError {
    /// Get back the packet that could not be injected
    #[must_use]
    pub fn into_packet(self) -> Packet<TestBuffer> {
        match self {
            InjectError::FullQueue(packet) | InjectError::NoEndpoint(packet) => packet,
        }
    }
}

/// Injects packets into the endpoints of the queues created by [`crate::queues`], e.g. the
/// packets punted, each into the endpoint that it came from (see [`PuntedPacket::origin`]).
/// Clones inject into the same endpoints.
#[derive(Clone)]
pub struct Injector(InjectSenders);

impl Injector {
    /// Inject `packet` into the endpoint `endpoint`, without blocking, and sched the run
    /// of its pipeline.
    ///
    /// # Errors
    ///
    /// The packet is returned if the injection queue of the endpoint is full, or if there is no
    /// such endpoint any more.
    #[allow(clippy::result_large_err)]
    pub fn inject(
        &self,
        endpoint: EndpointId,
        packet: Packet<TestBuffer>,
    ) -> Result<(), InjectError> {
        let senders = self.0.load();
        let Some(target) = senders.get(endpoint.0) else {
            return Err(InjectError::NoEndpoint(packet));
        };
        target.sender.try_send(packet).map_err(|e| match e {
            TrySendError::Full(packet) => InjectError::FullQueue(packet),
            TrySendError::Closed(packet) => InjectError::NoEndpoint(packet),
        })?;
        // sched a pipeline run in case no packet arrives
        target.sched.asap();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{InjectError, NfEndpoint, NfEndpointFactory};
    use net::buffer::TestBuffer;
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use std::num::NonZeroUsize;

    fn capacity(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    // the packets injected into an endpoint, at this point
    fn injected(endpoint: &mut NfEndpoint) -> Vec<Packet<TestBuffer>> {
        let ready = endpoint.pending_injected();
        endpoint.inject_fetch(ready).collect()
    }

    fn ttls(packets: &[Packet<TestBuffer>]) -> Vec<u8> {
        packets
            .iter()
            .map(|p| p.try_ipv4().unwrap().ttl())
            .collect()
    }

    #[test]
    fn test_endpoints_get_distinct_ids() {
        let (endpoints, _punted, _injector) = NfEndpointFactory::new(capacity(1), capacity(1));
        let a = endpoints.endpoint();
        let b = endpoints.clone().endpoint();
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn test_endpoints_added_concurrently_are_all_injectable() {
        const NUM_ENDPOINTS: usize = 16;
        let (endpoints, _punted, injector) = NfEndpointFactory::new(capacity(1), capacity(1));

        // endpoints are added at once from distinct threads, as pipelines would
        let barrier = concurrency::sync::Barrier::new(NUM_ENDPOINTS);
        let mut added: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..NUM_ENDPOINTS)
                .map(|_| {
                    let endpoints = endpoints.clone();
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        endpoints.endpoint()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        // none was lost: each has an id of its own and gets what is injected into it
        let mut ids: Vec<_> = added.iter().map(super::NfEndpoint::id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), NUM_ENDPOINTS);
        for endpoint in &mut added {
            let packet = build_test_ipv4_packet(1).unwrap();
            injector.inject(endpoint.id(), packet).unwrap();
            assert_eq!(injected(endpoint).len(), 1);
        }
    }

    #[test]
    fn test_inject_into_the_endpoint_a_packet_came_from() {
        let (endpoints, _punted, injector) = NfEndpointFactory::new(capacity(1), capacity(10));
        let mut a = endpoints.endpoint();
        let mut b = endpoints.endpoint();

        let packet = |ttl| build_test_ipv4_packet(ttl).unwrap();
        injector.inject(a.id(), packet(1)).unwrap();
        injector.inject(b.id(), packet(2)).unwrap();
        injector.inject(a.id(), packet(3)).unwrap();

        assert_eq!(ttls(&injected(&mut a)), [1, 3]);
        assert_eq!(ttls(&injected(&mut b)), [2]);
    }

    #[test]
    fn test_inject_requests_a_run() {
        use pipeline::SchedRun;

        let (endpoints, _punted, injector) = NfEndpointFactory::new(capacity(1), capacity(1));
        let mut a = endpoints.endpoint();
        let b = endpoints.endpoint();
        let sched = SchedRun::default();
        a.set_sched_run(sched.clone());

        // a packet injected is signalled, with the signal of its endpoint only
        let b_sched = SchedRun::default();
        b.set_sched_run(b_sched.clone());
        injector
            .inject(a.id(), build_test_ipv4_packet(1).unwrap())
            .unwrap();
        assert!(sched.is_set());
        assert!(!b_sched.is_set());
        assert_eq!(injected(&mut a).len(), 1);

        // one that could not be injected (the queue is full) is not
        injector
            .inject(a.id(), build_test_ipv4_packet(2).unwrap())
            .unwrap();
        assert!(sched.is_set());
        // watch a clear signal, as a pipeline would have cleared it when run
        let sched = SchedRun::default();
        a.set_sched_run(sched.clone());
        let mut packet = injector
            .inject(a.id(), build_test_ipv4_packet(3).unwrap())
            .unwrap_err()
            .into_packet();
        packet.done(DoneReason::InternalDrop);
        assert!(!sched.is_set());
        assert_eq!(injected(&mut a).len(), 1);
    }

    #[test]
    fn test_inject_into_a_full_endpoint() {
        let (endpoints, _punted, injector) = NfEndpointFactory::new(capacity(1), capacity(1));
        let mut a = endpoints.endpoint();

        injector
            .inject(a.id(), build_test_ipv4_packet(1).unwrap())
            .unwrap();
        let err = injector
            .inject(a.id(), build_test_ipv4_packet(2).unwrap())
            .unwrap_err();
        assert!(matches!(err, InjectError::FullQueue(_)));
        let mut packet = err.into_packet();
        assert_eq!(packet.try_ipv4().unwrap().ttl(), 2);
        packet.done(DoneReason::InternalDrop);

        // once the endpoint takes its packet, there is room again
        assert_eq!(ttls(&injected(&mut a)), [1]);
        injector.inject(a.id(), packet).unwrap();
    }

    #[test]
    fn test_inject_into_a_gone_endpoint() {
        let (endpoints, _punted, injector) = NfEndpointFactory::new(capacity(1), capacity(1));
        let a = endpoints.endpoint();
        let id = a.id();
        drop(a);

        let mut packet = build_test_ipv4_packet(1).unwrap();
        packet.done(DoneReason::InternalDrop);
        let err = injector.inject(id, packet).unwrap_err();
        assert!(matches!(err, InjectError::NoEndpoint(_)));
    }

    #[test]
    fn test_inject_into_an_endpoint_of_other_queues() {
        // an endpoint of other queues, with an id that these queues have no endpoint for
        let (_endpoints, _punted, injector) = NfEndpointFactory::new(capacity(1), capacity(1));
        let (others, _other_punted, _other_injector) =
            NfEndpointFactory::new(capacity(1), capacity(1));
        let other = others.endpoint();

        let mut packet = build_test_ipv4_packet(1).unwrap();
        packet.done(DoneReason::InternalDrop);
        let err = injector.inject(other.id(), packet).unwrap_err();
        assert!(matches!(err, InjectError::NoEndpoint(_)));
    }

    #[test]
    fn test_punt_into_a_full_queue() {
        let (endpoints, mut punted, _injector) = NfEndpointFactory::new(capacity(1), capacity(1));
        let a = endpoints.endpoint();
        a.punt(build_test_ipv4_packet(1).unwrap())
            .expect("Should fit in the queue");

        // the queue is full: the packet is returned
        let mut packet = a.punt(build_test_ipv4_packet(2).unwrap()).unwrap_err();
        assert_eq!(packet.try_ipv4().unwrap().ttl(), 2);
        packet.done(DoneReason::InternalDrop);

        // the packet punted is stamped with the id of the endpoint
        let mut first = punted.pop().expect("the first packet should be there");
        assert_eq!(first.origin(), a.id());
        first.done(DoneReason::Delivered);
    }

    #[test]
    fn test_punt_receiver_pop_ready_is_bounded() {
        let (endpoints, mut punted, _injector) = NfEndpointFactory::new(capacity(10), capacity(1));
        let a = endpoints.endpoint();
        let punt = |a: &NfEndpoint| {
            let packet = build_test_ipv4_packet(64).unwrap();
            a.punt(packet).expect("Should fit in the queue");
        };
        for _ in 0..3 {
            punt(&a);
        }

        // packets punted while draining are not popped by the same pop_ready()
        let mut popped = 0;
        for _ in punted.pop_ready() {
            popped += 1;
            punt(&a);
        }
        assert_eq!(popped, 3);
        assert_eq!(punted.pop_ready().count(), 3);
    }
}
