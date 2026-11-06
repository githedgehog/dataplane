// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A network function able to punt packets and inject them

use crate::queue::{EndpointId, Injector, NfEndpoint, NfEndpointFactory, PuntReceiver};
use net::buffer::{BufferPool, TestBufferPool};
use net::headers::{Headers, TryHeaders};
use net::packet::{DoneReason, Packet, PacketMeta, Rebuffer};
use pipeline::{NetworkFunction, SchedRun};
use std::num::NonZeroUsize;

#[allow(unused)]
use tracing::{debug, trace};

/// A type of network function that has two basic capabilities:
///    1) pulling packets out of a pipeline ("punt" or "trap" them), for extra processing
///       elsewhere, possibly by another thread.
///    2) injecting packets into the pipeline(s)
///
/// Note:
///    * The packets to punt are determined by a configurable [`TrapFunction`]
///    * Since multiple pipelines exist and each requires an instance of this type, a
///      [`PktIoFactory`] is created in advance to allow each worker to create a [`PktIo`].
///    * Each [`PktIo`] will have a sender to punt (over a shared queue towards a single consumer)
///      and its own receiver to receive injected packets. The two, plus an identifier
///      are contained in a `queue::NfEndpoint`.
///    * The queues:
///         * have fixed capacities (bounded)
///         * hold `Packet<TestBuffer>`s: packets are rebuffered with [`Rebuffer`] when punted
///           and when injected, so that the buffers of the pipeline, which may be local to
///           it, never leave it. When receiving packets to be injected, each [`PktIo`]
///           will rebuffer them into buffers that it gets from its [`BufferPool`] `P` (see
///           [`PktIoFactory::nf`]). The buffers of the pool, `P::Buf`, are the type of buffers
///           of the pipeline that the [`PktIo`] is a stage of.
///         * For injected packets to be received, the stage gets a clone of [`SchedRun`] from the
///           pipeline where it can signal that has pending packets to inject, for the pipeline
///           owner to know that it may need to run a pipeline without packets if none arrives.
///
/// ```text
///                             N:1           +--------------+ +-----------+
///                         +---------------->+ PuntReceiver | | Injector  |
///                         |       +-------->+              | |           |
///                         ^       |      +->|              | +-+--+---+--+
///                         |       |      |  +--------------+   |  |   |
///                         |       |      |                     v  v   v
///                         |       |      |         1:1         |  |   |
///                         | +-----+---<--+----<----------------+  |   |
///                     +-+ | |     |      |                        |   |
///                     |P| | |     ^      |                        |   |
///          +----------+-+-+-v-+   |      |                        |   |
/// pipeline |          | pktio |   |      |                        v   |
///          +----------+-------+   |      |                        |   |
///                                 |      |                        |   |
///                     +-+ +-------+      |                        |   |
///                     |P| |+----<--------+--<---------<-----------+   v
///          +----------+-+-+v--+          |                            |
/// pipeline |          | pktio |          |                            |
///          +----------+-------+          |                            |
///                                        |                            |
///                     +-+ +--------------+                            |
///                     |P| |+--------------<-----<-----<--------<------+
///          +----------+-+-+v--+
/// pipeline |          | pktio |
///          +----------+-------+
///
///     * each pktio has an Endpoint and a pool of buffers P
///     * when punting, the Endpoint ID travels with packet to the receiver
///     * pktio rebuffers packets in both directions to/from the PuntReceiver/Injector, which
///       only deal with packets buffered with TestBuffers
///          - when punting, packets get rebuffered with TestBuffers
///          - injected packets get rebuffered to the pipeline buffer type, from pool P.
/// ```
pub struct PktIo<P> {
    name: String,
    endpoint: NfEndpoint,
    pool: P,
    trap_function: TrapFunction,
    sched: SchedRun,
}

/// A function to select packets to be punted (trapped). This should be in reality
/// `fn(&Packet<Buf>) -> bool`. However, the pipeline factory is created before the type of
/// buffer is known and that would make [`PktIoFactory`] depend on `Buf`. We overcome this
/// by defining a trap function independent of the buffer type, which receives the headers,
/// metadata and payload (past the parsed headers) as 3 arguments.
pub type TrapFunction = fn(&Headers, &PacketMeta, &[u8]) -> bool;

/// A [`PktIo`] for pipelines of `TestBuffer`s, with the pool for them
pub type TestPktIo = PktIo<TestBufferPool>;

/// A [`TrapFunction`] that selects no packet
#[must_use]
pub fn no_trap(_headers: &Headers, _meta: &PacketMeta, _payload: &[u8]) -> bool {
    false
}

/// Create the queues to punt packets from, and inject packets into, a number of [`PktIo`]s named
/// `name`, which punt the packets selected by `trap`. The punt queue holds up to `punt_capacity`
/// packets, and the injection queue of each [`PktIo`] up to `inject_capacity` packets.
///
/// Returns: the [`PktIoFactory`] to create the [`PktIo`]s, and the [`PuntReceiver`] and the
/// [`Injector`] to be used by the consumer of the packets punted.
#[must_use]
pub fn queues(
    name: &str,
    trap: TrapFunction,
    punt_capacity: NonZeroUsize,
    inject_capacity: NonZeroUsize,
) -> (PktIoFactory, PuntReceiver, Injector) {
    let (ep_factory, punt_rx, injector) = NfEndpointFactory::new(punt_capacity, inject_capacity);
    let factory = PktIoFactory {
        name: name.to_string(),
        trap,
        ep_factory,
    };
    (factory, punt_rx, injector)
}

/// A type to allow creating multiple [`PktIo`] instances; e.g. for pipeline replicas.
/// All instances share the same name and trap function.
/// Each instance owns its own pool of buffers and endpoint.
/// Endpoints have a dedicated receiver and sender. The sender allows queueing on a shared
/// queue towards the entity that receives punted packets. The receiver allows an external
/// entity to inject packets to a specific endpoint and [`PktIo`] instance.
#[derive(Clone)]
pub struct PktIoFactory {
    name: String,
    trap: TrapFunction,
    ep_factory: NfEndpointFactory,
}

impl PktIoFactory {
    /// Create a [`PktIo`] from a factory. This is called once the type of buffer is known.
    /// The [`PktIo`] gets the buffers to rebuffer the packets injected into it from `pool`
    /// (e.g. the pool of the worker). For pipelines of `TestBuffer`s, `pool` is a
    /// [`TestBufferPool`].
    #[must_use]
    pub fn nf<P: BufferPool>(&self, pool: P) -> PktIo<P> {
        // create a new endpoint (and register it)
        let endpoint = self.ep_factory.endpoint();

        // create the NF with that endpoint
        PktIo::new(&self.name, endpoint, pool, self.trap)
    }
}

impl<P> PktIo<P> {
    fn new(name: &str, endpoint: NfEndpoint, pool: P, trap: TrapFunction) -> Self {
        Self {
            name: name.to_string(),
            endpoint,
            pool,
            trap_function: trap,
            sched: SchedRun::default(),
        }
    }

    /// The id of the endpoint of this [`PktIo`]. The id is stamped on punted packets and
    /// used to inject packets into it.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }
}

impl<P> NetworkFunction<P::Buf> for PktIo<P>
where
    P: BufferPool,
    P::Buf: Rebuffer,
{
    fn process_burst(&mut self, burst: &mut Vec<Packet<P::Buf>>) {
        // Punting packets:
        //  * select packets by the trap function and punt them
        //  * packets to be punted which cannot be punted are marked as dropped and remain in the burst.
        //  * queue space is reserved before rebuffering a packet, so that a packet that does not fit keeps its original buffer.
        let trap = self.trap_function;
        let mut failed = vec![];
        for packet in burst.extract_if(.., |p| trap(p.headers(), p.meta(), p.payload().as_ref())) {
            if let Err(mut packet) = self.endpoint.punt(packet) {
                trace!("{}: Unable to punt packet\n{packet}", self.name);
                packet.done(DoneReason::InternalDrop);
                failed.push(packet);
            }
        }
        burst.append(&mut failed);

        // inject packets awaiting injection:
        //   * we attempt to allocate as many buffers as packets to inject, but up to `P::MAX_ALLOC`
        //   * only remove from the injection queue those for which we'll have buffers. So, we back-pressure
        //     depending on the buffer availability
        //   * rebuffering may still fail if packet does not fit in buffer
        let awaiting = self.endpoint.pending_injected();
        if awaiting == 0 {
            return;
        }

        // allocate as many buffers as packets are awaiting but up to `P::MAX_ALLOC`.
        // For each buffer, take a packet to inject and rebuffer it.
        let num = awaiting.min(P::MAX_ALLOC);
        let bufs = self.pool.alloc(num);
        for (buf, packet) in bufs.zip(self.endpoint.inject_fetch(num)) {
            match P::Buf::from_test_buffer(packet, buf) {
                Ok(packet) => burst.push(packet),
                Err(mut packet) => {
                    debug!("{}: Unable to rebuffer packet to inject", self.name);
                    packet.done(DoneReason::NoBuffRoom);
                    burst.push(packet);
                }
            }
        }

        // if there are packets to be injected, request a run as soon as possible
        if self.endpoint.pending_injected() > 0 {
            self.sched.asap();
        }
    }

    fn set_sched_run(&mut self, sched: SchedRun) {
        self.endpoint.set_sched_run(sched.clone());
        self.sched = sched;
    }
}
