// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod test {
    use crate::{PuntReceiver, TestPktIo, queues};
    use net::buffer::TestBuffer;
    use net::buffer::TestBufferPool;
    use net::headers::Headers;
    use net::headers::TryIpv4;
    use net::packet::DoneReason;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::packet::{Packet, PacketMeta};

    use concurrency::sync::Arc;
    use concurrency::sync::atomic::{AtomicBool, Ordering};
    use pipeline::sample_nfs::DecrementTtl;
    use pipeline::{DynPipeline, NetworkFunction};
    use std::num::NonZeroUsize;
    use std::{thread, time::Duration};
    use tracing::info;
    use tracing_test::traced_test;

    fn capacity(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    // the trap function of the tests: it selects the packets marked as needing ARP/ND
    fn marked(_headers: &Headers, meta: &PacketMeta, _payload: &[u8]) -> bool {
        meta.need_arp_nd()
    }

    // a packet marked to be punted, as `marked` selects it
    fn marked_packet(ttl: u8) -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet(ttl).unwrap();
        packet.meta_mut().set_need_arp_nd(true);
        packet
    }

    #[test]
    #[traced_test]
    fn test_pkt_injection() {
        /* This tests checks the packet injection capability of pkt-io.
         * The setup is the following.
         *
         *          injecting thread
         *                │
         *                │
         *                ▼
         *               │ │┌─┐
         *      ┌────────┤ ││ ├───────────────────────────────┐
         *      │   ┌────┤ ││ ├──────┐    ┌───────────────┐   │
         *      │   │    │ ││ │      │    │               │   │
         *      │   │    └┬┘│ │      │    │               │   │
         *      │   │     │          │    │               │   │
         *  ────►   │     └───────►─►┼────►   decrement   ┼───┼───►
         *      │   │                │    │      TTL      │   │
         *      │   │                │    │               │   │
         *      │   │    pkt-io      │    │               │   │
         *      │   └────────────────┘    └───────────────┘   │
         *      └─────────────────────────────────────────────┘
         *                    2-stage pipeline
         */

        let (factory, _punted, injector) = queues("test", marked, capacity(1), capacity(1));
        let injector_nf: TestPktIo = factory.nf(TestBufferPool);
        let id = injector_nf.endpoint_id();
        let mut pipeline = DynPipeline::new()
            .add_stage(injector_nf)
            .add_stage(DecrementTtl);

        let ttl = 64;

        // queue a packet for injection from some thread
        let handle = thread::spawn(move || {
            let packet = build_test_ipv4_packet(ttl).unwrap();
            injector
                .inject(id, packet)
                .expect("Should fit in the queue");
        });

        // loop until we see the packet at the end of the pipeline.
        // Packet should have the ttl decremented by 1 due to the DecrementTtl stage.
        loop {
            let input = vec![].into_iter();
            let output: Vec<_> = pipeline.process(input).collect();
            if output.len() == 1 {
                let pkt = &output[0];
                assert_eq!(pkt.try_ipv4().unwrap().ttl(), ttl - 1);
                break;
            }
        }
        handle.join().unwrap();
    }

    #[test]
    #[traced_test]
    fn test_pkt_punting() {
        /* This tests checks the packet stealing capability (punting).
         * The setup is the following.
         *
         *           consuming thread
         *                   ▲
         *                   │
         *               │ │┌┼┐
         *      ┌────────┤ ││ ├───────────────────────────────┐
         *      │   ┌────┤ ││ ├──────┐    ┌───────────────┐   │
         *      │   │    │ ││ │      │    │               │   │
         *      │   │    └─┘│▲│      │    │               │   │
         *      │   │        │       │    │               │   │
         * ─────►   ├────────┴──────►┼────►   decrement   ┼───┼───►
         *      │   │                │    │      TTL      │   │
         *      │   │                │    │               │   │
         *      │   │    pkt-io      │    │               │   │
         *      │   └────────────────┘    └───────────────┘   │
         *      └─────────────────────────────────────────────┘
         *                   2-stage pipeline
         */

        let (factory, mut punted, _injector) = queues("test", marked, capacity(1), capacity(1));
        let pktio: TestPktIo = factory.nf(TestBufferPool);
        let mut pipeline = DynPipeline::new().add_stage(pktio).add_stage(DecrementTtl);

        // some thread loops until it steals a packet from the pipeline
        let handle = thread::spawn(move || {
            loop {
                if let Some(mut packet) = punted.pop() {
                    println!("Got punted packet:\n{}", *packet);
                    packet.done(DoneReason::Delivered);
                    break;
                }
            }
        });

        // feed the pipeline with a marked packet
        let input = vec![marked_packet(64)].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();
        assert!(output.is_empty(), "Packet should have been punted");

        handle.join().unwrap();
    }

    #[test]
    #[traced_test]
    fn test_pkt_punting_no_buffer() {
        // build pipeline with single PktIo stage, whose punt queue fits a single packet
        let (factory, mut punted, _injector) = queues("test", marked, capacity(1), capacity(1));
        let pktio: TestPktIo = factory.nf(TestBufferPool);
        let mut pipeline = DynPipeline::new().add_stage(pktio);

        // Build two marked packets. We use ttl to differentiate them
        let input = vec![marked_packet(128), marked_packet(64)].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();

        // checks: the 2nd packet should not be punted but dropped due to lack of room
        assert_eq!(output.len(), 1);
        let out = &output[0];
        assert_eq!(out.try_ipv4().unwrap().ttl(), 64);
        assert_eq!(out.get_done(), Some(DoneReason::InternalDrop));
        let mut first = punted
            .pop()
            .expect("the first packet should have been punted");
        assert_eq!(first.try_ipv4().unwrap().ttl(), 128);
        first.done(DoneReason::Delivered);
    }

    /// Process `burst` with `pipeline`, and then empty bursts until it outputs `expected`
    /// packets, which are returned.
    fn collect(
        pipeline: &mut DynPipeline<'static, TestBuffer>,
        burst: Vec<Packet<TestBuffer>>,
        expected: usize,
    ) -> Vec<Packet<TestBuffer>> {
        let mut output: Vec<_> = pipeline.process(burst).collect();
        while output.len() < expected {
            thread::sleep(Duration::from_millis(10));
            output.extend(pipeline.process(vec![]));
        }
        output
    }

    /// Return every packet punted to `punted` to the endpoint it came from, with `injector`,
    /// until `done` is set.
    fn spawn_returner(
        mut punted: PuntReceiver,
        injector: crate::Injector,
        done: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                for mut packet in punted.pop_ready() {
                    packet.meta_mut().set_need_arp_nd(false);
                    packet.done(DoneReason::Delivered);
                    let origin = packet.origin();
                    injector
                        .inject(origin, packet.into_packet())
                        .expect("Should fit in the queue");
                }
                thread::sleep(Duration::from_millis(1));
            }
        })
    }

    #[test]
    #[traced_test]
    fn test_pkt_returned_to_the_pipeline_that_punted_it() {
        /*
         * Two pipelines punt packets to the same consumer thread, which injects each of them back:
         * every packet must get back to the pipeline that punted it, and only to it.
         *
         *    pipeline A ──punt──┐                  ┌──inject──► pipeline A
         *                       ├──► consumer ─────┤
         *    pipeline B ──punt──┘                  └──inject──► pipeline B
         */
        let (factory, punted, injector) = queues("test", marked, capacity(10), capacity(10));
        let mut pipeline_a: DynPipeline<TestBuffer> =
            DynPipeline::new().add_stage(factory.nf(TestBufferPool));
        let mut pipeline_b: DynPipeline<TestBuffer> =
            DynPipeline::new().add_stage(factory.nf(TestBufferPool));

        let done = Arc::new(AtomicBool::new(false));
        let returner = spawn_returner(punted, injector, done.clone());

        // the TTL tells which pipeline a packet was punted from
        let back_a = collect(&mut pipeline_a, vec![marked_packet(1), marked_packet(1)], 2);
        let back_b = collect(&mut pipeline_b, vec![marked_packet(2)], 1);

        done.store(true, Ordering::Relaxed);
        returner.join().unwrap();

        let ttls = |packets: &[Packet<TestBuffer>]| -> Vec<u8> {
            packets
                .iter()
                .map(|p| p.try_ipv4().unwrap().ttl())
                .collect()
        };
        assert_eq!(ttls(&back_a), [1, 1]);
        assert_eq!(ttls(&back_b), [2]);
        assert!(
            back_a
                .iter()
                .chain(&back_b)
                .all(|p| p.get_done() == Some(DoneReason::Delivered))
        );
    }

    #[traced_test]
    #[test]
    fn test_custom_trap() {
        // custom trap function that traps ipv4 packets with TTL equal to 64
        fn ttl_is_64(headers: &Headers, _meta: &PacketMeta, _payload: &[u8]) -> bool {
            headers.try_ipv4().is_some_and(|ip| ip.ttl() == 64)
        }
        // build a pipeline with a `PktIo` that traps packets with the above trap
        let (factory, mut punted, _injector) = queues("test", ttl_is_64, capacity(10), capacity(1));
        let pktio: TestPktIo = factory.nf(TestBufferPool);
        let mut pipeline = DynPipeline::new().add_stage(pktio);

        // feed the pipeline with packets of distinct TTLs
        let p1 = build_test_ipv4_packet(60).unwrap();
        let p2 = build_test_ipv4_packet(64).unwrap();
        let p3 = build_test_ipv4_packet(128).unwrap();

        let input = vec![p1, p2, p3].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();
        assert_eq!(output.len(), 2, "Only 2 packets should remain in pipeline");
        assert!(output[0].try_ipv4().unwrap().ttl() != 64);
        assert!(output[1].try_ipv4().unwrap().ttl() != 64);
        let mut trapped = punted.pop().unwrap();
        assert_eq!(trapped.try_ipv4().unwrap().ttl(), 64);
        trapped.done(DoneReason::Delivered);
    }

    #[test]
    #[traced_test]
    fn test_async_popping() {
        let (factory, mut punted, _injector) = queues("test", marked, capacity(10), capacity(1));
        let pktio: TestPktIo = factory.nf(TestBufferPool);
        let mut pipeline = DynPipeline::new().add_stage(pktio).add_stage(DecrementTtl);

        // some thread loops until it steals a packet from the pipeline
        // thread uses tokio runtime and gets notified.
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("Tokio runtime creation failed");

            rt.block_on(async {
                // mix non-blocking and async pops, checking the count after each one so that we
                // never await a packet that will not arrive
                let mut seen = 0;
                info!("Waiting for packets...");
                while seen < 2 {
                    if let Some(mut packet) = punted.pop() {
                        seen += 1;
                        info!("Got packet {seen} (non-blocking pop):\n{}", *packet);
                        packet.done(DoneReason::Delivered);
                        continue;
                    }
                    if let Some(mut packet) = punted.pop_async().await {
                        seen += 1;
                        info!("Got packet {seen} (async pop):\n{}", *packet);
                        packet.done(DoneReason::Delivered);
                    }
                }
                info!("All packets seen. We're done");
            });
        });

        // feed the pipeline with two marked packets
        let input = vec![marked_packet(64), marked_packet(64)].into_iter();
        info!("Injecting packets....");
        let output: Vec<_> = pipeline.process(input).collect();
        assert!(output.is_empty(), "Packet should have been punted");
        handle.join().unwrap();
    }
}

#[cfg(test)]
mod test_nf {
    use crate::{TestPktIo, queues};
    use net::buffer::TestBuffer;
    use net::buffer::{BufferPool, TestBufferPool};
    use net::headers::Headers;
    use net::headers::TryIpv4;
    use net::packet::PacketMeta;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::packet::{DoneReason, Packet};
    use pipeline::{DynPipeline, NetworkFunction};
    use std::num::NonZeroUsize;

    // the trap function of the tests: it selects the packets marked as needing ARP/ND
    fn marked(_headers: &Headers, meta: &PacketMeta, _payload: &[u8]) -> bool {
        meta.need_arp_nd()
    }

    // packets are identified by their TTL, and marked to be punted or not
    fn packet(ttl: u8, punt: bool) -> Packet<TestBuffer> {
        let mut packet = build_test_ipv4_packet(ttl).unwrap();
        packet.meta_mut().set_need_arp_nd(punt);
        packet
    }

    // build a vector of TTLs for the given iterator of packets
    fn ttls<'a>(packets: impl IntoIterator<Item = &'a Packet<TestBuffer>>) -> Vec<u8> {
        packets
            .into_iter()
            .map(|p| p.try_ipv4().unwrap().ttl())
            .collect()
    }

    fn pktio(
        punt_capacity: usize,
        inject_capacity: usize,
    ) -> (TestPktIo, crate::PuntReceiver, crate::Injector) {
        let (factory, punted, injector) = queues(
            "test",
            marked,
            NonZeroUsize::new(punt_capacity).unwrap(),
            NonZeroUsize::new(inject_capacity).unwrap(),
        );
        (factory.nf(TestBufferPool), punted, injector)
    }

    #[test]
    fn test_process_burst_punts_and_keeps_order() {
        let (mut pktio, mut puntq, _) = pktio(10, 1);

        // burst of packets (TTLs) and marks (booleans)
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
        assert_eq!(ttls(punted.iter().map(|p| &**p)), [1, 3]);
        assert!(punted.iter().all(|p| p.origin() == pktio.endpoint_id()));
    }

    #[test]
    fn test_process_burst_full_puntq() {
        let (mut pktio, mut puntq, _) = pktio(1, 1);

        let mut burst = vec![packet(1, true), packet(2, false), packet(3, true)];
        pktio.process_burst(&mut burst);

        // the packet that did not fit in the punt queue stays in the burst, marked as dropped
        assert_eq!(ttls(&burst), [2, 3]);
        assert_eq!(burst[0].get_done(), None);
        assert_eq!(burst[1].get_done(), Some(DoneReason::InternalDrop));
        let punted: Vec<_> = puntq.pop_ready().collect();
        assert_eq!(ttls(punted.iter().map(|p| &**p)), [1]);
    }

    #[test]
    fn test_process_burst_injects_as_many_as_it_has_buffers_for() {
        // a pool that hands out at most one buffer at a time
        struct OneAtATime;
        impl BufferPool for OneAtATime {
            type Buf = TestBuffer;
            const MAX_ALLOC: usize = 1;
            fn alloc(&self, num: usize) -> impl Iterator<Item = TestBuffer> {
                TestBufferPool.alloc(num.min(1))
            }
        }
        let (factory, _punted, injector) = queues(
            "test",
            marked,
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(10).unwrap(),
        );
        let pktio = factory.nf(OneAtATime);
        let id = pktio.endpoint_id();
        let mut pipeline = DynPipeline::new().add_stage(pktio);
        assert!(!pipeline.must_run());
        for ttl in [10, 11, 12] {
            injector.inject(id, packet(ttl, false)).unwrap();
        }
        assert!(
            pipeline.must_run(),
            "the packets injected are work for the pipeline"
        );

        // one packet is injected per burst, in order: those without a buffer wait in the queue,
        // and remain pending work while there are packets left
        for (ttl, pending_after) in [(10, true), (11, true), (12, false)] {
            let mut burst = vec![];
            pipeline.process_burst(&mut burst);
            assert_eq!(ttls(&burst), [ttl]);
            assert_eq!(pipeline.must_run(), pending_after);
            for mut packet in burst {
                packet.done(DoneReason::Delivered);
            }
        }
        let mut burst = vec![];
        pipeline.process_burst(&mut burst);
        assert!(
            burst.is_empty(),
            "all of the packets should have been injected"
        );
    }

    #[test]
    fn test_process_burst_injects_after_punting() {
        let (mut pktio, mut puntq, injector) = pktio(10, 10);
        let id = pktio.endpoint_id();

        // injected packets are marked too, but must not be punted
        injector.inject(id, packet(10, true)).unwrap();
        injector.inject(id, packet(11, true)).unwrap();

        let mut burst = vec![packet(1, true), packet(2, false)];
        pktio.process_burst(&mut burst);

        assert_eq!(ttls(&burst), [2, 10, 11]);
        let punted: Vec<_> = puntq.pop_ready().collect();
        assert_eq!(ttls(punted.iter().map(|p| &**p)), [1]);
    }
}
