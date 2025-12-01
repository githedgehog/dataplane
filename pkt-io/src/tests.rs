// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod test {
    use crate::PktIo;
    use crate::PktQueue;
    use net::buffer::{PacketBufferMut, TestBuffer};
    use net::headers::TryIpv4;
    use net::packet::DoneReason;
    use net::packet::Packet;
    use net::packet::test_utils::build_test_ipv4_packet;

    use pipeline::sample_nfs::DecrementTtl;
    use pipeline::{DynPipeline, NetworkFunction};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::{thread, time::Duration};
    use tracing::info;
    use tracing_test::traced_test;

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

        let injector = PktIo::<TestBuffer>::new("test", 1, 0);
        let queue = injector.get_injectq().unwrap();
        let mut pipeline = DynPipeline::new()
            .add_stage(injector)
            .add_stage(DecrementTtl);

        let ttl = 64;

        // queue a packet for injection from some thread
        let handle = thread::spawn(move || {
            let packet = build_test_ipv4_packet(ttl).unwrap();
            queue.push(packet).expect("Should fit in the queue");
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

        let pktio = PktIo::<TestBuffer>::new("test", 0, 1);
        let queue = pktio.get_puntq().unwrap();
        let mut pipeline = DynPipeline::new().add_stage(pktio).add_stage(DecrementTtl);

        // some thread loops until it steals a packet from the pipeline
        let handle = thread::spawn(move || {
            loop {
                if let Some(packet) = queue.pop() {
                    println!("Got punted packet:\n{packet}");
                    break;
                }
            }
        });

        // feed the pipeline with a packet marked as local
        let mut packet = build_test_ipv4_packet(64).unwrap();
        packet.meta_mut().set_local(true);
        let input = vec![packet].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();
        assert!(output.is_empty(), "Packet should have been punted");

        handle.join().unwrap();
    }

    #[test]
    #[traced_test]
    fn test_pkt_punting_no_buffer() {
        // build pipeline with single PktIo stage
        let pktio = PktIo::<TestBuffer>::new("test", 0, 1);
        let puntq = pktio.get_puntq().unwrap();
        let mut pipeline = DynPipeline::new().add_stage(pktio);

        // some thread loops until it steals a packet from the pipeline.
        // the thread is very slow and only processes one packet every 3 seconds
        let handle = thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(3));
                if let Some(_packet) = puntq.pop() {
                    break;
                }
            }
        });

        // Build two packets marked as local. We use ttl to differentiate them
        let mut packet1 = build_test_ipv4_packet(128).unwrap();
        packet1.meta_mut().set_local(true);
        let mut packet2 = build_test_ipv4_packet(64).unwrap();
        packet2.meta_mut().set_local(true);

        // Inject into the pipeline
        let input = vec![packet1, packet2].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();

        // checks: the 2nd packet should not be punted but dropped due to lack of room
        assert_eq!(output.len(), 1,);
        let out = &output[0];
        assert_eq!(out.try_ipv4().unwrap().ttl(), 64,);
        assert_eq!(out.get_done(), Some(DoneReason::InternalDrop));

        handle.join().unwrap();
    }

    #[test]
    #[traced_test]
    fn test_pkt_transparency_no_puntq() {
        // build pipeline with single, queueless PktIo stage
        let pktio = PktIo::<TestBuffer>::new("test", 0, 0);
        assert!(pktio.get_puntq().is_none());
        assert!(pktio.get_injectq().is_none());
        let mut pipeline = DynPipeline::new().add_stage(pktio);

        // feed the pipeline with a packet marked as local
        let mut packet = build_test_ipv4_packet(64).unwrap();
        packet.meta_mut().set_local(true);
        let input = vec![packet].into_iter();

        // pipeline should output packet since it should not be punted.
        // packet should not be marked as dropped (transparency)
        let output: Vec<_> = pipeline.process(input).collect();
        assert_eq!(output.len(), 1);
        let out = &output[0];
        assert_eq!(out.get_done(), None);
    }

    struct HeavyProcessing;
    impl<Buf: PacketBufferMut> NetworkFunction<Buf> for HeavyProcessing {
        fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
            for _packet in burst {
                println!("Starting heavy packet processing...");
                thread::sleep(Duration::from_secs(3));
                println!("Heavy processing done");
            }
        }
    }

    #[test]
    #[traced_test]
    fn test_pkt_sidecar_pipeline() {
        /*
         *  Test a secondary, parallel pipeline, by letting pkt-io's in distinct pipelines share the
         *  same queues. This may be useful to pull costly operations out of the main pipeline, or to
         *  have more than one worker per "flow". This is just a proof of concept. A better way to
         *  implement this would probably require modifying the pipeline trait/types.
         *                                                                                          ┌────────────────────┐
         * ┌──────────────────────┐                                                                 │                    │
         * │                      │                                                                 │                    │
         * │                     │││┌─┐         secondary pipeline                              │ │┌┼┐                   │
         * │            ┌────────┤▼││ ├─────────────────────────────────────────────────────────┤ ││ ├────────────┐      │
         * │            │   ┌────┤ ││ ├──────┐    ┌───────────────┐  ┌───────────────┐     ┌────┤ ││ ├──────┐     │      │
         * │            │   │    │ ││ │      │    │               │  │               │     │    │ ││ │      │     │      │
         * │            │   │    └─┘│ │      │    │               │  │               │     │    └─┘│ │      │     │      │
         * │            │   │                │    │   heavy       │  │   decrement   │     │                │     │      │
         * │    ────────►   │                ┼────►   processing  ┼──►     TTL       ┼─────┼►               ┼─────┼─►    │
         * │            │   │                │    │               │  │               │     │                │     │      │
         * │            │   │    pkt-io      │    │               │  │               │     │    pkt-io      │     │      │
         * │            │   └────────────────┘    └───────────────┘  └───────────────┘     └────────────────┘     │      │
         * │            └─────────────────────────────────────────────────────────────────────────────────────────┘      │
         * │                                                                                                             │
         * │                                                                                                             │
         * └─────────────────────────┐                                                                                   │
         *                           │                                                                                   │
         *                        ┌──┼───────────────────────────────────────────────────────────────────────────────────┘
         *                        │  │
         *                        │  │
         *                       │▼│┌┼┐
         *              ┌────────┤ ││ ├───────────────────────────────┐
         *              │   ┌────┤ ││ ├──────┐    ┌───────────────┐   │
         *              │   │    │ ││ │      │    │               │   │
         *              │   │    └─┘│ │      │    │               │   │
         *              │   │                │    │               │   │
         *      ────────►   │              ─►┼────►   decrement   ┼───┼───►
         *              │   │                │    │      TTL      │   │
         *              │   │    pkt-io      │    │               │   │
         *              │   └────────────────┘    └───────────────┘   │
         *              └─────────────────────────────────────────────┘
         *                              primary pipeline
         */

        // to stop thread
        let done = Arc::new(AtomicBool::new(false));

        // create 3 queueless pktio
        let mut pktio1 = PktIo::<TestBuffer>::new("test1", 0, 0);
        let mut pktio2 = PktIo::<TestBuffer>::new("test2", 0, 0);
        let mut pktio3 = PktIo::<TestBuffer>::new("test3", 0, 0);

        // create two queues
        let queue1 = PktQueue::new(100);
        let queue2 = PktQueue::new(100);

        // do the inter-pipeline wiring
        pktio2.set_injectq(queue1.clone());
        pktio1.set_puntq(queue1);
        pktio1.set_injectq(queue2.clone());
        pktio3.set_puntq(queue2);

        // create primary pipeline: 1 stage only
        let mut primary = DynPipeline::new().add_stage(pktio1);

        // thread that processes secondary pipeline
        let finish_secondary = done.clone();
        let handle = thread::spawn(move || {
            let mut secondary = DynPipeline::new()
                .add_stage(pktio2)
                .add_stage(HeavyProcessing)
                .add_stage(DecrementTtl)
                .add_stage(pktio3);

            // loop invoking process() until told to finish
            while !finish_secondary.load(Ordering::Relaxed) {
                let empty = vec![].into_iter();
                let _: Vec<_> = secondary.process(empty).collect();
            }
        });

        // feed the pipeline with a single packet marked as local and ttl 128
        let ttl = 128;
        let mut packet = build_test_ipv4_packet(ttl).unwrap();
        packet.meta_mut().set_local(true);
        let input = vec![packet].into_iter();
        let mut output: Vec<_> = primary.process(input).collect();
        loop {
            if !output.is_empty() {
                println!("Got packet");
                assert_eq!(output.len(), 1);
                let pkt = &output[0];
                assert_eq!(pkt.try_ipv4().unwrap().ttl(), ttl - 1);
                break;
            }
            // keep on stimulating pipeline with zero packets
            let empty = vec![].into_iter();
            output = primary.process(empty).collect();
        }

        // stop auxiliary pipeline
        done.store(true, Ordering::Relaxed);

        handle.join().unwrap();
    }

    #[traced_test]
    #[test]
    fn test_custom_trap_function() {
        // custom trap function that traps ipv4 packets with TTL equal to 64
        fn my_trap_function(packet: &Packet<TestBuffer>) -> bool {
            if let Some(ip) = packet.try_ipv4() {
                ip.ttl() == 64
            } else {
                false
            }
        }
        // build a pipeline with a `PktIo` that traps packets with the above function
        let pktio = PktIo::<TestBuffer>::new("test", 0, 10).set_trap_function(my_trap_function);
        let puntq = pktio.get_puntq().unwrap();
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
        assert_eq!(puntq.pop().unwrap().try_ipv4().unwrap().ttl(), 64);
    }

    #[test]
    #[traced_test]
    fn test_async_popping() {
        let pktio = PktIo::<TestBuffer>::new("test", 0, 10);
        let puntq = pktio.get_puntq().unwrap();
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
                    if let Some(packet) = puntq.pop() {
                        seen += 1;
                        info!("Got packet {seen} (non-blocking pop):\n{packet}");
                        continue;
                    }
                    if let Some(packet) = puntq.pop_async().await {
                        seen += 1;
                        info!("Got packet {seen} (async pop):\n{packet}");
                    }
                }
                info!("All packets seen. We're done");
            });
        });

        // feed the pipeline with two packets marked as local
        let mut p1 = build_test_ipv4_packet(64).unwrap();
        p1.meta_mut().set_local(true);
        let p2 = p1.deep_copy().expect("Deep copy failed");

        let input = vec![p1, p2].into_iter();
        info!("Injecting packets....");
        let output: Vec<_> = pipeline.process(input).collect();
        assert!(output.is_empty(), "Packet should have been punted");
        handle.join().unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_async_pushing() {
        let pktio = PktIo::<TestBuffer>::new("test", 0, 10);
        let puntq = pktio.get_puntq().unwrap();
        let puntq2 = pktio.get_puntq().unwrap();

        // some thread loops until it steals a packet from the pipeline
        // thread uses tokio runtime and gets notified.
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("Tokio runtime creation failed");

            rt.block_on(async {
                let mut seen = 0;
                let mut loops = 0;
                info!("Waiting for packets...");
                loop {
                    if let Some(_packet) = puntq.pop() {
                        seen += 1;
                        info!("Got packet {seen}");
                    } else {
                        // got no packet. We were not blocked
                        loops += 1;
                    }
                    if seen == 2 {
                        info!("All packets seen. We're done");
                        assert!(loops > 0);
                        break;
                    }
                }
            });
        });

        // wait 3 seconds and feed the pipeline with two packets marked as local
        let mut p1 = build_test_ipv4_packet(64).unwrap();
        p1.meta_mut().set_local(true);
        let p2 = p1.deep_copy().expect("Deep copy failed");

        let input = vec![p1, p2].into_iter();

        // wait 2 secs for the other thread to try popping multiple times
        tokio::time::sleep(Duration::from_secs(2)).await;

        info!("Injecting packets....");
        for p in input {
            puntq2.push_async(p).await;
        }
        handle.join().unwrap();
    }
}
