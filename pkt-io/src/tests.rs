// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod test {
    use crate::nf::PktIo;
    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::{buffer::TestBuffer, packet::DoneReason};
    use pipeline::sample_nfs::DecrementTtl;
    use pipeline::{DynPipeline, NetworkFunction};
    use std::{thread, time::Duration};
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

        let injector = PktIo::<TestBuffer>::new(1, 0);
        let queue = injector.get_injectq().unwrap();
        let mut pipeline = DynPipeline::new()
            .add_stage(injector)
            .add_stage(DecrementTtl);

        let ttl = 64;

        // queue a packet for injection from some thread
        let handle = thread::spawn(move || {
            let packet = build_test_ipv4_packet(ttl).unwrap();
            queue
                .push(Box::new(packet))
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

        let pktio = PktIo::<TestBuffer>::new(0, 1);
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
        packet.get_meta_mut().set_local(true);
        let input = vec![packet].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();
        assert!(output.is_empty(), "Packet should have been punted");

        handle.join().unwrap();
    }

    #[test]
    #[traced_test]
    fn test_pkt_punting_no_buffer() {
        // build pipeline with single PktIo stage
        let pktio = PktIo::<TestBuffer>::new(0, 1);
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
        packet1.get_meta_mut().set_local(true);
        let mut packet2 = build_test_ipv4_packet(64).unwrap();
        packet2.get_meta_mut().set_local(true);

        // Inject into the pipeline
        let input = vec![packet1, packet2].into_iter();
        let output: Vec<_> = pipeline.process(input).collect();

        // checks
        assert_eq!(output.len(), 1, "Second packet should not have been punted");
        let out = &output[0];
        assert_eq!(
            out.try_ipv4().unwrap().ttl(),
            64,
            "The second pkt should not make it"
        );
        assert_eq!(out.get_done(), Some(DoneReason::InternalDrop));

        handle.join().unwrap();
    }

    #[test]
    #[traced_test]
    fn test_pkt_transparency_no_puntq() {
        // build pipeline with single, queueless PktIo stage
        let pktio = PktIo::<TestBuffer>::new(0, 0);
        assert!(pktio.get_puntq().is_none());
        assert!(pktio.get_injectq().is_none());
        let mut pipeline = DynPipeline::new().add_stage(pktio);

        // feed the pipeline with a packet marked as local
        let mut packet = build_test_ipv4_packet(64).unwrap();
        packet.get_meta_mut().set_local(true);
        let input = vec![packet].into_iter();

        // pipeline should output packet since it should not be punted
        let output: Vec<_> = pipeline.process(input).collect();
        assert_eq!(output.len(), 1);
    }
}
