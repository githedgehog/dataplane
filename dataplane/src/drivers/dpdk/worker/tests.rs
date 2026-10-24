// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
use concurrency::sync::Arc;
use concurrency::thread;
use flow_entry::flow_table::{FlowTable, WorkerFlowTable};
use net::buffer::TestBuffer;
use net::flows::{FlowInfo, FlowInfoFlags, FlowStatus};
use net::ip::NextHeader;
use net::packet::DoneReason;
use net::packet::test_utils::build_test_ipv4_packet_with_transport;
use net::{FlowKey, IpProtoKey, TcpProtoKey};
use std::time::Duration;

fn frame() -> TestBuffer {
    build_test_ipv4_packet_with_transport(64, Some(NextHeader::UDP))
        .unwrap()
        .serialize()
        .unwrap()
}

struct ReturnVerdicts(&'static [Option<DoneReason>]);

impl NetworkFunction<TestBuffer> for ReturnVerdicts {
    fn process_burst(&mut self, burst: &mut Vec<Packet<TestBuffer>>) {
        burst.resize_with(self.0.len(), || Packet::new(frame()).unwrap());
        for (packet, verdict) in burst.iter_mut().zip(self.0) {
            if let Some(reason) = verdict {
                packet.done(*reason);
            }
        }
    }
}

/// How many of `packets` the caller will drop.
fn drops(packets: &[Packet<TestBuffer>]) -> usize {
    packets
        .iter()
        .filter(|packet| Disposition::of(packet) == Disposition::Drop)
        .count()
}

#[test]
fn parse_failures_are_not_pipeline_drops() {
    let rx_if = InterfaceIndex::try_new(1).unwrap();
    let mut counters = RxCounters::default();
    let mut pipeline = DynPipeline::new().add_stage(ReturnVerdicts(&[Some(DoneReason::Delivered)]));
    let mut packets = Vec::new();
    process_burst(
        vec![frame(), TestBuffer::from_raw_data(&[0; 3])].into_iter(),
        rx_if,
        &mut pipeline,
        &mut packets,
        None,
        &mut Vec::new(),
        &mut counters,
    );
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].meta().iif, Some(rx_if));
    assert_eq!(counters.rx, 2);
    assert_eq!(counters.parse_errors, 1);
    assert_eq!(drops(&packets), 0);

    process_burst(
        [frame()].into_iter(),
        rx_if,
        &mut pipeline,
        &mut packets,
        None,
        &mut Vec::new(),
        &mut counters,
    );
    assert_eq!(packets.len(), 1);
    assert_eq!(counters.rx, 3);
    assert_eq!(counters.parse_errors, 1);
    assert_eq!(drops(&packets), 0);
}

/// Every packet comes back for the caller to count and free, drops included; `process_burst` counts
/// none of them itself.
#[test]
fn drop_verdicts_come_back_to_the_caller() {
    let mut pipeline = DynPipeline::new().add_stage(ReturnVerdicts(&[
        Some(DoneReason::Delivered),
        Some(DoneReason::Local),
        Some(DoneReason::AclDropped),
        Some(DoneReason::Unroutable),
        None,
    ]));
    let mut counters = RxCounters::default();
    let mut packets = Vec::new();
    process_burst(
        (0..5).map(|_| frame()),
        InterfaceIndex::try_new(1).unwrap(),
        &mut pipeline,
        &mut packets,
        None,
        &mut Vec::new(),
        &mut counters,
    );
    assert_eq!(packets.len(), 5);
    assert_eq!(packets[0].get_done(), Some(DoneReason::Delivered));
    assert_eq!(packets[1].get_done(), Some(DoneReason::Local));
    assert_eq!(drops(&packets), 3);
    assert_eq!(counters.rx, 5);
    assert_eq!(counters.ppline_drops, 0);
    assert_eq!(counters.parse_errors, 0);
    assert_eq!(counters.tx_drops, 0);
}

/// Stages mark packets dropped; one that removes them instead would hide the drop.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "removed 1 packet(s)")]
fn a_pipeline_that_removes_packets_is_a_bug() {
    let mut pipeline = DynPipeline::new().add_stage(ReturnVerdicts(&[Some(DoneReason::Delivered)]));
    let mut counters = RxCounters::default();
    let mut packets = Vec::new();
    process_burst(
        (0..2).map(|_| frame()),
        InterfaceIndex::try_new(1).unwrap(),
        &mut pipeline,
        &mut packets,
        None,
        &mut Vec::new(),
        &mut counters,
    );
}

/// Only `Local` reaches the control plane: the verdicts that used to be punted when the frame was
/// addressed to us are now drops, since the ingress stage marks `Local` whatever the control plane
/// should see.
#[test]
fn verdicts_other_than_local_and_delivered_are_dropped() {
    let mut pipeline = DynPipeline::new().add_stage(ReturnVerdicts(&[
        Some(DoneReason::Unhandled),
        Some(DoneReason::NotIp),
        Some(DoneReason::RouteFailure),
    ]));
    let mut counters = RxCounters::default();
    let mut packets = Vec::new();
    process_burst(
        (0..3).map(|_| frame()),
        InterfaceIndex::try_new(1).unwrap(),
        &mut pipeline,
        &mut packets,
        None,
        &mut Vec::new(),
        &mut counters,
    );
    assert_eq!(drops(&packets), 3);
}

#[test]
fn additional_pipeline_outputs_do_not_count_as_drops() {
    let mut pipeline =
        DynPipeline::new().add_stage(ReturnVerdicts(&[Some(DoneReason::Delivered); 2]));
    let mut counters = RxCounters::default();
    let mut packets = Vec::new();
    process_burst(
        [frame()].into_iter(),
        InterfaceIndex::try_new(1).unwrap(),
        &mut pipeline,
        &mut packets,
        None,
        &mut Vec::new(),
        &mut counters,
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(counters.rx, 1);
    assert_eq!(drops(&packets), 0);
    assert_eq!(counters.parse_errors, 0);
}

fn key(port: u16) -> FlowKey {
    FlowKey::new(
        None,
        net::flows::flow_key::FlowAddrs::V4 {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
        },
        IpProtoKey::Tcp(TcpProtoKey {
            src_port: port.try_into().unwrap(),
            dst_port: 80.try_into().unwrap(),
        }),
    )
}

/// The worker expires the flows its pipeline created, on its own thread, while it polls: one pair
/// by deadline, one by invalidation from another thread.
#[test]
fn flows_expire_on_the_worker_while_it_polls() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap();
    let shutdown = lifecycle::Shutdown::new();
    let table = Arc::new(FlowTable::new(2));
    let (created_tx, created_rx) = std::sync::mpsc::channel();
    let setup: PipelineFactory<'static, Mbuf<'static>> = {
        let table = table.clone();
        Arc::new(move || {
            let flows = WorkerFlowTable::new(table.clone());
            let pairs = [
                (1001, Duration::from_millis(100)),
                (1003, Duration::from_secs(60)),
            ]
            .map(|(port, timeout)| {
                let (forward, reverse) = FlowInfo::related_pair(
                    clock::now() + timeout,
                    key(port),
                    FlowInfoFlags::INITIATOR,
                    key(port + 1),
                    FlowInfoFlags::default(),
                )
                .unwrap();
                flows.insert_pair_if_absent(&forward, &reverse).unwrap();
                (forward, reverse)
            });
            created_tx.send(pairs).unwrap();
            WorkerPipeline {
                pipeline: DynPipeline::new(),
                flows,
            }
        })
    };

    thread::scope(|scope| {
        let _stop_on_failure = shutdown.workers.cancel_token().drop_guard();
        let worker = scope.spawn(|| {
            Worker::new(0, Vec::new()).run(&shutdown.workers, &setup, runtime.handle());
        });
        let [(forward, reverse), (cancelled, _)] =
            created_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cancelled.invalidate_pair();

        let deadline = clock::now() + Duration::from_secs(5);
        while table.live_len() != 0 {
            assert!(
                clock::now() < deadline,
                "expiration and cancellation must remove both flow pairs"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(forward.status(), FlowStatus::Expired);
        assert_eq!(reverse.status(), FlowStatus::Expired);
        assert!(!worker.is_finished());
        shutdown.workers.cancel_token().cancel();
        worker.join().unwrap();
    });
}

/// Counts what the pipeline is given.
struct Count(usize);

impl NetworkFunction<TestBuffer> for Count {
    fn process_burst(&mut self, burst: &mut Vec<Packet<TestBuffer>>) {
        self.0 += burst.len();
    }
}

/// An ARP request, broadcast.
fn arp() -> TestBuffer {
    let mut frame = vec![0xff; 6];
    frame.extend([0x02, 0, 0, 0, 0, 1, 0x08, 0x06]);
    frame.extend([0, 1, 8, 0, 6, 4, 0, 1]);
    frame.extend([0x02, 0, 0, 0, 0, 1, 10, 0, 0, 2]);
    frame.extend([0, 0, 0, 0, 0, 0, 10, 0, 0, 1]);
    frame.resize(60, 0);
    TestBuffer::from_raw_data(&frame)
}

#[test]
fn control_traffic_the_nic_does_not_steer_skips_the_pipeline() {
    use crate::drivers::dpdk::classes::{Fallback, fall_back};
    use std::collections::BTreeSet;
    use traffic_control::{Class, ClassTable, ControlPlane};

    let table = Arc::new(ClassTable::new(ControlPlane::default()));

    for (classes, diverted_expected) in [
        (BTreeSet::from([Class::Arp]), 1),
        // Steered by the NIC, so left alone here.
        (BTreeSet::from([Class::Bgp]), 0),
        (BTreeSet::new(), 0),
    ] {
        let fallback = Fallback::default();
        fall_back(&fallback, &table, classes);
        let early = fallback.load();
        let mut pipeline = Count(0);
        let mut packets = Vec::new();
        let mut diverted = Vec::new();
        let mut counters = RxCounters::default();
        process_burst(
            [arp(), frame()].into_iter(),
            InterfaceIndex::try_new(1).unwrap(),
            &mut pipeline,
            &mut packets,
            early.as_deref(),
            &mut diverted,
            &mut counters,
        );
        assert_eq!(counters.parse_errors, 0);
        assert_eq!(diverted.len(), diverted_expected);
        // The other frame is not control traffic and always reaches the pipeline.
        assert_eq!(pipeline.0, 2 - diverted_expected);
        assert_eq!(counters.rx, 2);
    }
}
