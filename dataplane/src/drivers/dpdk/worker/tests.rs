// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::*;
use concurrency::thread;
use flow_entry::flow_table::FlowTable;
use net::buffer::TestBuffer;
use net::flows::{FlowInfo, FlowInfoFlags, FlowStatus};
use net::ip::NextHeader;
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
        &mut counters,
    );
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].meta().iif, Some(rx_if));
    assert_eq!(counters.rx, 2);
    assert_eq!(counters.parse_errors, 1);
    assert_eq!(counters.ppline_drops, 0);

    process_burst(
        [frame()].into_iter(),
        rx_if,
        &mut pipeline,
        &mut packets,
        &mut counters,
    );
    assert_eq!(packets.len(), 1);
    assert_eq!(counters.rx, 3);
    assert_eq!(counters.parse_errors, 1);
    assert_eq!(counters.ppline_drops, 0);
}

#[test]
fn drop_verdicts_and_removed_packets_are_counted_once() {
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
        (0..6).map(|_| frame()),
        InterfaceIndex::try_new(1).unwrap(),
        &mut pipeline,
        &mut packets,
        &mut counters,
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].get_done(), Some(DoneReason::Delivered));
    assert_eq!(packets[1].get_done(), Some(DoneReason::Local));
    assert_eq!(counters.rx, 6);
    assert_eq!(counters.ppline_drops, 4);
    assert_eq!(counters.parse_errors, 0);
    assert_eq!(counters.tx_drops, 0);
}

#[test]
fn control_plane_verdicts_remain_available_to_the_driver() {
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
        &mut counters,
    );
    assert_eq!(packets.len(), 3);
    assert_eq!(counters.ppline_drops, 0);
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
        &mut counters,
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(counters.rx, 1);
    assert_eq!(counters.ppline_drops, 0);
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

#[test]
fn flow_timers_progress_while_the_worker_polls() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap();
    let shutdown = lifecycle::Shutdown::new();
    let table = Arc::new(FlowTable::new(2));
    let (created_tx, created_rx) = std::sync::mpsc::channel();
    let (timer_tx, timer_rx) = std::sync::mpsc::channel();
    let setup: Arc<dyn Send + Sync + Fn() -> DynPipeline<'static, Mbuf<'static>>> = {
        let table = table.clone();
        Arc::new(move || {
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
                table.insert_pair_if_absent(&forward, &reverse).unwrap();
                (forward, reverse)
            });
            created_tx.send((thread::current().id(), pairs)).unwrap();
            let timer_tx = timer_tx.clone();
            tokio::spawn(async move {
                timer_tx.send(thread::current().id()).unwrap();
            });
            DynPipeline::new()
        })
    };

    thread::scope(|scope| {
        let _stop_on_failure = shutdown.workers.cancel_token().drop_guard();
        let worker = scope.spawn(|| {
            Worker::new(0, Vec::new()).run(&shutdown.workers, &setup, runtime.handle());
        });
        let (worker_id, [(forward, reverse), (cancelled, _)]) =
            created_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let timer_id = timer_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_ne!(worker_id, timer_id);
        cancelled.invalidate_pair();

        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                while table.live_len() != 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("expiration and cancellation must remove both flow pairs");
        });
        assert_eq!(forward.status(), FlowStatus::Expired);
        assert_eq!(reverse.status(), FlowStatus::Expired);
        assert!(!worker.is_finished());
        shutdown.workers.cancel_token().cancel();
        worker.join().unwrap();
    });
}
