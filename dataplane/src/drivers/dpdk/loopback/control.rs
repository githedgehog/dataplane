// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control-plane frames over the cable: punted to the kernel's side, and injected from it.

use std::time::Duration;

use concurrency::sync::Arc;
use flow_entry::flow_table::FlowTable;
use flowgen_report::Bound;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;
use net::packet::PacketStats;
use traffic_control::ControlPlane;

use super::harness::{
    FarEnd, Gateway, Loopback, PATIENCE, TestCase, WORKERS, check_counters, expect, frame_evidence,
    over_cable,
};
use crate::drivers::cpbridge::DetachedPort;

/// A broadcast ARP request from `sender`, padded to the Ethernet minimum.
fn arp_request(sender: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(60);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&[0x08, 0x06]); // ARP
    frame.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]); // Ethernet/IPv4 request
    frame.extend_from_slice(&sender);
    frame.extend_from_slice(&[192, 0, 2, 1]);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&[192, 0, 2, 2]);
    frame.resize(60, 0);
    frame
}

/// Check, through a running driver, that control frames cross the port both ways.
fn exchange_control_frames(
    far: &mut FarEnd<'_>,
    kernel: &mut DetachedPort,
    case: &mut TestCase<'_>,
) {
    // Until the control worker finds the ring port has no rules and falls back to software,
    // ARP goes through the (empty) pipeline and is dropped; keep asking.
    let request = arp_request([0x02, 0, 0, 0, 0, 1]);
    let deadline = clock::now() + PATIENCE;
    let punted = loop {
        far.send(0, &request);
        if let Ok(frame) = kernel.control.try_recv() {
            break Some(frame);
        }
        if clock::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    expect(
        case,
        "arp-punted",
        "an ARP request on a data queue reaches the kernel on the control channel, unchanged",
        punted.as_deref() == Some(request.as_slice()),
        || frame_evidence("punted", punted.as_deref()),
    );
    let stray = kernel.punted.try_recv().ok();
    expect(
        case,
        "arp-not-punted-as-data",
        "control traffic does not come up the data path's punt channel",
        stray.is_none(),
        || frame_evidence("punted as data", stray.as_deref()),
    );

    let reply = arp_request([0x02, 0, 0, 0, 0, 2]);
    kernel.inject.try_send(reply.clone()).unwrap();
    let sent = far.receive(usize::from(WORKERS));
    expect(
        case,
        "injected-on-control-queue",
        "a frame the kernel injects leaves on the control queue, unchanged",
        sent.as_deref() == Some(reply.as_slice()),
        || frame_evidence("sent", sent.as_deref()),
    );
}

/// A ring cable carries control traffic both ways through the full DPDK driver: an ARP request
/// sent into a data queue is taken off the data path in software (a ring port has no `rte_flow`
/// to steer it) and reaches the kernel's side of the bridge, and a frame the kernel injects
/// leaves on the control queue.
#[test]
fn control_frames_cross_a_ring_cable_both_ways() {
    over_cable(
        "control_frames_cross_a_ring_cable_both_ways",
        || {
            let gateway = Gateway {
                mac: Mac([0x02, 0, 0, 0, 0, 0x10]),
                index: InterfaceIndex::try_new(1000).unwrap(),
                pipeline: None,
                packets: Arc::new(PacketStats::new()),
                flows: Arc::new(FlowTable::default()),
                control_plane: ControlPlane::new([], []),
            };
            (gateway, ())
        },
        |lb: &mut Loopback<'_, '_, '_, '_>| {
            let name = "control_frames_cross_a_ring_cable_both_ways";
            let mut case = lb
                .report
                .case(name, serde_json::json!({}))
                .expect("the report should take the case");
            exchange_control_frames(lb.far, lb.kernel, &mut case);
            check_counters(
                &mut case,
                lb.probe,
                &[
                    ("arp-received", "port.loop0.rx_packets", Bound::at_least(1)),
                    ("one-frame-sent", "port.loop0.tx_packets", Bound::exactly(1)),
                    ("none-missed", "port.loop0.rx_missed", Bound::exactly(0)),
                ],
            );
            case.finish()
                .expect("the report should take the case's end");
        },
    );
}
