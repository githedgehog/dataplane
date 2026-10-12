// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The transmitter, driven in paused virtual time so that every frame's send time is exact.

use crate::{Advertisement, FrameSink, Inputs, Link, Refused, Timing, transmit};
use clock::virtual_time::Paused;
use net::eth::mac::{Mac, SourceMac};
use net::headers::Headers;
use net::lldp::{ChassisId, IdOctets, Lldpdu, NEAREST_BRIDGE, OptionalTlv, PortId, Text};
use net::parse::Parse;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// Records each frame with when it was sent, counted from `start`.
struct Recorder {
    start: Instant,
    frames: mpsc::UnboundedSender<(Duration, Vec<u8>)>,
}

impl FrameSink for Recorder {
    fn send(&mut self, frame: Vec<u8>) -> Result<(), Refused> {
        let at = clock::now().duration_since(self.start);
        self.frames.send((at, frame)).map_err(|_| Refused::Closed)
    }
}

struct Harness {
    link: watch::Sender<Link>,
    new_neighbor: watch::Sender<()>,
    advertisement: watch::Sender<Option<Advertisement>>,
    frames: mpsc::UnboundedReceiver<(Duration, Vec<u8>)>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Start a transmitter; must run inside the paused runtime.
    fn start(link: Link, advertisement: Option<Advertisement>) -> Harness {
        let (link_tx, link_rx) = watch::channel(link);
        let (advert_tx, advert_rx) = watch::channel(advertisement);
        let (frames_tx, frames) = mpsc::unbounded_channel();
        let (new_neighbor, new_neighbor_rx) = watch::channel(());
        let cancel = CancellationToken::new();
        let inputs = Inputs {
            link: link_rx,
            advertisement: advert_rx,
            new_neighbor: new_neighbor_rx,
            sink: Recorder {
                start: clock::now(),
                frames: frames_tx,
            },
            timing: Timing::default(),
        };
        let task = tokio::spawn(transmit(inputs, cancel.clone()));
        Harness {
            link: link_tx,
            new_neighbor,
            advertisement: advert_tx,
            frames,
            cancel,
            task,
        }
    }

    /// Every frame sent so far: when, and the LLDPDU it carried.
    fn sent(&mut self) -> Vec<(Duration, Lldpdu)> {
        let mut sent = Vec::new();
        while let Ok((at, frame)) = self.frames.try_recv() {
            sent.push((at, decode(&frame)));
        }
        sent
    }
}

/// Check `frame` is a well-formed LLDP frame and return its LLDPDU.
fn decode(frame: &[u8]) -> Lldpdu {
    assert!(frame.len() >= 60, "a frame shorter than Ethernet allows");
    assert_eq!(
        frame[..6],
        NEAREST_BRIDGE.0,
        "not sent to the nearest bridge"
    );
    assert_eq!(frame[12..14], [0x88, 0xcc], "not an LLDP ethertype");
    let (mut headers, _) = Headers::parse(frame).unwrap();
    *headers.take_lldp().expect("the frame parses as LLDP")
}

fn advertisement(chassis: &str, system: &str) -> Advertisement {
    Advertisement::new(
        SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
        ChassisId::LocallyAssigned(IdOctets::new(chassis.as_bytes()).unwrap()),
        PortId::InterfaceName(IdOctets::new(b"eth1").unwrap()),
        [OptionalTlv::SystemName(
            Text::new(system.as_bytes()).unwrap(),
        )],
    )
    .unwrap()
}

/// When each frame went out, in whole seconds.
///
/// Every timer the transmitter sets is whole seconds from something a test did on a whole second, so a
/// frame between seconds is a scheduling bug.
fn times(sent: &[(Duration, Lldpdu)]) -> Vec<u64> {
    sent.iter()
        .map(|(at, _)| {
            assert_eq!(
                at.subsec_nanos(),
                0,
                "a frame went out between seconds: {at:?}"
            );
            at.as_secs()
        })
        .collect()
}

fn ttls(sent: &[(Duration, Lldpdu)]) -> Vec<u16> {
    sent.iter().map(|(_, pdu)| pdu.ttl().as_secs()).collect()
}

/// Let `seconds` of virtual time pass.
///
/// A sleep rather than `virtual_time::advance`: a paused runtime moves a sleeping clock from timer to
/// timer, so the transmitter runs at each instant it asked for, where `advance` would jump past them
/// all and fire them late.
async fn wait(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

#[test]
fn an_up_link_advertises_fast_then_every_interval() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(100).await;
        let sent = port.sent();
        // txFastInit (4) a second apart, then every msgTxInterval (30 s).
        assert_eq!(times(&sent), [0, 1, 2, 3, 33, 63, 93]);
        assert!(ttls(&sent).iter().all(|&ttl| ttl == 121));
        let chassis = ChassisId::LocallyAssigned(IdOctets::new(b"gw-1").unwrap());
        assert!(sent.iter().all(|(_, pdu)| *pdu.chassis_id() == chassis));
    });
}

#[test]
fn nothing_is_sent_without_a_link_or_an_advertisement() {
    Paused::new().block_on(async {
        let mut down = Harness::start(Link::Down, Some(advertisement("gw-1", "gw-1")));
        let mut empty = Harness::start(Link::Up, None);
        wait(100).await;
        assert_eq!(down.sent(), []);
        assert_eq!(empty.sent(), []);

        // Either arriving starts the fast start, counted from that moment.
        down.link.send(Link::Up).unwrap();
        empty
            .advertisement
            .send(Some(advertisement("gw-1", "gw-1")))
            .unwrap();
        wait(5).await;
        assert_eq!(times(&down.sent()), [100, 101, 102, 103]);
        assert_eq!(times(&empty.sent()), [100, 101, 102, 103]);
    });
}

#[test]
fn a_link_that_bounces_starts_over() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(40).await;
        port.link.send(Link::Down).unwrap();
        wait(60).await;
        port.link.send(Link::Up).unwrap();
        wait(5).await;
        // Nothing while down, not even a shutdown frame: a down link carries nothing.
        assert_eq!(times(&port.sent()), [0, 1, 2, 3, 33, 100, 101, 102, 103]);
    });
}

#[test]
fn stopping_tells_neighbours_to_forget_us() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(10).await;
        port.cancel.cancel();
        (&mut port.task).await.unwrap();
        let sent = port.sent();
        let (at, shutdown) = sent.last().unwrap();
        assert_eq!(*at, Duration::from_secs(10));
        assert_eq!(shutdown.ttl().as_secs(), 0);
        assert!(
            shutdown.optional().is_empty(),
            "a shutdown frame carries only the mandatory TLVs"
        );
    });
}

#[test]
fn news_goes_out_at_once_but_no_faster_than_credit_allows() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(10).await;
        port.sent();
        // Ten changes in the same instant: credit (txCreditMax 5) lets five out at once, and the latest
        // change goes out when the next credit comes back a second later.
        for n in 0..10 {
            port.advertisement
                .send(Some(advertisement("gw-1", &format!("gw-1 rev {n}"))))
                .unwrap();
            tokio::task::yield_now().await;
        }
        wait(5).await;
        let sent = port.sent();
        assert_eq!(times(&sent), [10, 10, 10, 10, 10, 11]);
        let last = &sent.last().unwrap().1;
        assert_eq!(
            last.optional(),
            [OptionalTlv::SystemName(Text::new(b"gw-1 rev 9").unwrap())]
        );
    });
}

#[test]
fn a_new_identity_retracts_the_old_one_first() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(10).await;
        port.sent();
        port.advertisement
            .send(Some(advertisement("gw-2", "gw-2")))
            .unwrap();
        wait(10).await;
        let sent = port.sent();
        let old = ChassisId::LocallyAssigned(IdOctets::new(b"gw-1").unwrap());
        let new = ChassisId::LocallyAssigned(IdOctets::new(b"gw-2").unwrap());
        // A shutdown under the old chassis, quiet for reinitDelay (2 s), then a fresh fast start.
        assert_eq!(times(&sent), [10, 12, 13, 14, 15]);
        assert_eq!(*sent[0].1.chassis_id(), old);
        assert_eq!(sent[0].1.ttl().as_secs(), 0);
        assert!(sent[1..].iter().all(|(_, pdu)| *pdu.chassis_id() == new));
    });
}

#[test]
fn withdrawing_the_advertisement_retracts_it() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(10).await;
        port.sent();
        port.advertisement.send(None).unwrap();
        wait(100).await;
        let sent = port.sent();
        assert_eq!(times(&sent), [10]);
        assert_eq!(sent[0].1.ttl().as_secs(), 0);
    });
}

#[test]
fn a_port_that_goes_away_ends_the_transmitter() {
    Paused::new().block_on(async {
        let port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        drop(port.frames);
        wait(10).await;
        assert!(port.task.is_finished());
    });
}

#[test]
fn a_new_neighbour_restarts_the_fast_start() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        wait(40).await;
        port.sent();
        port.new_neighbor.send_replace(());
        wait(40).await;
        // Told at once, then fast again (txFastInit 4 in all), then back to the routine interval.
        assert_eq!(times(&port.sent()), [40, 41, 42, 43, 73]);
    });
}

#[test]
fn a_new_neighbour_while_fast_does_not_lengthen_the_fast_start() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Up, Some(advertisement("gw-1", "gw-1")));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        port.new_neighbor.send_replace(());
        wait(40).await;
        // The newcomer is told at 1.5 s, which counts as one of the four fast sends, and the fast
        // cadence carries on from there.
        let at: Vec<_> = port.sent().iter().map(|(at, _)| at.as_millis()).collect();
        assert_eq!(at, [0, 1000, 1500, 2500, 32500]);
    });
}

#[test]
fn a_new_neighbour_while_silent_waits_for_the_link() {
    Paused::new().block_on(async {
        let mut port = Harness::start(Link::Down, Some(advertisement("gw-1", "gw-1")));
        port.new_neighbor.send_replace(());
        wait(10).await;
        assert_eq!(port.sent(), []);
    });
}
