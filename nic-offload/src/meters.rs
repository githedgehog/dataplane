// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The NIC's meters against the software's, over time: traffic the software meter has colored
//! nothing red so far, the NIC meter colors nothing red either.
//!
//! Once software colors a packet red, it keeps that packet's tokens, which the more permissive NIC
//! meter spent: from then on the two may drop different packets of the same traffic, and no margin
//! keeps every NIC red a software red. What the margins guarantee is that traffic within the
//! software's rates and bursts is never dropped in the NIC.
//!
//! Software is the meter the workers share, its leases spread over workers as packets arrive; the
//! NIC meter has its rates and bursts as mlx5 encodes them.

use std::time::Duration;

use dpdk::flow::template::{MeterAlgorithm, MeterProfile};
use policer::{Color, Profile, Rate};
use rate_limit::{Billing, Unit};

use crate::mlx5::{
    BYTE_OVERHEAD, MIN_OUTER_IP_BILLED, OUTER_IP_OVERHEAD, encoded_burst, encoded_rate, pmd_scale,
    profile,
};
use crate::program::PoliceMeter;

/// A NIC meter as mlx5 runs one: a packet passes a bucket while the bucket holds any token, and
/// is charged its whole cost (into debt). Buckets fill at their rates up to their sizes; under
/// srTCM what overflows the committed bucket fills the excess one, under RFC 4115 each fills on
/// its own. Rates, bursts and costs are in mlx5's units (packets scaled up), as encoded.
struct NicMeter {
    /// How far mlx5 scales costs up.
    shift: u32,
    cir: u64,
    eir: Option<u64>,
    cbs: i128,
    ebs: i128,
    /// Tokens, in billionths.
    tc: i128,
    te: i128,
    now: u64,
}

const NANOS: i128 = 1_000_000_000;

impl NicMeter {
    fn new(profile: &MeterProfile) -> NicMeter {
        let (cir, eir, cbs, ebs) = match profile.algorithm {
            MeterAlgorithm::Srtcm { cir, cbs, ebs } => (cir, None, cbs, ebs),
            MeterAlgorithm::Rfc4115 { cir, eir, cbs, ebs } => (cir, Some(eir), cbs, ebs),
            MeterAlgorithm::Trtcm { .. } => unreachable!("not lowered"),
        };
        let shift = pmd_scale(profile.unit);
        let (cir, eir) = (
            encoded_rate(cir << shift),
            eir.map(|eir| encoded_rate(eir << shift)),
        );
        let (cbs, ebs) = (
            i128::from(encoded_burst(cbs << shift)) * NANOS,
            i128::from(encoded_burst(ebs << shift)) * NANOS,
        );
        NicMeter {
            shift,
            cir,
            eir,
            cbs,
            ebs,
            tc: cbs,
            te: ebs,
            now: 0,
        }
    }

    fn color(&mut self, now: u64, cost: u64) -> Color {
        let elapsed = i128::from(now - self.now);
        self.now = now;
        let earned = i128::from(self.cir) * elapsed;
        let overflow = (self.tc + earned - self.cbs).max(0);
        self.tc = (self.tc + earned).min(self.cbs);
        let excess = match self.eir {
            Some(eir) => i128::from(eir) * elapsed,
            None => overflow,
        };
        self.te = (self.te + excess).min(self.ebs);
        let cost = i128::from(cost << self.shift) * NANOS;
        if self.tc > 0 {
            self.tc -= cost;
            Color::Green
        } else if self.te > 0 {
            self.te -= cost;
            Color::Yellow
        } else {
            Color::Red
        }
    }
}

/// A meter and packets: the gap before each, its IP bytes, and what the NIC counts beyond them.
#[derive(Debug, bolero::TypeGenerator)]
struct Run {
    packets_unit: bool,
    /// Whether the meter bills outer IP packets ([`Billing::OuterIp`]) rather than inner IP bytes.
    outer_ip_billing: bool,
    rate: u32,
    committed_burst: u32,
    excess: Option<(u32, u32)>,
    /// How many workers share the software meter.
    workers: u8,
    /// Each packet's gap, IP bytes, NIC overhead, and the worker it arrives at.
    arrivals: Vec<(u32, u16, u8, u8)>,
}

#[test]
fn conforming_traffic_is_never_red_in_the_nic() {
    bolero::check!().with_type::<Run>().for_each(|run| {
        let unit = if run.packets_unit { Unit::Packets } else { Unit::Bytes };
        let rate = |r: u32| Rate::new(std::num::NonZeroU64::new(u64::from(r).max(1)).unwrap_or(std::num::NonZeroU64::MIN));
        // Rates, bursts and gaps on the scale of the packets, so that buckets run dry.
        let (rates, bursts) = match unit {
            Unit::Bytes => (10_000_000, 100_000),
            Unit::Packets => (100_000, 100),
        };
        let (excess_rate, excess_burst) = match run.excess {
            Some((r, b)) => (Some(rate(r % rates)), u64::from(b % bursts)),
            None => (None, 0),
        };
        let Ok(software) = Profile::new(
            rate(run.rate % rates),
            u64::from(run.committed_burst % bursts),
            excess_rate,
            excess_burst,
        ) else {
            return;
        };
        let start = clock::now();
        let workers = std::num::NonZeroUsize::new(usize::from(run.workers % 16) + 1)
            .unwrap_or(std::num::NonZeroUsize::MIN);
        let shared = policer::SharedMeter::new(software, workers, start);
        let mut locals: Vec<_> = (0..workers.get()).map(|_| shared.local()).collect();
        let billing = if run.outer_ip_billing {
            Billing::OuterIp
        } else {
            Billing::Ip
        };
        let Some(nic_profile) = profile(&PoliceMeter {
            name: "m".into(),
            scope: crate::program::Scope::Peering,
            unit,
            billing,
            profile: software,
            lease_slack: shared.lease_slack(),
        }) else {
            return;
        };
        let mut nic = NicMeter::new(&nic_profile);
        let mut now = 0u64;
        for &(gap, bytes, overhead, worker) in run.arrivals.iter().take(400) {
            now += u64::from(gap % 1_000_000);
            // Packets of a jumbo frame at most, as the debt margin assumes.
            let (least, most) = match billing {
                Billing::Ip => (20, BYTE_OVERHEAD),
                Billing::OuterIp => (MIN_OUTER_IP_BILLED, OUTER_IP_OVERHEAD),
            };
            let billed = (u64::from(bytes) % 9217).max(least);
            let (cost, nic_cost) = match unit {
                Unit::Bytes => (billed, billed + u64::from(overhead) % (most + 1)),
                Unit::Packets => (1, 1),
            };
            let at = usize::from(worker) % locals.len();
            let software_color = locals[at].color(
                start + Duration::from_nanos(now),
                cost,
                Color::Green,
            );
            let nic_color = nic.color(now, nic_cost);
            if software_color == Color::Red {
                break;
            }
            assert!(
                nic_color != Color::Red,
                "the NIC colors red traffic software has colored nothing red\nrun: {run:?}\nNIC profile: {nic_profile:?}"
            );
        }
    });
}

/// A chained meter: a bytes component, then a packets component the bytes component's colors feed,
/// and packets: the gap before each, its outer IP bytes, and the worker it arrives at.
#[derive(Debug, bolero::TypeGenerator)]
struct Chain {
    bytes: (u32, u32, Option<(u32, u32)>),
    packets: (u32, u32, Option<(u32, u32)>),
    workers: u8,
    arrivals: Vec<(u32, u16, u8)>,
}

/// Software meters a packet with both components of a meter, the packets component taking the
/// bytes component's color (color-aware: never better); the NIC chains two color-blind meters, the
/// second charged with what the first did not color red. Traffic the software colors nothing red
/// in either component, the NIC colors nothing red in either: both meters see the same packets,
/// and a color-blind meter is at least as permissive as a color-aware one fed the same packets.
#[test]
fn a_chained_meter_is_never_red_in_the_nic_where_software_is_not() {
    // Runs whose packets component colored something red or yellow first, so the chain mattered.
    let reached = std::panic::AssertUnwindSafe(std::cell::Cell::new([0usize; 3]));
    bolero::check!().with_type::<Chain>().for_each(|chain| {
        let rate = |r: u32| {
            Rate::new(
                std::num::NonZeroU64::new(u64::from(r).max(1)).unwrap_or(std::num::NonZeroU64::MIN),
            )
        };
        let profile_of =
            |(r, b, excess): (u32, u32, Option<(u32, u32)>), rates: u32, bursts: u32| {
                let (excess_rate, excess_burst) = match excess {
                    Some((er, eb)) => (Some(rate(er % rates)), u64::from(eb % bursts)),
                    None => (None, 0),
                };
                Profile::new(
                    rate(r % rates),
                    u64::from(b % bursts),
                    excess_rate,
                    excess_burst,
                )
                .ok()
            };
        let (Some(bytes), Some(packets)) = (
            profile_of(chain.bytes, 10_000_000, 100_000),
            profile_of(chain.packets, 100_000, 100),
        ) else {
            return;
        };
        let start = clock::now();
        let workers = std::num::NonZeroUsize::new(usize::from(chain.workers % 16) + 1)
            .unwrap_or(std::num::NonZeroUsize::MIN);
        let (shared_bytes, shared_packets) = (
            policer::SharedMeter::new(bytes, workers, start),
            policer::SharedMeter::new(packets, workers, start),
        );
        let mut locals: Vec<_> = (0..workers.get())
            .map(|_| (shared_bytes.local(), shared_packets.local()))
            .collect();
        let nic_of = |unit, profile: Profile, lease_slack| {
            crate::mlx5::profile(&PoliceMeter {
                name: "m".into(),
                unit,
                billing: Billing::OuterIp,
                scope: crate::program::Scope::Ingress,
                profile,
                lease_slack,
            })
        };
        let (Some(nic_bytes), Some(nic_packets)) = (
            nic_of(Unit::Bytes, bytes, shared_bytes.lease_slack()),
            nic_of(Unit::Packets, packets, shared_packets.lease_slack()),
        ) else {
            return;
        };
        let (mut first, mut second) = (NicMeter::new(&nic_bytes), NicMeter::new(&nic_packets));
        let mut now = 0u64;
        for &(gap, size, worker) in chain.arrivals.iter().take(400) {
            now += u64::from(gap % 1_000_000);
            let cost = (u64::from(size) % 9217).max(MIN_OUTER_IP_BILLED);
            let at = usize::from(worker) % locals.len();
            let when = start + Duration::from_nanos(now);
            let (software_bytes, software_packets) = &mut locals[at];
            let colored = software_bytes.color(when, cost, Color::Green);
            let chained = if colored == Color::Red {
                Color::Red
            } else {
                software_packets.color(when, 1, colored)
            };
            let mut counts = reached.get();
            counts[match (colored, chained) {
                (Color::Red, _) => 0,
                (_, Color::Red) => 1,
                _ => 2,
            }] += 1;
            reached.set(counts);
            if chained == Color::Red {
                break;
            }
            let nic = first.color(now, cost + OUTER_IP_OVERHEAD);
            assert!(
                nic != Color::Red && second.color(now, 1) != Color::Red,
                "the NIC colors red what software colors nothing red\nchain: {chain:?}"
            );
        }
    });
    let [bytes_red, packets_red, passed] = reached.0.get();
    eprintln!(
        "chained meters: software colored {bytes_red} packet(s) red in the bytes component, {packets_red} in the packets component, and passed {passed}"
    );
    assert!(packets_red > 0, "the packets component never ran dry");
}

/// A burst is encoded at least as large as software's, without wrapping, or the meter is refused
/// (left in software): never encoded smaller, as a burst past what mlx5 takes would be.
#[test]
fn bursts_mlx5_cannot_take_are_refused_not_wrapped() {
    /// The greatest burst mlx5 takes, scaled (`MLX5_SRTCM_XBS_MAX`).
    const MAX_BURST: u64 = 255 << 31;
    let check = |packets: bool, burst: u64| {
        let unit = if packets { Unit::Packets } else { Unit::Bytes };
        let Ok(software) = Profile::new(Rate::new(std::num::NonZeroU64::MIN), burst, None, 0)
        else {
            return;
        };
        let meter = PoliceMeter {
            name: "m".into(),
            unit,
            billing: Billing::Ip,
            scope: crate::program::Scope::Peering,
            profile: software,
            lease_slack: [0, 0],
        };
        let shift = pmd_scale(profile_unit(unit));
        match profile(&meter) {
            Some(MeterProfile {
                algorithm: MeterAlgorithm::Srtcm { cbs, .. },
                ..
            }) => {
                let scaled = cbs << shift;
                assert!(cbs >= burst, "{burst} encoded as {cbs}");
                assert!(scaled <= MAX_BURST, "{burst} encoded past mlx5's maximum");
                assert!(encoded_burst(scaled) >= scaled, "{burst} wraps");
            }
            Some(other) => panic!("{other:?}"),
            // Software's burst alone is past mlx5's maximum, but for its scaling (up to 4.6
            // times) and one frame.
            None => assert!(burst > (MAX_BURST >> shift) / 5, "{burst} refused"),
        }
    };
    for packets in [false, true] {
        for burst in [
            1,
            1500,
            255 << 20,
            1 << 32,
            1 << 36,
            1 << 40,
            u64::MAX / 2,
            u64::MAX,
        ] {
            check(packets, burst);
        }
    }
    bolero::check!()
        .with_type::<(bool, u64)>()
        .for_each(|&(packets, burst)| check(packets, burst));
}

fn profile_unit(unit: Unit) -> dpdk::flow::template::MeterUnit {
    match unit {
        Unit::Bytes => dpdk::flow::template::MeterUnit::Bytes,
        Unit::Packets => dpdk::flow::template::MeterUnit::Packets,
    }
}
