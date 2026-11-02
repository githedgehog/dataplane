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
use rate_limit::Unit;

use crate::mlx5::{BYTE_OVERHEAD, encoded_burst, encoded_rate, pmd_scale, profile};
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
        let nic_profile = profile(&PoliceMeter {
            name: "m".into(),
            unit,
            profile: software,
            lease_slack: shared.lease_slack(),
        });
        let mut nic = NicMeter::new(&nic_profile);
        let mut now = 0u64;
        for &(gap, bytes, overhead, worker) in run.arrivals.iter().take(400) {
            now += u64::from(gap % 1_000_000);
            // Packets of a jumbo frame at most, as the debt margin assumes.
            let billed = (u64::from(bytes) % 9217).max(20);
            let (cost, nic_cost) = match unit {
                Unit::Bytes => (billed, billed + u64::from(overhead) % (BYTE_OVERHEAD + 1)),
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
