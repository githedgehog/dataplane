// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{
    Color, CommittedPlusExcess, Limits, Meter, Profile, ProfileError, Rate, SharedMeter,
    SingleRate, TwoRate,
};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

fn rate(per_second: u64) -> Rate {
    Rate::new(NonZeroU64::new(per_second).unwrap())
}

fn single(cir: u64, cbs: u64, ebs: u64) -> Profile {
    SingleRate::new(rate(cir), cbs, ebs).unwrap().into()
}

fn two(cir: u64, cbs: u64, pir: u64, pbs: u64) -> Profile {
    TwoRate::new(
        rate(cir),
        NonZeroU64::new(cbs).unwrap(),
        rate(pir),
        NonZeroU64::new(pbs).unwrap(),
    )
    .unwrap()
    .into()
}

fn excess(cir: u64, cbs: u64, eir: u64, ebs: u64) -> Profile {
    CommittedPlusExcess::new(
        rate(cir),
        NonZeroU64::new(cbs).unwrap(),
        rate(eir),
        NonZeroU64::new(ebs).unwrap(),
    )
    .into()
}

fn bytes(profile: Profile) -> Limits {
    Limits::new(Some(profile), None).unwrap()
}

/// RFC 2697, 2698 and 4115 transcribed as literally as they read: one token at a time, at the instants
/// the rates say, and the color-blind rules as written (for RFC 4115, as its Figure 1 writes them).
#[derive(Debug)]
struct Literal {
    profile: Profile,
    /// Tc and Te (RFC 2697 and 4115), or Tc and Tp (RFC 2698).
    tokens: [u64; 2],
    /// How many of each bucket's ticks have happened.
    ticks: [u64; 2],
}

impl Literal {
    fn new(profile: Profile) -> Literal {
        let tokens = match profile {
            Profile::SingleRate(p) => [p.committed_burst(), p.excess_burst()],
            Profile::TwoRate(p) => [p.committed_burst().get(), p.peak_burst().get()],
            Profile::CommittedPlusExcess(p) => [p.committed_burst().get(), p.excess_burst().get()],
        };
        Literal {
            profile,
            tokens,
            ticks: [0; 2],
        }
    }

    /// Ticks of a `rate` a second that have happened `elapsed` after time 0.
    fn due(rate: Rate, elapsed: Duration) -> u64 {
        u64::try_from(elapsed.as_nanos() * u128::from(rate.per_second().get()) / 1_000_000_000)
            .unwrap()
    }

    fn color(&mut self, elapsed: Duration, b: u64) -> Color {
        match self.profile {
            Profile::SingleRate(p) => {
                let [tc, te] = &mut self.tokens;
                let due = Literal::due(p.committed_rate(), elapsed);
                while self.ticks[0] < due {
                    self.ticks[0] += 1;
                    if *tc < p.committed_burst() {
                        *tc += 1;
                    } else if *te < p.excess_burst() {
                        *te += 1;
                    }
                }
                if *tc >= b {
                    *tc -= b;
                    Color::Green
                } else if *te >= b {
                    *te -= b;
                    Color::Yellow
                } else {
                    Color::Red
                }
            }
            Profile::TwoRate(p) => {
                let [tc, tp] = &mut self.tokens;
                let due = Literal::due(p.committed_rate(), elapsed);
                while self.ticks[0] < due {
                    self.ticks[0] += 1;
                    if *tc < p.committed_burst().get() {
                        *tc += 1;
                    }
                }
                let due = Literal::due(p.peak_rate(), elapsed);
                while self.ticks[1] < due {
                    self.ticks[1] += 1;
                    if *tp < p.peak_burst().get() {
                        *tp += 1;
                    }
                }
                if *tp < b {
                    Color::Red
                } else if *tc < b {
                    *tp -= b;
                    Color::Yellow
                } else {
                    *tp -= b;
                    *tc -= b;
                    Color::Green
                }
            }
            Profile::CommittedPlusExcess(p) => {
                let [tc, te] = &mut self.tokens;
                let due = Literal::due(p.committed_rate(), elapsed);
                while self.ticks[0] < due {
                    self.ticks[0] += 1;
                    if *tc < p.committed_burst().get() {
                        *tc += 1;
                    }
                }
                let due = Literal::due(p.excess_rate(), elapsed);
                while self.ticks[1] < due {
                    self.ticks[1] += 1;
                    if *te < p.excess_burst().get() {
                        *te += 1;
                    }
                }
                if b <= *tc {
                    *tc -= b;
                    Color::Green
                } else if b <= *te {
                    *te -= b;
                    Color::Yellow
                } else {
                    Color::Red
                }
            }
        }
    }
}

/// A small profile and a stream of packets, from raw fuzzer input.
type Scenario = (u8, [u16; 4], Vec<(u16, u16)>);

fn scenario((kind, [r1, r2, b1, b2], packets): &Scenario) -> (Profile, Vec<(Duration, u32)>) {
    // Small rates and bursts, so that the literal model's tick by tick refill stays cheap.
    let r1 = u64::from(r1 % 2000) + 1;
    let r2 = u64::from(r2 % 2000) + 1;
    let profile = match kind % 3 {
        0 => {
            let (cbs, ebs) = (u64::from(b1 % 4000), u64::from(b2 % 4000));
            single(r1, cbs, if cbs == 0 { ebs.max(1) } else { ebs })
        }
        1 => two(
            r1.min(r2),
            u64::from(b1 % 4000) + 1,
            r1.max(r2),
            u64::from(b2 % 4000) + 1,
        ),
        _ => excess(r1, u64::from(b1 % 4000) + 1, r2, u64::from(b2 % 4000) + 1),
    };
    let mut elapsed = Duration::ZERO;
    let packets = packets
        .iter()
        .take(200)
        .map(|&(gap_us, size)| {
            elapsed += Duration::from_micros(u64::from(gap_us));
            (elapsed, u32::from(size % 1500) + 1)
        })
        .collect();
    (profile, packets)
}

//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# The token buckets C and E are initially (at time 0) full, i.e., the
//# token count Tc(0) = CBS and the token count Te(0) = EBS.
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=test
//# The token buckets P and C are initially (at time 0) full, i.e., the
//# token count Tp(0) = PBS and the token count Tc(0) = CBS.
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# Thereafter,
//# the token counts Tc and Te are updated CIR times per second as
//# follows:
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o If Tc is less than CBS, Tc is incremented by one, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o if Te is less then EBS, Te is incremented by one, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o neither Tc nor Te is incremented.
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=test
//# Thereafter,
//# the token count Tp is incremented by one PIR times per second up to
//# PBS and the token count Tc is incremented by one CIR times per second
//# up to CBS.
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# When a packet of size B bytes arrives at time t, the following
//# happens if the srTCM is configured to operate in the Color-Blind
//# mode:
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o If Tc(t)-B >= 0, the packet is green and Tc is decremented by B
//# down to the minimum value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o if Te(t)-B >= 0, the packets is yellow and Te is decremented by B
//# down to the minimum value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o the packet is red and neither Tc nor Te is decremented.
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=test
//# When a packet of size B bytes arrives at time t, the following
//# happens if the trTCM is configured to operate in the Color-Blind
//# mode:
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=test
//# o If Tp(t)-B < 0, the packet is red, else
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=test
//# o if Tc(t)-B < 0, the packet is yellow and Tp is decremented by B,
//# else
//
//= https://www.rfc-editor.org/rfc/rfc2698#section-3
//= type=test
//# o the packet is green and both Tp and Tc are decremented by B.
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# The token buckets C and E are initially (at time 0) full; i.e., the
//# token count Tc(0) = CBS and Te(0) = EBS.
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# Thereafter, the token count
//# Tc is incremented by one CIR times per second (up to CBS), and the
//# token count Te is incremented by one EIR times per second (up to
//# EBS).
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# When a green packet of size B arrives at time t, then
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# o  the packet is red.
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# In the color-blind operation, the meter assumes that all incoming
//# packets are green.
#[test]
fn the_meter_colors_as_the_rfcs_do() {
    bolero::check!().with_type::<Scenario>().for_each(|input| {
        let (profile, packets) = scenario(input);
        let start = clock::now();
        let mut literal = Literal::new(profile);
        let mut meter = Meter::new(&bytes(profile), start);
        for (elapsed, size) in packets {
            assert_eq!(
                meter.color(start + elapsed, size),
                literal.color(elapsed, u64::from(size)),
                "{profile:?} at {elapsed:?} for {size} bytes"
            );
        }
    });
}

#[test]
fn a_burst_within_the_committed_size_is_green_and_then_the_excess_is_yellow() {
    let start = clock::now();
    let mut meter = Meter::new(&bytes(single(1000, 3000, 1500)), start);
    let colors: Vec<_> = (0..6).map(|_| meter.color(start, 1000)).collect();
    assert_eq!(
        colors,
        [
            Color::Green,
            Color::Green,
            Color::Green,
            Color::Yellow,
            Color::Red,
            Color::Red
        ]
    );
    // A second refills a thousand tokens, into the committed bucket first.
    assert_eq!(
        meter.color(start + Duration::from_secs(1), 1000),
        Color::Green
    );
    assert_eq!(
        meter.color(start + Duration::from_secs(1), 500),
        Color::Yellow
    );
}

#[test]
fn over_the_peak_rate_is_red_and_between_the_rates_is_yellow() {
    let start = clock::now();
    let mut meter = Meter::new(&bytes(two(1000, 1000, 2000, 2000)), start);
    assert_eq!(meter.color(start, 1000), Color::Green);
    assert_eq!(meter.color(start, 1000), Color::Yellow);
    assert_eq!(meter.color(start, 1), Color::Red);
    // Half a second earns 500 committed and 1000 peak tokens.
    let later = start + Duration::from_millis(500);
    assert_eq!(meter.color(later, 500), Color::Green);
    assert_eq!(meter.color(later, 500), Color::Yellow);
    assert_eq!(meter.color(later, 1), Color::Red);
}

#[test]
fn the_excess_rate_adds_to_the_committed_rate() {
    let start = clock::now();
    let mut meter = Meter::new(&bytes(excess(1000, 1000, 1000, 1000)), start);
    assert_eq!(meter.color(start, 1000), Color::Green);
    assert_eq!(meter.color(start, 1000), Color::Yellow);
    assert_eq!(meter.color(start, 1), Color::Red);
    // A second earns 1000 committed and 1000 excess tokens: twice what RFC 2698 passes with a
    // peak rate of 1000.
    let later = start + Duration::from_secs(1);
    assert_eq!(meter.color(later, 1000), Color::Green);
    assert_eq!(meter.color(later, 1000), Color::Yellow);
    assert_eq!(meter.color(later, 1), Color::Red);
}

/// RFC 4115's reason to exist: under RFC 2698 a packet within the committed rate can be red because
/// the peak bucket is smaller than the committed one, or drained by yellow traffic.
#[test]
fn green_traffic_does_not_depend_on_the_excess_bucket() {
    let start = clock::now();
    let mut peak = Meter::new(&bytes(two(1000, 1000, 2000, 500)), start);
    assert_eq!(peak.color(start, 1000), Color::Red);
    let mut excess_rate = Meter::new(&bytes(excess(1000, 1000, 1000, 500)), start);
    assert_eq!(excess_rate.color(start, 1000), Color::Green);
    // Spending the whole excess bucket on yellow leaves the committed bucket to green.
    let mut excess_rate = Meter::new(&bytes(excess(1000, 500, 1000, 1000)), start);
    assert_eq!(excess_rate.color(start, 1000), Color::Yellow);
    assert_eq!(excess_rate.color(start, 500), Color::Green);
}

//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# o  if Tc(t)- B > 0, the packet is green, and Tc(t) is decremented
//# by B; else
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# o  if Te(t)- B > 0, the packet is yellow, and Te(t) is decremented
//# by B; else
#[test]
fn a_packet_that_exactly_empties_a_bucket_still_pays_for_its_color() {
    let start = clock::now();
    let mut meter = Meter::new(&bytes(excess(1, 1000, 1, 500)), start);
    assert_eq!(meter.color(start, 1000), Color::Green);
    assert_eq!(meter.color(start, 500), Color::Yellow);
    assert_eq!(meter.color(start, 1), Color::Red);
}

//= https://www.rfc-editor.org/rfc/rfc4115#section-2
//= type=test
//# The CIR and EIR can be set
//# independently of each other.
#[test]
fn an_excess_rate_profile_takes_any_two_rates() {
    let start = clock::now();
    // An excess rate below the committed rate is fine; it is not a peak.
    let mut meter = Meter::new(&bytes(excess(2000, 1000, 1000, 1000)), start);
    assert_eq!(meter.color(start, 1000), Color::Green);
    assert_eq!(meter.color(start, 1000), Color::Yellow);
}

#[test]
fn a_packet_limit_counts_packets_not_bytes() {
    let start = clock::now();
    let limits = Limits::new(None, Some(single(10, 2, 0))).unwrap();
    let mut meter = Meter::new(&limits, start);
    assert_eq!(meter.color(start, 9000), Color::Green);
    assert_eq!(meter.color(start, 9000), Color::Green);
    assert_eq!(meter.color(start, 64), Color::Red);
    assert_eq!(
        meter.color(start + Duration::from_millis(100), 64),
        Color::Green
    );
}

#[test]
fn time_running_backwards_earns_nothing() {
    let earlier = clock::now();
    let start = earlier + Duration::from_secs(1);
    let mut meter = Meter::new(&bytes(single(1000, 1000, 0)), start);
    assert_eq!(meter.color(start, 1000), Color::Green);
    assert_eq!(meter.color(earlier, 1), Color::Red);
    assert_eq!(
        meter.color(start + Duration::from_millis(1), 1),
        Color::Green
    );
}

//= https://www.rfc-editor.org/rfc/rfc2697#section-2
//= type=test
//# The CBS and the EBS and are measured in bytes.  The CBS and EBS must
//# be configured so that at least one of them is larger than 0.
#[test]
fn a_single_rate_profile_needs_a_burst() {
    assert_eq!(SingleRate::new(rate(1), 0, 0), Err(ProfileError::NoBurst));
    assert!(SingleRate::new(rate(1), 0, 1).is_ok());
    assert!(SingleRate::new(rate(1), 1, 0).is_ok());
}

//= https://www.rfc-editor.org/rfc/rfc2698#section-2
//= type=test
//# The PIR must be equal to or greater than the CIR.
#[test]
fn a_two_rate_profile_peaks_at_or_above_its_committed_rate() {
    let burst = NonZeroU64::new(1500).unwrap();
    assert_eq!(
        TwoRate::new(rate(2), burst, rate(1), burst),
        Err(ProfileError::PeakBelowCommitted {
            committed: NonZeroU64::new(2).unwrap(),
            peak: NonZeroU64::new(1).unwrap(),
        })
    );
    assert!(TwoRate::new(rate(2), burst, rate(2), burst).is_ok());
}

#[test]
fn limits_must_limit_something() {
    assert_eq!(Limits::new(None, None), Err(ProfileError::Unlimited));
}

// Outside a model run, the model checkers' locks cannot be taken.
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
mod leasing {
    use super::*;
    use crate::LocalMeter;
    use std::num::NonZeroUsize;

    #[test]
    fn one_worker_leasing_only_what_it_needs_is_the_exact_meter() {
        bolero::check!().with_type::<Scenario>().for_each(|input| {
            let (profile, packets) = scenario(input);
            let start = clock::now();
            let mut literal = Literal::new(profile);
            let mut local = SharedMeter::with_leases(&bytes(profile), start, |_, _| 1).local();
            for (elapsed, size) in packets {
                assert_eq!(
                    local.color(start + elapsed, size),
                    literal.color(elapsed, u64::from(size)),
                    "{profile:?} at {elapsed:?} for {size} bytes"
                );
            }
        });
    }

    /// However the workers interleave and whatever they lease, no token is spent twice: what passes as
    /// green, or as green or yellow, is never more than the buckets held to begin with plus what they
    /// have earned since.
    #[test]
    fn leases_never_admit_more_than_the_buckets_earn() {
        bolero::check!()
            .with_type::<(Scenario, u16, Vec<u8>)>()
            .for_each(|(input, lease, workers)| {
                let (profile, packets) = scenario(input);
                let lease = u64::from(*lease);
                let start = clock::now();
                let shared = SharedMeter::with_leases(&bytes(profile), start, |_, _| lease);
                let mut locals: Vec<_> = (0..4).map(|_| shared.local()).collect();
                let (mut green, mut passed) = (0, 0);
                let mut end = Duration::ZERO;
                for (i, (elapsed, size)) in packets.into_iter().enumerate() {
                    let worker = usize::from(workers.get(i).copied().unwrap_or(0) % 4);
                    match locals[worker].color(start + elapsed, size) {
                        Color::Green => green += u64::from(size),
                        Color::Yellow => {}
                        Color::Red => continue,
                    }
                    passed += u64::from(size);
                    end = elapsed;
                }
                let earned = |rate: Rate| Literal::due(rate, end);
                let (green_bound, passed_bound) = match profile {
                    Profile::SingleRate(p) => {
                        let earned = earned(p.committed_rate());
                        (
                            p.committed_burst() + earned,
                            p.committed_burst() + p.excess_burst() + earned,
                        )
                    }
                    Profile::TwoRate(p) => (
                        p.committed_burst().get() + earned(p.committed_rate()),
                        p.peak_burst().get() + earned(p.peak_rate()),
                    ),
                    Profile::CommittedPlusExcess(p) => {
                        let green = p.committed_burst().get() + earned(p.committed_rate());
                        (
                            green,
                            green + p.excess_burst().get() + earned(p.excess_rate()),
                        )
                    }
                };
                assert!(green <= green_bound, "{green} green of {green_bound}");
                assert!(passed <= passed_bound, "{passed} passed of {passed_bound}");
            });
    }

    #[test]
    fn a_packet_is_only_as_good_as_its_worse_limit() {
        // Tokens not yet spent, whether in the shared buckets or in the worker's lease.
        fn unspent(shared: &SharedMeter, local: &LocalMeter) -> Vec<[u64; 2]> {
            shared
                .tokens()
                .into_iter()
                .zip(local.held())
                .map(|([c, s], [held_c, held_s])| [c + held_c, s + held_s])
                .collect()
        }
        let start = clock::now();
        let limits = Limits::new(Some(single(1000, 1000, 1000)), Some(single(1, 1, 1))).unwrap();
        let shared = SharedMeter::with_leases(&limits, start, |_, _| 1);
        let mut local = shared.local();
        assert_eq!(local.color(start, 100), Color::Green);
        // Within the byte limit's committed burst, but over the packet limit's: yellow, and charged to the
        // byte limit as yellow.
        assert_eq!(local.color(start, 100), Color::Yellow);
        assert_eq!(unspent(&shared, &local), [[900, 900], [0, 0]]);
        assert_eq!(local.color(start, 100), Color::Red);
        assert_eq!(unspent(&shared, &local), [[900, 900], [0, 0]]);
    }

    #[test]
    fn leases_are_a_slice_of_the_rate_and_never_drain_the_bucket_into_one_worker() {
        let start = clock::now();
        // 100 µs of 10 MB/s is 1000 tokens, and a quarter of the bucket among two workers is 1250.
        let workers = NonZeroUsize::new(2).unwrap();
        let shared = SharedMeter::new(&bytes(single(10_000_000, 10_000, 1)), workers, start);
        let mut local = shared.local();
        assert_eq!(local.color(start, 100), Color::Green);
        assert_eq!(local.held(), [[900, 0]]);
        // A small bucket caps the lease instead: a quarter of 2000 among two workers is 250.
        let shared = SharedMeter::new(&bytes(single(10_000_000, 2000, 1)), workers, start);
        let mut local = shared.local();
        assert_eq!(local.color(start, 100), Color::Green);
        assert_eq!(local.held(), [[150, 0]]);
    }
}

/// Workers coloring at the same instant share the committed burst between them: every token ends up
/// spent on a green packet, held by a worker, or still in the shared bucket, and in exactly one place.
#[concurrency::test]
fn workers_spend_each_token_once() {
    use concurrency::sync::Arc;
    use concurrency::thread;

    const BURST: u64 = 1000;
    const PACKET: u32 = 100;
    let start = Instant::now();
    let shared = Arc::new(SharedMeter::with_leases(
        &bytes(single(1, BURST, 0)),
        start,
        |_, _| 300,
    ));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut local = shared.local();
                let green = (0..4)
                    .filter(|_| local.color(start, PACKET) == Color::Green)
                    .count();
                (
                    u64::try_from(green).unwrap() * u64::from(PACKET),
                    local.held(),
                )
            })
        })
        .collect();
    let mut accounted = 0;
    for worker in workers {
        let (green, held) = worker.join().unwrap();
        accounted += green + held[0][0];
    }
    accounted += shared.tokens()[0][0];
    assert_eq!(accounted, BURST);
}

#[test]
fn limits_render_what_they_limit() {
    let limits = Limits::new(Some(two(1000, 1500, 2000, 3000)), Some(single(10, 5, 0))).unwrap();
    assert_eq!(
        limits.to_string(),
        "bytes: trTCM cir 1000/s cbs 1500 pir 2000/s pbs 3000; packets: srTCM cir 10/s cbs 5 ebs 0"
    );
    let limits = Limits::new(None, Some(single(10, 5, 0))).unwrap();
    assert_eq!(limits.to_string(), "packets: srTCM cir 10/s cbs 5 ebs 0");
    let limits = Limits::new(Some(excess(1000, 1500, 500, 3000)), None).unwrap();
    assert_eq!(
        limits.to_string(),
        "bytes: rfc4115 cir 1000/s cbs 1500 eir 500/s ebs 3000"
    );
}
