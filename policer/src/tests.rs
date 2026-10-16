// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{Color, Meter, Profile, ProfileError, Rate, SharedMeter};
use std::num::NonZeroU64;
use std::time::Duration;

fn rate(per_second: u64) -> Rate {
    Rate::new(NonZeroU64::new(per_second).unwrap())
}

/// A profile with no excess rate: RFC 2697's single rate marker.
fn single(cir: u64, cbs: u64, ebs: u64) -> Profile {
    Profile::new(rate(cir), cbs, None, ebs).unwrap()
}

/// A profile with an excess rate.
fn excess(cir: u64, cbs: u64, eir: u64, ebs: u64) -> Profile {
    Profile::new(rate(cir), cbs, Some(rate(eir)), ebs).unwrap()
}

/// Independent oracle: refill one token at a time, with coupling and color-aware marking.
#[derive(Debug)]
struct Literal {
    profile: Profile,
    /// Tc and Te.
    tokens: [u64; 2],
    /// How many of each rate's ticks have happened.
    ticks: [u64; 2],
}

impl Literal {
    fn new(profile: Profile) -> Literal {
        Literal {
            profile,
            tokens: [profile.committed_burst(), profile.excess_burst()],
            ticks: [0; 2],
        }
    }

    /// Ticks of a `rate` a second that have happened `elapsed` after time 0.
    fn due(rate: Rate, elapsed: Duration) -> u64 {
        u64::try_from(elapsed.as_nanos() * u128::from(rate.per_second().get()) / 1_000_000_000)
            .unwrap()
    }

    fn color(&mut self, elapsed: Duration, b: u64, input: Color) -> Color {
        let p = self.profile;
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
        if let Some(eir) = p.excess_rate() {
            let due = Literal::due(eir, elapsed);
            while self.ticks[1] < due {
                self.ticks[1] += 1;
                if *te < p.excess_burst() {
                    *te += 1;
                }
            }
        }
        match input {
            Color::Green if b <= *tc => {
                *tc -= b;
                Color::Green
            }
            Color::Green | Color::Yellow if b <= *te => {
                *te -= b;
                Color::Yellow
            }
            _ => Color::Red,
        }
    }
}

/// A small profile and a stream of packets, from raw fuzzer input.
type Scenario = (bool, [u16; 4], Vec<(u16, u16, u8)>);

fn scenario(
    (with_excess_rate, [r1, r2, b1, b2], packets): &Scenario,
) -> (Profile, Vec<(Duration, u32, Color)>) {
    // Small rates and bursts, so that the literal model's tick by tick refill stays cheap.
    let cir = u64::from(r1 % 2000) + 1;
    let eir = with_excess_rate.then(|| rate(u64::from(r2 % 2000) + 1));
    let (cbs, ebs) = (u64::from(b1 % 4000), u64::from(b2 % 4000));
    let profile =
        Profile::new(rate(cir), cbs, eir, if cbs == 0 { ebs.max(1) } else { ebs }).unwrap();
    let mut elapsed = Duration::ZERO;
    let packets = packets
        .iter()
        .take(200)
        .map(|&(gap_us, size, color)| {
            elapsed += Duration::from_micros(u64::from(gap_us));
            let input = match color % 4 {
                0 | 1 => Color::Green,
                2 => Color::Yellow,
                _ => Color::Red,
            };
            (elapsed, u32::from(size % 1500) + 1, input)
        })
        .collect();
    (profile, packets)
}

//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# The token buckets C and E are initially (at time 0) full, i.e., the
//# token count Tc(0) = CBS and the token count Te(0) = EBS.
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
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# When a packet of size B bytes arrives at time t, the following
//# happens if the srTCM is configured to operate in the Color-Aware
//# mode:
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o If the packet has been precolored as green and Tc(t)-B >= 0, the
//# packet is green and Tc is decremented by B down to the minimum
//# value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o If the packet has been precolored as green or yellow and if
//# Te(t)-B >= 0, the packets is yellow and Te is decremented by B
//# down to the minimum value of 0, else
//
//= https://www.rfc-editor.org/rfc/rfc2697#section-3
//= type=test
//# o the packet is red and neither Tc nor Te is decremented.
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
//# When a yellow packet of size B arrives at time t, then
//
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# Incoming red packets are not tested against any of the two token
//# buckets and remain red.
#[test]
fn the_meter_colors_as_mef_10_does() {
    bolero::check!().with_type::<Scenario>().for_each(|input| {
        let (profile, packets) = scenario(input);
        let start = clock::now();
        let mut literal = Literal::new(profile);
        let mut meter = Meter::new(profile, start);
        for (elapsed, size, color) in packets {
            assert_eq!(
                meter.color(start + elapsed, u64::from(size), color),
                literal.color(elapsed, u64::from(size), color),
                "{profile:?} at {elapsed:?} for {size} tokens arriving {color:?}"
            );
        }
    });
}

/// Color-blind: every packet arrives green.
//= https://www.rfc-editor.org/rfc/rfc4115#section-3
//= type=test
//# In the color-blind operation, the meter assumes that all incoming
//# packets are green.
#[test]
fn a_burst_within_the_committed_size_is_green_and_then_the_excess_is_yellow() {
    let start = clock::now();
    let mut meter = Meter::new(single(1000, 3000, 1500), start);
    let colors: Vec<_> = (0..6)
        .map(|_| meter.color(start, 1000, Color::Green))
        .collect();
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
    let later = start + Duration::from_secs(1);
    assert_eq!(meter.color(later, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(later, 500, Color::Green), Color::Yellow);
}

#[test]
fn the_excess_rate_adds_to_the_committed_rate() {
    let start = clock::now();
    let mut meter = Meter::new(excess(1000, 1000, 1000, 1000), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Yellow);
    assert_eq!(meter.color(start, 1, Color::Green), Color::Red);
    // A second earns 1000 committed and 1000 excess tokens.
    let later = start + Duration::from_secs(1);
    assert_eq!(meter.color(later, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(later, 1000, Color::Green), Color::Yellow);
    assert_eq!(meter.color(later, 1, Color::Green), Color::Red);
}

#[test]
fn green_traffic_does_not_depend_on_the_excess_bucket() {
    let start = clock::now();
    let mut meter = Meter::new(excess(1000, 1000, 1000, 500), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    // Spending the whole excess bucket on yellow leaves the committed bucket to green.
    let mut meter = Meter::new(excess(1000, 500, 1000, 1000), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Yellow);
    assert_eq!(meter.color(start, 500, Color::Green), Color::Green);
}

#[test]
fn the_committed_overflow_refills_the_excess_bucket() {
    let start = clock::now();
    let mut meter = Meter::new(excess(1000, 1000, 1, 10_000), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(start, 10_000, Color::Green), Color::Yellow);
    assert_eq!(meter.color(start, 1, Color::Green), Color::Red);
    // Of five idle seconds, the first refills the committed bucket and the other four overflow into
    // the excess bucket, on top of the 5 tokens of its own rate. Uncoupled, it would hold only those 5.
    let later = start + Duration::from_secs(5);
    assert_eq!(meter.color(later, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(later, 4005, Color::Green), Color::Yellow);
    assert_eq!(meter.color(later, 1, Color::Green), Color::Red);
}

/// Coupling never adds rate: committed tokens green traffic spends do not reach the excess bucket.
#[test]
fn green_traffic_at_the_committed_rate_leaves_the_excess_bucket_its_own_rate() {
    let start = clock::now();
    let mut meter = Meter::new(excess(1000, 1000, 100, 10_000), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(start, 10_000, Color::Green), Color::Yellow);
    for second in 1..=5 {
        let now = start + Duration::from_secs(second);
        assert_eq!(meter.color(now, 1000, Color::Green), Color::Green);
    }
    let end = start + Duration::from_secs(5);
    assert_eq!(meter.color(end, 500, Color::Green), Color::Yellow);
    assert_eq!(meter.color(end, 1, Color::Green), Color::Red);
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
    let mut meter = Meter::new(excess(1, 1000, 1, 500), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(start, 500, Color::Green), Color::Yellow);
    assert_eq!(meter.color(start, 1, Color::Green), Color::Red);
}

//= https://www.rfc-editor.org/rfc/rfc4115#section-2
//= type=test
//# The CIR and EIR can be set
//# independently of each other.
#[test]
fn the_excess_rate_can_be_below_the_committed_rate() {
    let start = clock::now();
    let mut meter = Meter::new(excess(2000, 1000, 1000, 1000), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Yellow);
}

#[test]
fn a_yellow_packet_is_never_green_and_pays_only_the_excess_bucket() {
    let start = clock::now();
    let mut meter = Meter::new(single(1, 1000, 500), start);
    assert_eq!(meter.color(start, 500, Color::Yellow), Color::Yellow);
    // The committed bucket is still full, but a yellow packet cannot use it.
    assert_eq!(meter.color(start, 1, Color::Yellow), Color::Red);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
}

#[test]
fn a_red_packet_stays_red_and_pays_nothing() {
    let start = clock::now();
    let mut meter = Meter::new(single(1, 100, 100), start);
    assert_eq!(meter.color(start, 100, Color::Red), Color::Red);
    assert_eq!(meter.color(start, 100, Color::Green), Color::Green);
    assert_eq!(meter.color(start, 100, Color::Green), Color::Yellow);
}

#[test]
fn time_running_backwards_earns_nothing() {
    let earlier = clock::now();
    let start = earlier + Duration::from_secs(1);
    let mut meter = Meter::new(single(1000, 1000, 0), start);
    assert_eq!(meter.color(start, 1000, Color::Green), Color::Green);
    assert_eq!(meter.color(earlier, 1, Color::Green), Color::Red);
    assert_eq!(
        meter.color(start + Duration::from_millis(1), 1, Color::Green),
        Color::Green
    );
}

#[test]
fn combined_retry_deadlines_are_positive_and_do_not_delay_available_tokens() {
    use crate::buckets::Accrual;

    bolero::check!()
        .with_type::<([u64; 2], u32, u8)>()
        .for_each(|(rates, elapsed_ns, tokens)| {
            let rates = rates.map(|r| rate(r.max(1)));
            let elapsed = Duration::from_nanos(u64::from(*elapsed_ns));
            let start = clock::now();
            let now = start + elapsed;
            let mut accruals = rates.map(|r| Accrual::new(r, start));
            for accrual in &mut accruals {
                accrual.earn(now);
            }
            let tokens = u64::from(*tokens);
            let delay = Accrual::until_together(&accruals[0], &accruals[1], tokens);
            if tokens == 0 {
                assert_eq!(delay, Duration::ZERO);
                return;
            }
            assert!(!delay.is_zero());
            let ticks = |r: Rate, t: Duration| {
                t.as_nanos() * u128::from(r.per_second().get()) / 1_000_000_000
            };
            let earned = |after: Duration| {
                rates
                    .iter()
                    .map(|&r| ticks(r, elapsed + after) - ticks(r, elapsed))
                    .sum::<u128>()
            };
            let before = delay.checked_sub(Duration::from_nanos(1)).unwrap();
            assert!(earned(before) < u128::from(tokens));
            if tokens == 1 {
                assert!(earned(delay) >= 1, "retry when the first token arrives");
            }
        });
}

//= https://www.rfc-editor.org/rfc/rfc2697#section-2
//= type=test
//# The CBS and the EBS and are measured in bytes.  The CBS and EBS must
//# be configured so that at least one of them is larger than 0.
#[test]
fn a_profile_needs_a_burst() {
    assert_eq!(
        Profile::new(rate(1), 0, None, 0),
        Err(ProfileError::NoBurst)
    );
    assert_eq!(
        Profile::new(rate(1), 0, Some(rate(1)), 0),
        Err(ProfileError::NoBurst)
    );
    assert!(Profile::new(rate(1), 0, None, 1).is_ok());
    assert!(Profile::new(rate(1), 1, None, 0).is_ok());
}

// Outside a model run, the model checkers' locks cannot be taken.
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
mod leasing {
    use super::*;
    use std::num::NonZeroUsize;

    #[test]
    fn one_worker_leasing_only_what_it_needs_is_the_exact_meter() {
        bolero::check!().with_type::<Scenario>().for_each(|input| {
            let (profile, packets) = scenario(input);
            let start = clock::now();
            let mut literal = Literal::new(profile);
            let mut local = SharedMeter::with_leases(profile, start, |_, _| 1).local();
            for (elapsed, size, color) in packets {
                assert_eq!(
                    local.color(start + elapsed, u64::from(size), color),
                    literal.color(elapsed, u64::from(size), color),
                    "{profile:?} at {elapsed:?} for {size} tokens arriving {color:?}"
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
                let shared = SharedMeter::with_leases(profile, start, |_, _| lease);
                let mut locals: Vec<_> = (0..4).map(|_| shared.local()).collect();
                let (mut green, mut passed) = (0, 0);
                let mut end = Duration::ZERO;
                for (i, (elapsed, size, color)) in packets.into_iter().enumerate() {
                    let worker = usize::from(workers.get(i).copied().unwrap_or(0) % 4);
                    match locals[worker].color(start + elapsed, u64::from(size), color) {
                        Color::Green => green += u64::from(size),
                        Color::Yellow => {}
                        Color::Red => continue,
                    }
                    passed += u64::from(size);
                    end = elapsed;
                }
                let committed = Literal::due(profile.committed_rate(), end);
                let excess = profile
                    .excess_rate()
                    .map_or(0, |eir| Literal::due(eir, end));
                let green_bound = profile.committed_burst() + committed;
                let passed_bound = green_bound + profile.excess_burst() + excess;
                assert!(green <= green_bound, "{green} green of {green_bound}");
                assert!(passed <= passed_bound, "{passed} passed of {passed_bound}");
            });
    }

    #[test]
    fn leases_are_a_slice_of_the_rate_and_never_drain_the_bucket_into_one_worker() {
        let start = clock::now();
        // 100 µs of 10 MB/s is 1000 tokens, and a quarter of the bucket among two workers is 1250.
        let workers = NonZeroUsize::new(2).unwrap();
        let shared = SharedMeter::new(single(10_000_000, 10_000, 1), workers, start);
        let mut local = shared.local();
        assert_eq!(local.color(start, 100, Color::Green), Color::Green);
        assert_eq!(local.held(), [900, 0]);
        // A small bucket caps the lease instead: a quarter of 2000 among two workers is 250.
        let shared = SharedMeter::new(single(10_000_000, 2000, 1), workers, start);
        let mut local = shared.local();
        assert_eq!(local.color(start, 100, Color::Green), Color::Green);
        assert_eq!(local.held(), [150, 0]);
    }

    /// The excess bucket fills at up to both rates, so its leases are sized on both: a small excess
    /// rate does not send every yellow packet to the shared buckets.
    #[test]
    fn excess_leases_count_the_committed_overflow() {
        let start = clock::now();
        let workers = NonZeroUsize::MIN;
        let shared = SharedMeter::new(excess(10_000_000, 1, 1, 1_000_000), workers, start);
        let mut local = shared.local();
        assert_eq!(local.color(start, 100, Color::Yellow), Color::Yellow);
        // 100 µs of 10 MB/s and 1 B/s is 1000 tokens.
        assert_eq!(local.held(), [0, 900]);
    }
}

/// Workers coloring at the same instant share the committed burst between them: every token ends up
/// spent on a green packet, held by a worker, or still in the shared bucket, and in exactly one place.
#[concurrency::test]
fn workers_spend_each_token_once() {
    use concurrency::sync::Arc;
    use concurrency::thread;

    const BURST: u64 = 1000;
    const PACKET: u64 = 100;
    let start = clock::now();
    let shared = Arc::new(SharedMeter::with_leases(
        single(1, BURST, 0),
        start,
        |_, _| 300,
    ));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let mut local = shared.local();
                let green = (0..4)
                    .filter(|_| local.color(start, PACKET, Color::Green) == Color::Green)
                    .count();
                (u64::try_from(green).unwrap() * PACKET, local.held())
            })
        })
        .collect();
    let mut accounted = 0;
    for worker in workers {
        let (green, held) = worker.join().unwrap();
        accounted += green + held[0];
    }
    accounted += shared.tokens()[0];
    assert_eq!(accounted, BURST);
}

#[test]
fn profiles_render_what_they_allow() {
    assert_eq!(
        excess(1000, 1500, 500, 3000).to_string(),
        "cir 1000/s cbs 1500 eir 500/s ebs 3000"
    );
    assert_eq!(single(10, 5, 0).to_string(), "cir 10/s cbs 5 ebs 0");
}
