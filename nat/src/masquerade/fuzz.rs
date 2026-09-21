// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::Masquerade;
use crate::masquerade::probe::{Arrival, Fabric, Probe, ProbeSpec, Stray, run};
use bolero::{Driver, TypeGenerator, ValueGenerator};
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use config::external::overlay::vpcpeering::contract::MasqueradeExposes;
use config::external::overlay::vpcpeering::{MappingPolicy, VpcExpose, VpcExposeNatConfig};
use flow_entry::flow_table::FlowLookup;
use net::buffer::TestBuffer;
use net::packet::Packet;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZero;
use std::ops::Bound::Included;

const MAX_EXPOSES: u8 = 3;

const PROBES: usize = 8;

const TEST_TIME: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
struct Scenario {
    strays: bool,
}

impl ValueGenerator for Scenario {
    type Output = (Vec<VpcExpose>, Vec<ProbeSpec>);

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let policy = generate_policy(driver)?;
        let exposes = stamp_policy(MasqueradeExposes(MAX_EXPOSES).generate(driver)?, policy);

        let mut probes = Vec::with_capacity(PROBES);
        for _ in 0..PROBES {
            let mut probe = ProbeSpec::generate(driver)?;
            if !self.strays {
                probe.clear_stray();
            }
            probes.push(probe);
        }
        Some((exposes, probes))
    }
}

fn generate_policy<D: Driver>(driver: &mut D) -> Option<MappingPolicy> {
    Some(match driver.gen_u8(Included(&0), Included(&2))? {
        0 => MappingPolicy::EndpointIndependent,
        1 => MappingPolicy::AddressDependent,
        _ => MappingPolicy::AddressAndPortDependent,
    })
}

// Overwrite every generated expose's mapping policy with the provided policy
fn stamp_policy(mut exposes: Vec<VpcExpose>, policy: MappingPolicy) -> Vec<VpcExpose> {
    for expose in &mut exposes {
        if let Some(nat) = expose.nat.as_mut()
            && let VpcExposeNatConfig::Masquerade(masquerade) = &mut nat.config
        {
            masquerade.mapping_policy = policy;
        }
    }
    exposes
}

// Like Scenario, but hands the chosen policy back to the caller instead of only stamping it in
#[derive(Debug, Clone, Copy)]
struct PolicyScenario;

impl ValueGenerator for PolicyScenario {
    type Output = (Vec<VpcExpose>, Vec<ProbeSpec>, MappingPolicy);

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let policy = generate_policy(driver)?;
        let exposes = stamp_policy(MasqueradeExposes(MAX_EXPOSES).generate(driver)?, policy);

        let mut probes = Vec::with_capacity(PROBES);
        for _ in 0..PROBES {
            let mut probe = ProbeSpec::generate(driver)?;
            probe.clear_stray();
            probes.push(probe);
        }
        Some((exposes, probes, policy))
    }
}

fn with_runtime(body: impl FnOnce()) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"));
    let _guard = runtime.enter();
    body();
}

fn settled(body: impl FnOnce()) {
    const PAST_ANY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(30);
    const GIVE_UP: usize = 4096;
    thread_local! {
        static CLOCK: clock::virtual_time::Paused = clock::virtual_time::Paused::new();
    }
    CLOCK.with(|clock| {
        clock.block_on(async {
            body();
            clock::virtual_time::advance(PAST_ANY_TIMEOUT).await;
            let handle = tokio::runtime::Handle::current();
            for _ in 0..GIVE_UP {
                if handle.metrics().num_alive_tasks() == 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!(
                "{} tasks from this case would not retire; the flow tables they hold will \
                 accumulate until the run is out of memory",
                handle.metrics().num_alive_tasks()
            );
        });
    });
}

fn fabric(exposes: &[VpcExpose]) -> Option<Fabric> {
    let fabric = Fabric::build(exposes)?;
    fabric.is_probeable().then_some(fabric)
}

fn source_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_source()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_src_port().map_or(0, NonZero::get),
    )
}

fn destination_of(packet: &Packet<TestBuffer>) -> (IpAddr, u16) {
    (
        packet
            .ip_destination()
            .unwrap_or_else(|| unreachable!("a probe is always an ip packet")),
        packet.transport_dst_port().map_or(0, NonZero::get),
    )
}

/// Whether this run saw enough to judge the ratios below, or only to print them.
///
/// Three kinds of run are too small, and they are not interchangeable:
///
///   - **instrumentation.** A coverage run of these properties got through a
///     single configuration. The ratios then measure the build, not the property.
///   - **emulation.** miri and qemu-user see roughly two orders of magnitude
///     fewer cases; the same stand-down appears in `clock` and in the config
///     algebra's completeness table.
///   - **a corpus replay.** bolero runs exactly the inputs it is handed, so
///     `BOLERO_RANDOM_ITERATIONS=0` over one saved entry is *one case*. An
///     aggregate rate over one case reports how that case happened to fall --
///     and that is precisely the run a developer makes to confirm a fix, so
///     failing it there is worse than not checking at all.
///
/// The floor separates the last of those from a real campaign. It has to sit
/// below what the smallest honest run reaches, which is why it is measured
/// rather than picked.
///
/// Measured natively 2026-09-06: 12 to 28 configurations per property, against
/// 1060 to 2863 for the static-NAT twin. The difference is the cost of a case
/// here -- a flow table and the timers that go with it -- and not, as an earlier
/// version of this comment guessed, anything about how the runtime is driven: the
/// counts are the same either side of the commit that changed that.
///
/// The floor is therefore *two*, not a fraction of the measured run. A CI runner
/// at a third of this machine's throughput would sit under any floor calibrated
/// on the numbers above, and a guard that stands down everywhere it runs is worse
/// than no guard. Two is the smallest sample a rate can be computed from at all,
/// which is exactly the corpus-replay case and nothing else. The ratio is the
/// part that carries meaning -- see the commit that removed the previous absolute
/// floor for why a bigger number measures the machine rather than the property.
fn judged(built: usize) -> bool {
    /// One case cannot support a rate; anything above that, the ratios can speak to.
    const ENOUGH_CONFIGURATIONS: usize = 2;
    !cfg!(instrumented) && !cfg!(emulated) && !cfg!(sanitized) && built >= ENOUGH_CONFIGURATIONS
}

const ENOUGH_TO_RATE: usize = 25;

#[derive(Default)]
struct Tally {
    seen: AtomicUsize,
    built: AtomicUsize,
    reached: AtomicUsize,
}

impl Tally {
    fn report(&self, what: &str) {
        let (seen, built, reached) = (
            self.seen.load(Ordering::Relaxed),
            self.built.load(Ordering::Relaxed),
            self.reached.load(Ordering::Relaxed),
        );
        if seen == 0 {
            return;
        }
        println!("{what}: {built}/{seen} configurations built, {reached} flows reached it");
        if !judged(built) {
            println!("  {what}: not judged -- {built} configurations is too small a sample");
            return;
        }
        assert!(
            built * 2 >= seen,
            "only {built} of {seen} configurations built, so this checked much less than it looks \
             like it did"
        );
        assert!(
            reached > 0,
            "no flow reached the {what} assertion in {built} configurations; this property \
             held trivially"
        );
        if built < ENOUGH_TO_RATE {
            println!(
                "  {what}: {built} configurations is too small a sample to judge the yield \
                 rate; only the nonzero check ran"
            );
            return;
        }
        assert!(
            reached * 4 >= built,
            "{reached} flows reached the {what} assertion across {built} configurations; \
             this property has gone vacuous"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn a_masqueraded_flow_comes_back() {
    let tally = Tally::default();

    bolero::check!()
        .with_test_time(TEST_TIME)
        .with_generator(Scenario { strays: false })
        .cloned()
        .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            settled(|| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut masq) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let before = (probe.source, probe.sport);
                    let out = run(
                        &mut lookup,
                        &mut masq,
                        vec![probe.packet()],
                        probe.arrival.dst_vpcd,
                    );
                    let after = source_of(&out[0]);
                    if after == before || out[0].is_done() {
                        continue;
                    }

                    let back = run(
                        &mut lookup,
                        &mut masq,
                        vec![probe.reply(after.0, after.1)],
                        Arrival::inbound().dst_vpcd,
                    );
                    assert_eq!(
                        destination_of(&back[0]),
                        before,
                        "{:?} was masqueraded to {after:?}, and the reply came back to {:?}",
                        before,
                        destination_of(&back[0])
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
        });
    tally.report("reversibility");
}

#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn a_flow_keeps_its_translation() {
    let tally = Tally::default();

    bolero::check!()
        .with_test_time(TEST_TIME)
    .with_generator(Scenario { strays: false })
    .cloned()
    .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| settled(||     {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                let before = (probe.source, probe.sport);
                let first = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if out_unchanged(&first, before) {
                    continue;
                }
                let second = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);

                assert_eq!(
                    source_of(&second[0]),
                    source_of(&first[0]),
                    "the same flow from {before:?} was given {:?} and then {:?}, so its reply can \
                     only reach one of them",
                    source_of(&first[0]),
                    source_of(&second[0])
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        }));
    tally.report("stability");
}

fn out_unchanged(out: &[Packet<TestBuffer>], before: (IpAddr, u16)) -> bool {
    out[0].is_done() || source_of(&out[0]) == before
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
//= type=test
//# REQ-2:  It is RECOMMENDED that a NAT have an "IP address pooling"
//# behavior of "Paired".
#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn an_internal_endpoint_keeps_one_public_address() {
    let tally = Tally::default();

    bolero::check!()
    .with_generator(Scenario { strays: false })
    .cloned()
    .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| settled(||     {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                let before = (probe.source, probe.sport);
                let first = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if out_unchanged(&first, before) {
                    continue;
                }

                let mut elsewhere = (*spec).resolve(&fabric);
                elsewhere.dport = elsewhere.dport.wrapping_add(1).max(1);
                if let Some(other) = fabric.peer.iter().find(|a| **a != probe.destination) {
                    elsewhere.destination = *other;
                }
                if (elsewhere.destination, elsewhere.dport) == (probe.destination, probe.dport) {
                    continue;
                }

                let second = run(
                    &mut lookup,
                    &mut masq,
                    vec![elsewhere.packet()],
                    elsewhere.arrival.dst_vpcd,
                );
                if out_unchanged(&second, before) {
                    continue;
                }

                assert_eq!(
                    source_of(&second[0]).0,
                    source_of(&first[0]).0,
                    "{before:?} was given {:?} talking to {:?} and {:?} talking to {:?}, so the \
                     public address it is given depends on who it is addressing",
                    source_of(&first[0]),
                    (probe.destination, probe.dport),
                    source_of(&second[0]),
                    (elsewhere.destination, elsewhere.dport)
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        }));
    tally.report("address pairing");
}

// Independent restatement of RFC 4787 4.1's X1':x1'=X2':x2' definition
fn should_reuse(
    policy: MappingPolicy,
    before_dst: (IpAddr, u16),
    after_dst: (IpAddr, u16),
) -> bool {
    match policy {
        MappingPolicy::EndpointIndependent => true,
        MappingPolicy::AddressDependent => before_dst.0 == after_dst.0,
        MappingPolicy::AddressAndPortDependent => before_dst == after_dst,
    }
}

// Send "elsewhere" on the same flow that produced "before"/"before_tuple", and check that whether
// the public tuple is reused matches what the policy says it should be
#[allow(clippy::too_many_arguments)]
fn check_policy_scoped_reuse(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    elsewhere: &Probe,
    before: (IpAddr, u16),
    before_tuple: (IpAddr, u16),
    before_dst: (IpAddr, u16),
    policy: MappingPolicy,
    tally: &Tally,
) {
    let second = run(
        lookup,
        masq,
        vec![elsewhere.packet()],
        elsewhere.arrival.dst_vpcd,
    );
    if out_unchanged(&second, before) {
        return;
    }
    let after_tuple = source_of(&second[0]);
    let after_dst = (elsewhere.destination, elsewhere.dport);
    if after_dst == before_dst {
        return;
    }

    let expected_reuse = should_reuse(policy, before_dst, after_dst);
    let actual_reuse = after_tuple == before_tuple;
    assert_eq!(
        expected_reuse, actual_reuse,
        "under {policy:?}, {before:?} talking to {before_dst:?} got {before_tuple:?}, and talking to {after_dst:?} got {after_tuple:?}; \
         reuse should have been {expected_reuse}"
    );
    tally.reached.fetch_add(1, Ordering::Relaxed);
}

//= https://www.rfc-editor.org/rfc/rfc4787#section-4.1
//= type=test
//# REQ-1:  A NAT MUST have an "Endpoint-Independent Mapping" behavior.
#[test]
#[cfg_attr(miri, ignore = "one configuration is ~15 min under miri")]
fn mapping_reuse_matches_the_configured_policy() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
            .with_generator(PolicyScenario)
            .cloned()
            .for_each(
                |(exposes, probes, policy): (Vec<VpcExpose>, Vec<ProbeSpec>, MappingPolicy)| {
                    tally.seen.fetch_add(1, Ordering::Relaxed);
                    let Some(fabric) = fabric(&exposes) else {
                        return;
                    };
                    tally.built.fetch_add(1, Ordering::Relaxed);
                    let (mut lookup, mut masq) = fabric.stages();

                    for spec in &probes {
                        let probe = (*spec).resolve(&fabric);
                        let before = (probe.source, probe.sport);
                        let first = run(
                            &mut lookup,
                            &mut masq,
                            vec![probe.packet()],
                            probe.arrival.dst_vpcd,
                        );
                        if out_unchanged(&first, before) {
                            continue;
                        }
                        let before_tuple = source_of(&first[0]);
                        let before_dst = (probe.destination, probe.dport);

                        // Same destination address, different port: separates ADM (must reuse)
                        // from APDM (must not).
                        let mut same_addr = (*spec).resolve(&fabric);
                        same_addr.dport = same_addr.dport.wrapping_add(1).max(1);
                        check_policy_scoped_reuse(
                            &mut lookup,
                            &mut masq,
                            &same_addr,
                            before,
                            before_tuple,
                            before_dst,
                            policy,
                            &tally,
                        );

                        // A genuinely different destination address: EIM must still reuse; ADM and
                        // APDM must not.
                        if let Some(other) = fabric.peer.iter().find(|a| **a != probe.destination) {
                            let mut other_addr = (*spec).resolve(&fabric);
                            other_addr.destination = *other;
                            check_policy_scoped_reuse(
                                &mut lookup,
                                &mut masq,
                                &other_addr,
                                before,
                                before_tuple,
                                before_dst,
                                policy,
                                &tally,
                            );
                        }
                    }
                },
            );
    });

    tally.report("policy-scoped reuse");
}

// A generated configuration plus the policy a later config update switches it to
#[derive(Debug, Clone, Copy)]
struct MigrationScenario;

impl ValueGenerator for MigrationScenario {
    type Output = (Vec<VpcExpose>, Vec<ProbeSpec>, MappingPolicy);

    fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let (exposes, probes, _) = PolicyScenario.generate(driver)?;
        Some((exposes, probes, generate_policy(driver)?))
    }
}

// No config update may leave two live private endpoints sharing one public tuple.
//
// A flow is carried across a migration only when the replacement allocator reserves the tuple it is
// still translating to. If one were carried without that reservation, the allocator would consider
// the tuple free and hand it to the next endpoint that asks; so this drives fresh allocations after
// the update and checks that none of them lands on a tuple a carried flow is still using.
#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn a_config_update_never_leaves_two_flows_on_one_tuple() {
    let tally = Tally::default();

    with_runtime(|| {
        bolero::check!()
        .with_test_time(TEST_TIME)
        .with_generator(MigrationScenario)
        .cloned()
        .for_each(|(exposes, probes, next): (Vec<VpcExpose>, Vec<ProbeSpec>, MappingPolicy)| {
            // One source port for every probe, so probes from the same private address toward
            // different peers share a private tuple. That is the case a policy change re-keys:
            // under Address-Dependent Mapping they hold distinct mappings, and switching to
            // Endpoint-Independent merges them onto one.
            const SHARED_SPORT: u16 = 1024;

            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(mut fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);

            {
                let (mut lookup, mut masq) = fabric.stages();
                for spec in &probes {
                    let mut probe = (*spec).resolve(&fabric);
                    probe.sport = SHARED_SPORT;
                    run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                }
            }

            if !fabric.reconfigure(&stamp_policy(exposes, next), 2) {
                return;
            }

            // Everything the flow table still translates after the update, plus everything the
            // replacement allocator hands out afterwards, has to stay one-to-one.
            let (mut lookup, mut masq) = fabric.stages();
            let mut taken: BTreeMap<(IpAddr, u16), (IpAddr, u16)> = BTreeMap::new();
            // Returns whether it actually reached the assertion
            let mut record = |before: (IpAddr, u16), out: &[Packet<TestBuffer>]| -> bool {
                if out_unchanged(out, before) {
                    return false;
                }
                let after = source_of(&out[0]);
                if let Some(previous) = taken.insert(after, before) {
                    assert_eq!(
                        previous, before,
                        "after a config update, flows from {previous:?} and {before:?} are both masqueraded to {after:?}, \
                         so a reply can only reach one of them"
                    );
                }
                true
            };

            for spec in &probes {
                let mut probe = (*spec).resolve(&fabric);
                probe.sport = SHARED_SPORT;
                let before = (probe.source, probe.sport);
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if record(before, &out) {
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Fresh endpoints, drawing from whatever the replacement allocator believes is free
            for (index, spec) in probes.iter().enumerate() {
                let mut probe = (*spec).resolve(&fabric);
                probe.sport = u16::try_from(40000 + index).unwrap_or(40000);
                let before = (probe.source, probe.sport);
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if record(before, &out) {
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    });

    tally.report("migration exclusivity");
}

//= https://www.rfc-editor.org/rfc/rfc5382#section-7.1
//= type=test
//# REQ-7:  A NAT MUST NOT have a "Port assignment" behavior of "Port
//# overloading" for TCP.
//= https://www.rfc-editor.org/rfc/rfc4787#section-4.2.1
//= type=test
//# REQ-3:  A NAT MUST NOT have a "Port assignment" behavior of "Port
//# overloading".
#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn distinct_flows_do_not_share_a_translation() {
    let tally = Tally::default();

    bolero::check!()
        .with_test_time(TEST_TIME)
    .with_generator(Scenario { strays: false })
    .cloned()
    .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| settled(||     {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let (mut lookup, mut masq) = fabric.stages();

            let mut taken: BTreeMap<(IpAddr, u16), (IpAddr, u16)> = BTreeMap::new();
            for (index, spec) in probes.iter().enumerate() {
                let mut probe = (*spec).resolve(&fabric);
                probe.sport = u16::try_from(1024 + index).unwrap_or(1024);
                let before = (probe.source, probe.sport);
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                if out_unchanged(&out, before) {
                    continue;
                }
                let after = source_of(&out[0]);

                if let Some(previous) = taken.insert(after, before) {
                    assert_eq!(
                        previous, before,
                        "flows from {previous:?} and {before:?} were both masqueraded to {after:?}, \
                         so a reply can only reach one of them"
                    );
                }
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        }));
    tally.report("exclusivity");
}

#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn a_translation_stays_inside_the_public_range() {
    let tally = Tally::default();

    bolero::check!()
        .with_test_time(TEST_TIME)
        .with_generator(Scenario { strays: false })
        .cloned()
        .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| {
            settled(|| {
                tally.seen.fetch_add(1, Ordering::Relaxed);
                let Some(fabric) = fabric(&exposes) else {
                    return;
                };
                tally.built.fetch_add(1, Ordering::Relaxed);
                let (mut lookup, mut masq) = fabric.stages();

                for spec in &probes {
                    let probe = (*spec).resolve(&fabric);
                    let before = (probe.source, probe.sport);
                    let out = run(
                        &mut lookup,
                        &mut masq,
                        vec![probe.packet()],
                        probe.arrival.dst_vpcd,
                    );
                    if out_unchanged(&out, before) {
                        continue;
                    }
                    let (addr, port) = source_of(&out[0]);

                    assert!(
                        fabric.is_public(addr),
                        "{before:?} was masqueraded to {addr}:{port}, which no expose offers; the \
                     fabric has no route back to it"
                    );
                    tally.reached.fetch_add(1, Ordering::Relaxed);
                }
            });
        });
    tally.report("containment");
}

#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn nothing_is_masqueraded_without_permission() {
    let tally = Tally::default();

    bolero::check!()
        .with_test_time(TEST_TIME)
    .with_generator(Scenario { strays: true })
    .cloned()
    .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| settled(||     {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                if probe.asks_for_translation() && probe.exposed {
                    continue;
                }
                let before = (probe.source, probe.sport);
                let (stray, arrival) = (probe.stray, probe.arrival);
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);

                if out[0].is_done() {
                    // Not `reached`: a dropped packet never gets as far as the
                    // assertion below, so counting it here would let the vacuity
                    // guard be satisfied entirely by packets that checked nothing.
                    // `exclusivity` above is the shape to copy -- count past the
                    // assert, never before it.
                    continue;
                }
                assert_eq!(
                    source_of(&out[0]),
                    before,
                    "masquerade translated {before:?} although {stray:?} forbade it; the packet \
                     arrived as {arrival:?}"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        }));
    tally.report("permission");
}

#[test]
#[cfg_attr(miri, ignore = "full-flow fuzz probe is too slow under Miri")]
fn a_flow_that_cannot_be_masqueraded_says_so() {
    let tally = Tally::default();

    bolero::check!()
        .with_test_time(TEST_TIME)
    .with_generator(Scenario { strays: true })
    .cloned()
    .for_each(|(exposes, probes): (Vec<VpcExpose>, Vec<ProbeSpec>)| settled(||     {
            tally.seen.fetch_add(1, Ordering::Relaxed);
            let Some(fabric) = fabric(&exposes) else {
                return;
            };
            tally.built.fetch_add(1, Ordering::Relaxed);
            let (mut lookup, mut masq) = fabric.stages();

            for spec in &probes {
                let probe = (*spec).resolve(&fabric);
                let unplaceable = matches!(
                    probe.stray,
                    Some(Stray::SourceNotExposed | Stray::UnknownSourceVni | Stray::UnknownDestVni)
                );
                if !unplaceable {
                    continue;
                }
                let before = (probe.source, probe.sport);
                let stray = probe.stray;
                let out = run(&mut lookup, &mut masq, vec![probe.packet()], probe.arrival.dst_vpcd);
                let packet = &out[0];

                assert!(
                    packet.is_done(),
                    "a flow from {before:?} with {stray:?} passed masquerade with no verdict, so \
                     a private address reaches the fabric untranslated"
                );
                tally.reached.fetch_add(1, Ordering::Relaxed);
            }
        }));
    tally.report("attribution");
}
