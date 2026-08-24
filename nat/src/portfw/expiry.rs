// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port-forwarding flow expiry, on a clock the test drives.
//!
//! The same three dispositions `masquerade::expiry` covers, asked of the other direction. What
//! differs is what expiry *means* here: a masquerade flow that expires costs the tenant a
//! connection, while a port-forwarding flow that expires and is then re-established has to arrive at
//! the same backend, because the published tuple is a service address rather than an ephemeral one.
//!
//! Port forwarding takes its lifetime from the expose's idle timeout, which the generator draws as
//! absent, five seconds or five minutes -- so a property that wants an expiry has to outrun the
//! longest of them. That costs nothing on a virtual clock and would cost five minutes per case on a
//! real one, which is the whole reason this file can exist.

#![cfg(test)]

use crate::portfw::PortForwarder;
use crate::portfw::probe::{Arrival, Fabric, PAST_ANY_TIMEOUT, run};
use crate::static_nat::probe::build;
use clock::Duration;
use clock::virtual_time::advance;
use config::external::overlay::vpcpeering::VpcExpose;
use flow_entry::flow_table::FlowLookup;
use lpm::prefix::{L4Protocol, PrefixWithOptionalPorts};
use std::net::IpAddr;

/// Comfortably inside every timeout the generator draws.
const WITHIN_LIFETIME: Duration = Duration::from_secs(1);

/// A runtime whose clock starts paused and only moves when a property says so.
///
/// Thin, now that [`clock::virtual_time`] owns the shape. What it adds beyond `block_on` is the
/// part a local copy kept getting wrong: `Paused` refuses a *second* clock, and while it is alive a
/// clock read from a thread that never entered the runtime panics instead of quietly answering an
/// hour behind.
fn with_paused_clock<F: Future<Output = ()>>(body: impl FnOnce() -> F) {
    clock::virtual_time::Paused::new().block_on(body());
}

/// One fixed rule: `172.16.0.0/30` ports 8000-8003 published to `10.0.0.0/30` ports 9000-9003.
///
/// Fixed rather than generated. Expiry is about time, and a drawn shape would only add variance to
/// a property whose subject is the clock.
fn fabric() -> Fabric {
    let expose = VpcExpose::empty()
        .make_port_forwarding(Some(Duration::from_secs(5)), Some(L4Protocol::Tcp))
        .unwrap_or_else(|e| unreachable!("{e}"))
        .ip(PrefixWithOptionalPorts::new(
            "10.0.0.0/30".parse().unwrap_or_else(|_| unreachable!()),
            Some(lpm::prefix::PortRange::new(9000, 9003).unwrap_or_else(|_| unreachable!())),
        ))
        .as_range(PrefixWithOptionalPorts::new(
            "172.16.0.0/30".parse().unwrap_or_else(|_| unreachable!()),
            Some(lpm::prefix::PortRange::new(8000, 8003).unwrap_or_else(|_| unreachable!())),
        ))
        .unwrap_or_else(|e| unreachable!("{e}"));
    Fabric::build(&[expose]).unwrap_or_else(|| unreachable!("a fixed expose builds"))
}

/// Send one inbound packet to a published tuple and report where it was forwarded.
fn forward(
    lookup: &mut FlowLookup,
    pfw: &mut PortForwarder,
    peer: IpAddr,
    published: (IpAddr, u16),
) -> Option<(IpAddr, u16)> {
    let mut packet = build(peer, published.0, true, 1234, published.1);
    Arrival::inbound().stamp(&mut packet);
    let out = run(lookup, pfw, vec![packet], Arrival::inbound().dst_vpcd);
    if out[0].is_done() {
        return None;
    }
    let addr = out[0].ip_destination()?;
    let port = out[0].transport_dst_port()?.get();
    ((addr, port) != published).then_some((addr, port))
}

/// A published service keeps working while time passes.
///
/// The **preserved** disposition. A port-forwarding rule is configuration, not state: it does not
/// expire, and a service that stopped answering merely because time passed would be an outage with
/// no configuration change behind it.
#[test]
fn a_published_service_answers_while_time_passes() {
    with_paused_clock(|| async {
        let fabric = fabric();
        let (mut lookup, mut pfw) = fabric.stages();
        let peer = fabric.peer[0];
        let published = (
            "172.16.0.1"
                .parse::<IpAddr>()
                .unwrap_or_else(|_| unreachable!()),
            8001,
        );

        for step in 0..6 {
            assert!(
                forward(&mut lookup, &mut pfw, peer, published).is_some(),
                "the published service stopped answering at step {step}"
            );
            advance(WITHIN_LIFETIME).await;
        }
    });
}

/// A service re-established after its flow expires reaches the same backend.
///
/// The **never resurrected** disposition, in the form port forwarding needs. The flow carrying the
/// translation is state and does expire; the rule that produced it is configuration and does not. So
/// a client returning after an idle period must land where it landed before -- a published address
/// that moved between connections is a service that silently changed identity.
///
/// Three epochs, and the middle one is longer than any timeout the configuration can name. That is
/// exactly the shape the clock facade was built for: unwritable while deadlines came from the wall
/// clock, and free now.
#[test]
fn a_service_re_established_after_expiry_reaches_the_same_backend() {
    with_paused_clock(|| async {
        let fabric = fabric();
        let (mut lookup, mut pfw) = fabric.stages();
        let peer = fabric.peer[0];
        let published = (
            "172.16.0.2"
                .parse::<IpAddr>()
                .unwrap_or_else(|_| unreachable!()),
            8002,
        );

        let first = forward(&mut lookup, &mut pfw, peer, published)
            .unwrap_or_else(|| unreachable!("a published tuple is forwarded"));

        advance(PAST_ANY_TIMEOUT).await;

        let again = forward(&mut lookup, &mut pfw, peer, published).unwrap_or_else(|| {
            unreachable!(
                "a published service could not be reached after its flow expired; the rule is \
                 configuration and does not expire with the flow"
            )
        });

        assert_eq!(
            first, again,
            "{published:?} reached {first:?} and then, after its flow expired, {again:?}; a \
             published address moved between connections"
        );
    });
}

/// Every published tuple still maps somewhere distinct after an expiry.
///
/// The reason to check more than one: an expiry that dropped shared state could leave the rule
/// intact while the *mapping* it produces collapses, which one tuple on its own cannot show.
#[test]
fn published_tuples_stay_distinct_across_an_expiry() {
    with_paused_clock(|| async {
        let fabric = fabric();
        let (mut lookup, mut pfw) = fabric.stages();
        let peer = fabric.peer[0];

        let published: Vec<(IpAddr, u16)> = (0..4u8)
            .map(|i| {
                (
                    format!("172.16.0.{i}")
                        .parse::<IpAddr>()
                        .unwrap_or_else(|_| unreachable!()),
                    8000 + u16::from(i),
                )
            })
            .collect();

        let before: Vec<_> = published
            .iter()
            .map(|p| forward(&mut lookup, &mut pfw, peer, *p))
            .collect();

        advance(PAST_ANY_TIMEOUT).await;

        let after: Vec<_> = published
            .iter()
            .map(|p| forward(&mut lookup, &mut pfw, peer, *p))
            .collect();

        assert_eq!(
            before, after,
            "the mapping from published tuples to backends changed across an expiry"
        );
        let distinct: std::collections::BTreeSet<_> = after.iter().flatten().collect();
        assert_eq!(
            distinct.len(),
            after.iter().flatten().count(),
            "two published tuples share a backend after an expiry: {after:?}"
        );
    });
}
