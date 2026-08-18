// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::portfw::PortForwarder;
use crate::portfw::probe::{Arrival, Fabric, PAST_ANY_TIMEOUT, run};
use crate::static_nat::probe::build;
use clock::Duration;
use config::external::overlay::vpcpeering::VpcExpose;
use flow_entry::flow_table::FlowLookup;
use lpm::prefix::{L4Protocol, PrefixWithOptionalPorts};
use std::net::IpAddr;

const WITHIN_LIFETIME: Duration = Duration::from_secs(1);

fn with_paused_clock<F: Future<Output = ()>>(body: impl FnOnce() -> F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"));
    runtime.block_on(body());
}

async fn advance(by: Duration) {
    tokio::time::advance(by).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

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
