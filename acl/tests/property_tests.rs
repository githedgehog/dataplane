// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for ACL classification.
//!
//! Uses bolero to generate random rule sets and verify that the opaque
//! `Classifier` produces identical results to the reference
//! `LinearClassifier` on all generated inputs.

#![allow(clippy::unwrap_used)]

use dataplane_acl::{AclRule, AclTableBuilder, Fate};
use net::headers::builder::HeaderStack;
use net::ipv4::UnicastIpv4Addr;
use net::tcp::port::TcpPort;
use std::net::Ipv4Addr;

/// Build a set of test headers to classify against.
/// These are fixed "probe packets" that exercise different match paths.
fn probe_packets() -> Vec<net::headers::Headers> {
    let ips = [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ];
    let ports = [1u16, 22, 80, 443, 8080, 65535];

    let mut packets = Vec::new();
    for ip in &ips {
        for port in &ports {
            if let (Ok(uip), Ok(tp)) = (
                UnicastIpv4Addr::new(*ip),
                TcpPort::new_checked(*port),
            ) {
                if let Ok(headers) = HeaderStack::new()
                    .eth(|_| {})
                    .ipv4(|h| { h.set_source(uip); })
                    .tcp(|h| { h.set_destination(tp); })
                    .build_headers()
                {
                    packets.push(headers);
                }
            }
        }
    }
    packets
}

#[test]
fn compile_matches_linear_on_random_rules() {
    let packets = probe_packets();

    bolero::check!()
        .with_type::<Vec<AclRule<()>>>()
        .for_each(|rules: &Vec<AclRule<()>>| {
            if rules.is_empty() {
                return;
            }

            // Build table from generated rules.
            // Use unique priorities — if there are duplicates, the table
            // may behave unpredictably.  Deduplicate by priority.
            let mut seen = std::collections::HashSet::new();
            let mut builder = AclTableBuilder::new(Fate::Drop);
            for rule in rules {
                if seen.insert(rule.priority()) {
                    builder.push_rule(rule.clone());
                }
            }
            let table = builder.build();

            let opaque = table.compile();
            let linear = table.compile_linear();

            for pkt in &packets {
                let opaque_fate = opaque.classify(pkt).fate();
                let linear_fate = linear.classify(pkt).fate();
                assert_eq!(
                    opaque_fate, linear_fate,
                    "opaque vs linear mismatch on generated table with {} rules",
                    table.rules().len()
                );
            }
        });
}
