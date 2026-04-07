// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Basic ACL classification examples.
//!
//! These examples demonstrate the core API for building ACL rules,
//! compiling them, and classifying packets.  They use the software
//! linear-scan classifier (no DPDK required).
//!
//! Run with: `cargo run --example basic_classification -p dataplane-acl-dpdk`

use std::net::Ipv4Addr;

use acl::{
    AclRuleBuilder, AclTableBuilder, ActionSequence, Fate, FieldMatch,
    IpPrefix, Ipv4Prefix, Priority, Step,
};
use net::headers::builder::HeaderStack;

fn main() {
    simple_permit_deny();
    port_range_matching();
    action_metadata();
    mixed_protocols();
}

/// Example 1: Simple permit/deny rules.
///
/// A firewall that allows HTTP traffic from 10.0.0.0/8 and
/// drops everything else.
fn simple_permit_deny() {
    println!("=== Example 1: Simple permit/deny ===");

    // Build the rule table.  Rules are evaluated in priority order
    // (lower number = higher precedence).  Default fate applies
    // when no rule matches.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            // Permit HTTP from the 10.0.0.0/8 network.
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80..=80);
                })
                .permit(Priority::new(100).unwrap()),
        )
        .build();

    // Compile to a classifier.  This sorts rules by priority and
    // builds the internal lookup structure.
    let classifier = table.compile();

    // Classify packets.  Each call returns the fate of the
    // highest-priority matching rule, or the default (Drop).
    let allowed = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
            );
        })
        .tcp(|tcp| {
            tcp.set_destination(net::tcp::port::TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    let blocked = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap(),
            );
        })
        .tcp(|tcp| {
            tcp.set_destination(net::tcp::port::TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    // No metadata — pass &() for the trivial metadata type.
    println!("  10.1.2.3:80  → {:?}", classifier.classify(&allowed, &()).fate());   // Accept
    println!("  192.168.1.1:80 → {:?}", classifier.classify(&blocked, &()).fate()); // Drop
}

/// Example 2: Port range matching.
///
/// Permit well-known ports (1-1023) from trusted networks,
/// deny high ports, and allow HTTPS specifically from anywhere.
fn port_range_matching() {
    println!("\n=== Example 2: Port ranges ===");

    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            // Permit well-known ports from 10.0.0.0/8.
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(1..=1023);
                })
                .permit(Priority::new(200).unwrap()),
        )
        .add_rule(
            // Permit HTTPS from anywhere (higher priority than above).
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(443..=443);
                })
                .permit(Priority::new(100).unwrap()),
        )
        .build();

    let classifier = table.compile();

    let packets = [
        ("10.0.0.1", 80, "trusted + well-known"),
        ("10.0.0.1", 8080, "trusted + high port"),
        ("8.8.8.8", 443, "untrusted + HTTPS"),
        ("8.8.8.8", 80, "untrusted + HTTP"),
    ];

    for (ip_str, port, label) in &packets {
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|h| {
                if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(ip) {
                    h.set_source(uip);
                }
            })
            .tcp(|tcp| {
                tcp.set_destination(net::tcp::port::TcpPort::new_checked(*port).unwrap());
            })
            .build_headers()
            .unwrap();

        println!("  {label:30} → {:?}", classifier.classify(&pkt, &()).fate());
    }
}

/// Example 3: Action sequences with metadata output.
///
/// Rules can attach metadata to matched packets via Mark, Meta,
/// and Tag steps.  The caller reads these values from the
/// matched action sequence.
fn action_metadata() {
    println!("\n=== Example 3: Action metadata ===");

    // Annotate matching traffic with a VPC identifier (Meta)
    // and a NAT-required flag (Mark).
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .action(
                    ActionSequence::new(
                        vec![
                            Step::Meta(42),       // destination VPC ID
                            Step::Mark(0x01),     // NAT required flag
                        ],
                        Fate::Accept,
                    ),
                    Priority::new(100).unwrap(),
                ),
        )
        .build();

    let classifier = table.compile();

    let pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
            );
        })
        .tcp(|tcp| {
            tcp.set_destination(net::tcp::port::TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    let outcome = classifier.classify(&pkt, &());

    // The caller inspects the matched action sequence to extract
    // metadata.  Accessor methods provide convenient access to
    // the first value of each type.
    if let acl::ClassifyOutcome::Matched(seq) = outcome {
        println!("  Fate:     {:?}", seq.fate());
        println!("  VPC (Meta): {:?}", seq.meta());       // Some(42)
        println!("  NAT (Mark): {:?}", seq.mark());       // Some(1)
        println!("  Flag:     {}", seq.flag());            // false
        println!("  Tag(0):   {:?}", seq.tag(0));          // None
    }
}

/// Example 4: Mixed protocol rules.
///
/// Rules with different protocol layers (TCP, UDP, IP-only)
/// coexist in the same table.  The classifier handles them
/// transparently — no manual signature grouping required.
fn mixed_protocols() {
    println!("\n=== Example 4: Mixed protocols ===");

    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            // Permit HTTP (TCP:80)
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80..=80);
                })
                .permit(Priority::new(100).unwrap()),
        )
        .add_rule(
            // Permit DNS (UDP:53)
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .udp(|udp| {
                    udp.dst = FieldMatch::Select(53..=53);
                })
                .permit(Priority::new(200).unwrap()),
        )
        .add_rule(
            // Permit all traffic from management network (any protocol).
            // This is an IPv4-only rule — no transport layer constraint.
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                    );
                })
                .permit(Priority::new(50).unwrap()), // highest precedence
        )
        .build();

    let classifier = table.compile();

    let test_cases: Vec<(&str, Box<dyn Fn() -> net::headers::Headers>)> = vec![
        ("TCP:80 from 10.x", Box::new(|| {
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| { ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap()); })
                .tcp(|tcp| { tcp.set_destination(net::tcp::port::TcpPort::new_checked(80).unwrap()); })
                .build_headers().unwrap()
        })),
        ("UDP:53 from 10.x", Box::new(|| {
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| { ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap()); })
                .udp(|udp| { udp.set_destination(net::udp::port::UdpPort::new_checked(53).unwrap()); })
                .build_headers().unwrap()
        })),
        ("TCP:8080 from mgmt", Box::new(|| {
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| { ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(172, 16, 1, 1)).unwrap()); })
                .tcp(|tcp| { tcp.set_destination(net::tcp::port::TcpPort::new_checked(8080).unwrap()); })
                .build_headers().unwrap()
        })),
        ("TCP:22 from 8.8.8.8", Box::new(|| {
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| { ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(8, 8, 8, 8)).unwrap()); })
                .tcp(|tcp| { tcp.set_destination(net::tcp::port::TcpPort::new_checked(22).unwrap()); })
                .build_headers().unwrap()
        })),
    ];

    for (label, make_pkt) in &test_cases {
        let pkt = make_pkt();
        println!("  {label:30} → {:?}", classifier.classify(&pkt, &()).fate());
    }
}
