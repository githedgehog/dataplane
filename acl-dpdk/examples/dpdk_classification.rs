// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK ACL classification example.
//!
//! Compiles an ACL table to a DPDK ACL trie and classifies packets
//! through it.  Requires EAL initialization.
//!
//! Run with: `cargo run --example dpdk_classification -p dataplane-acl-dpdk`

use std::net::Ipv4Addr;

use acl::{
    AclRuleBuilder, AclTableBuilder, ActionSequence, Fate, FieldMatch,
    IpPrefix, Ipv4Prefix, Priority, Step,
};
use dataplane_acl_dpdk::classifier::DpdkAclClassifier;
use dpdk::eal;
use net::headers::builder::HeaderStack;

fn main() {
    // Initialize the DPDK EAL.  In a real application this happens
    // once at startup.  We use minimal flags for testing.
    let _eal = eal::init(["example", "--no-huge", "--in-memory", "--no-pci"]);

    simple_dpdk_classify();
    mixed_signature_classify();
}

/// Example: compile and classify through DPDK ACL.
///
/// The DpdkAclClassifier hides all DPDK details: field signatures,
/// compact buffer assembly, categories, priority resolution.  The
/// user provides an AclTable and gets a classifier that takes
/// parsed headers.
fn simple_dpdk_classify() {
    println!("=== DPDK ACL: Simple classification ===");

    // Same rule-building API as the software classifier.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
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
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80..=80);
                })
                .deny(Priority::new(50).unwrap()),
        )
        .build();

    // One call to compile.  Internally this:
    // - groups rules by field signature
    // - computes the union signature
    // - assigns DPDK categories per group
    // - pads rules with wildcards for the union layout
    // - builds the DPDK ACL trie
    let classifier = DpdkAclClassifier::compile(&table).unwrap();

    // One call to classify.  Internally this:
    // - assembles a compact input buffer from parsed headers
    // - calls rte_acl_classify with the right category count
    // - resolves the best match across categories
    // - maps the result back to a Fate
    let packets = [
        ("10.1.2.3", 80, "matches /16 deny (pri 50) -> Drop"),
        ("10.2.0.1", 80, "matches /8 permit (pri 100) -> Accept"),
        ("192.168.1.1", 80, "no match -> Drop (default)"),
        ("10.1.2.3", 443, "wrong port -> Drop (default)"),
    ];

    for (ip_str, port, description) in &packets {
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let pkt = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip_hdr| {
                if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(ip) {
                    ip_hdr.set_source(uip);
                }
            })
            .tcp(|tcp| {
                tcp.set_destination(net::tcp::port::TcpPort::new_checked(*port).unwrap());
            })
            .build_headers()
            .unwrap();

        let fate = classifier.classify_fate(&pkt);
        println!("  {ip_str}:{port} -> {fate:?}  ({description})");
    }
}

/// Example: mixed-protocol rules through DPDK ACL.
///
/// Rules with different protocol layers (TCP, UDP, IP-only) have
/// different field signatures.  The compiler merges them into a
/// single DPDK context using categories - the user doesn't need
/// to know about any of this.
fn mixed_signature_classify() {
    println!("\n=== DPDK ACL: Mixed signatures ===");

    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            // Management network: permit everything (IPv4-only, no transport).
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                    );
                })
                .permit(Priority::new(10).unwrap()),
        )
        .add_rule(
            // HTTP from any source.
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
            // DNS from any source.
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
            // Annotate SSH traffic with a mark (for downstream processing).
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(22..=22);
                })
                .action(
                    ActionSequence::new(
                        vec![Step::Mark(0xBEEF)],
                        Fate::Accept,
                    ),
                    Priority::new(150).unwrap(),
                ),
        )
        .build();

    // Three different field signatures (IPv4-only, IPv4+TCP, IPv4+UDP),
    // all compiled into one DPDK context.
    let classifier = DpdkAclClassifier::compile(&table).unwrap();

    println!("  Compiled: {} categories", classifier.num_categories());

    let packets = [
        ("172.16.1.1", 8080u16, "tcp", "mgmt network -> Accept (pri 10)"),
        ("8.8.8.8", 80, "tcp", "HTTP -> Accept (pri 100)"),
        ("8.8.8.8", 53, "udp", "DNS -> Accept (pri 200)"),
        ("8.8.8.8", 22, "tcp", "SSH -> Accept + Mark (pri 150)"),
        ("8.8.8.8", 8080, "tcp", "no match -> Drop"),
    ];

    for (ip_str, port, proto, description) in &packets {
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let pkt = match *proto {
            "tcp" => HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip_hdr| {
                    if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(ip) {
                        ip_hdr.set_source(uip);
                    }
                })
                .tcp(|tcp| {
                    tcp.set_destination(net::tcp::port::TcpPort::new_checked(*port).unwrap());
                })
                .build_headers()
                .unwrap(),
            "udp" => HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip_hdr| {
                    if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(ip) {
                        ip_hdr.set_source(uip);
                    }
                })
                .udp(|udp| {
                    udp.set_destination(net::udp::port::UdpPort::new_checked(*port).unwrap());
                })
                .build_headers()
                .unwrap(),
            _ => unreachable!(),
        };

        let fate = classifier.classify_fate(&pkt);
        println!("  {ip_str}:{port}/{proto} → {fate:?}  ({description})");
    }
}
