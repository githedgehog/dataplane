// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests for the ACL filter.
//!
//! ACLs are attached to a peering and evaluated in the order the user provides them: the first
//! matching rule decides the action, and if no rule matches, the peering's default action is used
//! (if no ACL is configured at all, traffic is allowed). A rule's scope ('flow' or 'packet')
//! decides whether reply traffic is allowed once the corresponding request is allowed.

use crate::{AclFilter, AclFilterContext, AclFilterContextWriter};

use config::external::overlay::acl::{
    Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope,
};
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};

use lpm::prefix::{Prefix, PrefixPortsSet, PrefixWithOptionalPorts};

use net::FlowKey;
use net::buffer::TestBuffer;
use net::flows::{FlowInfo, FlowInfoFlags, FlowStatus};
use net::headers::Headers;
use net::headers::builder::HeaderStack;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::parse::DeParse;
use net::tcp::TcpPort;
use net::udp::UdpPort;
use net::vxlan::Vni;

use concurrency::sync::Arc;
use pipeline::NetworkFunction;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

// VNIs and IP ranges used by the standard two-VPC peering (vpc1 <-> vpc2). The manifest names
// ("vpc1"/"vpc2") double as the ACL rule `from`/`to` endpoints.
const VNI1: u32 = 100;
const VNI2: u32 = 200;
const V1_IPS: &str = "10.0.0.0/24";
const V2_IPS: &str = "20.0.0.0/24";
const V1_IPS_V6: &str = "2001:db8::/64";
const V2_IPS_V6: &str = "2001:db9::/64";

// -------------------------------------------------------------------------------------------------
// Identifiers and address parsing

fn vni(id: u32) -> Vni {
    Vni::new_checked(id).unwrap()
}

fn vpcd(id: u32) -> VpcDiscriminant {
    VpcDiscriminant::from_vni(vni(id))
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

// -------------------------------------------------------------------------------------------------
// Expose / peering / overlay builders

/// Plain expose (no NAT): the listed prefix is both private and public.
fn expose(ip: &str) -> VpcExpose {
    VpcExpose::empty().ip(ip.into())
}

/// Static-NAT expose: `private` addresses are translated 1:1 to `public`.
fn expose_static(private: &str, public: &str) -> VpcExpose {
    VpcExpose::empty()
        .make_static_nat()
        .unwrap()
        .ip(private.into())
        .as_range(public.into())
        .unwrap()
}

/// Masquerade expose: `private` addresses are masqueraded behind `public`.
fn expose_masquerade(private: &str, public: &str) -> VpcExpose {
    VpcExpose::empty()
        .make_masquerade(None)
        .unwrap()
        .ip(private.into())
        .as_range(public.into())
        .unwrap()
}

/// Build a peering between `local` and `remote`, each given as `(vpc_name, exposes)`, with an
/// optional ACL attached.
fn peering(
    name: &str,
    local: (&str, Vec<VpcExpose>),
    remote: (&str, Vec<VpcExpose>),
    acl: Option<Acl>,
) -> VpcPeering {
    let mut peering = VpcPeering::with_default_group(
        name,
        VpcManifest::with_exposes(local.0, local.1),
        VpcManifest::with_exposes(remote.0, remote.1),
    );
    peering.acl = acl;
    peering
}

/// Assemble a `VpcTable` from `(name, vni)` pairs, generating valid 5-char ids.
fn vpc_table(vpcs: &[(&str, u32)]) -> VpcTable {
    let mut table = VpcTable::new();
    for (i, (name, vni_id)) in vpcs.iter().enumerate() {
        let id = format!("VPC{:02}", i + 1); // VpcId must be exactly 5 chars
        table.add(Vpc::new(name, &id, *vni_id).unwrap()).unwrap();
    }
    table
}

/// Build and validate an overlay from a set of VPCs and peerings.
fn overlay(vpcs: &[(&str, u32)], peerings: Vec<VpcPeering>) -> ValidatedOverlay {
    let mut peering_table = VpcPeeringTable::new();
    for p in peerings {
        peering_table.add(p).unwrap();
    }
    Overlay::new(vpc_table(vpcs), peering_table)
        .validate()
        .unwrap()
}

/// Build an `AclFilter` network function from a validated overlay.
fn acl_filter(overlay: &ValidatedOverlay) -> AclFilter {
    let writer = AclFilterContextWriter::new();
    // Use the reference backend so the semantic suite stays fast and EAL-free; the rte_acl backend
    // is exercised separately (see the `dpdk_backend` differential module).
    writer.store(AclFilterContext::for_test(overlay));
    AclFilter::new("test-acl-filter", writer.get_reader())
}

// Build an `AclFilter` for the standard vpc1 <-> vpc2 peering with plain exposes and the given ACL
fn build_filter(local_ips: &str, remote_ips: &str, acl: Option<Acl>) -> AclFilter {
    acl_filter(&overlay(
        &[("vpc1", VNI1), ("vpc2", VNI2)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose(local_ips)]),
            ("vpc2", vec![expose(remote_ips)]),
            acl,
        )],
    ))
}

fn build_filter_v4(acl: Option<Acl>) -> AclFilter {
    build_filter(V1_IPS, V2_IPS, acl)
}

// -------------------------------------------------------------------------------------------------
// ACL rule builders

fn prefixes(entries: &[&str]) -> PrefixPortsSet {
    entries
        .iter()
        .map(|p| PrefixWithOptionalPorts::new(Prefix::from(*p), None))
        .collect()
}

fn pattern(src: &[&str], dst: &[&str], proto: AclProtoMatch) -> AclPattern {
    AclPattern {
        src: prefixes(src),
        dst: prefixes(dst),
        src_any_ports: Vec::new(),
        dst_any_ports: Vec::new(),
        proto,
    }
}

// A rule in the given direction (`from`/`to` are the peering's VPC manifest names)
fn directional_rule(
    name: &str,
    from: &str,
    to: &str,
    action: AclAction,
    scope: AclScope,
    pattern: AclPattern,
) -> AclRule {
    AclRule {
        name: name.to_owned(),
        from: from.to_owned(),
        to: to.to_owned(),
        action,
        pattern,
        scope,
        log: true,
    }
}

// A rule in the request direction, from "vpc1" to "vpc2" (the standard peering's manifest names)
fn rule(name: &str, action: AclAction, scope: AclScope, pattern: AclPattern) -> AclRule {
    directional_rule(name, "vpc1", "vpc2", action, scope, pattern)
}

// -------------------------------------------------------------------------------------------------
// Packet-header builders (via the HeaderStack builder) and packet assembly

fn build_tcp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .tcp(|tcp| {
            tcp.set_source(TcpPort::try_from(sport).unwrap());
            tcp.set_destination(TcpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}

fn build_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .udp(|udp| {
            udp.set_source(UdpPort::try_from(sport).unwrap());
            udp.set_destination(UdpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}

fn build_tcp_packet_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv6(|ip| {
            ip.set_source(UnicastIpv6Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .tcp(|tcp| {
            tcp.set_source(TcpPort::try_from(sport).unwrap());
            tcp.set_destination(TcpPort::try_from(dport).unwrap());
        })
        .build_headers()
        .unwrap()
}

// ICMP (IP protocol 1): a non-TCP/UDP protocol, used to exercise the `Other(n)` and `Any` tables.
fn build_icmp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(UnicastIpv4Addr::new(src).unwrap());
            ip.set_destination(dst);
        })
        .icmp4(|_| {})
        .build_headers()
        .unwrap()
}

// Serialize built headers into a parseable overlay test packet with the given source and (optional)
// destination VPC. By the time a packet reaches the ACL filter both discriminants are set, so unit
// tests provide `dst_vpcd`; in the end-to-end pipeline the flow filter sets it, so `None` is used.
fn packet(
    src_vpcd: VpcDiscriminant,
    dst_vpcd: Option<VpcDiscriminant>,
    headers: Headers,
) -> Packet<TestBuffer> {
    let mut buffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();
    let mut packet = Packet::new(buffer).unwrap();
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = Some(src_vpcd);
    packet.meta_mut().dst_vpcd = dst_vpcd;
    packet
}

fn run(filter: &mut AclFilter, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
    filter.process(std::iter::once(packet)).next().unwrap()
}

fn is_allowed(packet: &Packet<TestBuffer>) -> bool {
    packet.get_done().is_none()
}

fn is_denied(packet: &Packet<TestBuffer>) -> bool {
    packet.get_done() == Some(DoneReason::AclDropped)
}

// -------------------------------------------------------------------------------------------------
// Packet-scope tests: ordering, default action, protocol matching

#[test]
fn no_acl_allows_all() {
    let mut filter = build_filter_v4(None);
    let pkt = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, pkt)));
}

// A rule that only covers the upper half of vpc2 (20.0.0.128/25), so a packet destined to the
// lower half matches no rule and hits the peering's default action
fn acl_with_nonmatching_rule(default: AclAction) -> Acl {
    Acl::new(
        default,
        vec![rule(
            "narrow-allow",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &["20.0.0.128/25"], AclProtoMatch::Tcp),
        )],
    )
}

#[test]
fn default_deny_when_no_rule_matches() {
    let mut filter = build_filter_v4(Some(acl_with_nonmatching_rule(AclAction::Deny)));
    // Destination 20.0.0.5 is in the lower half, not covered by the rule -> default Deny
    let pkt = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, pkt)));
}

#[test]
fn default_allow_when_no_rule_matches() {
    let mut filter = build_filter_v4(Some(acl_with_nonmatching_rule(AclAction::Allow)));
    // Destination 20.0.0.5 is not covered by the rule -> default Allow
    let pkt = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, pkt)));
}

#[test]
fn explicit_allow_over_default_deny() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-tcp",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    // Matches the allow rule
    let allowed = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, allowed)));

    // Destination outside the rule's dst prefix -> falls through to the default Deny
    let denied = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.1.5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, denied)));
}

// The first matching rule wins: a narrow Allow placed before a broad Deny lets matching traffic
// through, while traffic that only hits the later Deny is dropped
#[test]
fn first_matching_rule_wins() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![
            rule(
                "allow-lower-half",
                AclAction::Allow,
                AclScope::Packet,
                pattern(&["10.0.0.0/25"], &[V2_IPS], AclProtoMatch::Tcp),
            ),
            rule(
                "deny-whole-range",
                AclAction::Deny,
                AclScope::Packet,
                pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
            ),
        ],
    );
    let mut filter = build_filter_v4(Some(acl));

    // 10.0.0.5 is in the /25 -> hits the Allow rule first
    let allowed = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, allowed)));

    // 10.0.0.200 is outside the /25 but inside the /24 -> only the Deny rule matches
    let denied = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.200"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, denied)));
}

// A rule matching only TCP must not affect UDP traffic, which falls through to the default
#[test]
fn protocol_specific_rule_does_not_match_other_protocol() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-tcp-only",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    let tcp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, tcp)));

    // Same addresses, UDP -> the TCP-only rule doesn't apply, default Deny drops it
    let udp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_udp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, udp)));
}

// A rule matching any protocol must match both TCP and UDP traffic
#[test]
fn protocol_any_rule_matches_both_tcp_and_udp() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-any-proto",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Any),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    let tcp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, tcp)));

    // Same addresses, UDP -> the TCP-only rule doesn't apply, default Deny drops it
    let udp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_udp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, udp)));
}

// An 'any protocol' rule also covers non-TCP/UDP traffic (matched via the proto-agnostic table)
#[test]
fn protocol_any_rule_matches_icmp() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-any-proto",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Any),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    let icmp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_icmp_packet(v4("10.0.0.5"), v4("20.0.0.5")),
    );
    assert!(is_allowed(&run(&mut filter, icmp)));
}

// A numeric-protocol rule matches only packets carrying that exact IP protocol number
#[test]
fn protocol_other_rule_matches_only_its_protocol_number() {
    // ICMP is IP protocol 1: an Other(1) rule must match ICMP traffic.
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-icmp",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Other(1)),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));
    let icmp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_icmp_packet(v4("10.0.0.5"), v4("20.0.0.5")),
    );
    assert!(is_allowed(&run(&mut filter, icmp)));

    // A rule for a different protocol number (2 = IGMP) must not match ICMP traffic; it falls
    // through to the default Deny.
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-igmp",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Other(2)),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));
    let icmp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_icmp_packet(v4("10.0.0.5"), v4("20.0.0.5")),
    );
    assert!(is_denied(&run(&mut filter, icmp)));
}

// A numeric-protocol rule for a non-TCP/UDP protocol must not leak onto TCP traffic
#[test]
fn protocol_other_rule_does_not_match_tcp() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-icmp-only",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Other(1)),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    let tcp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, tcp)));
}

// For a non-TCP/UDP packet, a numeric-protocol rule and an 'any protocol' rule can both match, so
// first-match ordering must still decide (they share a single proto-range table). Both rules below
// match the ICMP packet, so the peering default never applies; only their relative order matters.
#[test]
fn protocol_any_and_other_rules_respect_order() {
    // Other(1) (ICMP) Allow placed before Any Deny -> ICMP is allowed.
    let acl = Acl::new(
        AclAction::Deny,
        vec![
            rule(
                "allow-icmp",
                AclAction::Allow,
                AclScope::Packet,
                pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Other(1)),
            ),
            rule(
                "deny-any",
                AclAction::Deny,
                AclScope::Packet,
                pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Any),
            ),
        ],
    );
    let mut filter = build_filter_v4(Some(acl));
    let icmp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_icmp_packet(v4("10.0.0.5"), v4("20.0.0.5")),
    );
    assert!(is_allowed(&run(&mut filter, icmp)));

    // Any Deny placed before Other(1) Allow -> ICMP is denied (the earlier rule wins).
    let acl = Acl::new(
        AclAction::Allow,
        vec![
            rule(
                "deny-any",
                AclAction::Deny,
                AclScope::Packet,
                pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Any),
            ),
            rule(
                "allow-icmp",
                AclAction::Allow,
                AclScope::Packet,
                pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Other(1)),
            ),
        ],
    );
    let mut filter = build_filter_v4(Some(acl));
    let icmp = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_icmp_packet(v4("10.0.0.5"), v4("20.0.0.5")),
    );
    assert!(is_denied(&run(&mut filter, icmp)));
}

#[test]
fn ipv6_allow_and_default_deny() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-v6",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS_V6], &[V2_IPS_V6], AclProtoMatch::Tcp),
        )],
    );
    let mut filter = build_filter(V1_IPS_V6, V2_IPS_V6, Some(acl));

    let allowed = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet_v6(v6("2001:db8::5"), v6("2001:db9::5"), 1234, 80),
    );
    assert!(is_allowed(&run(&mut filter, allowed)));

    let denied = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet_v6(v6("2001:db8::5"), v6("2001:dbf::5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, denied)));
}

// -------------------------------------------------------------------------------------------------
// Flow-scope tests
//
// These exercise the reply logic in isolation by faking the flow relation that masquerade or port
// forwarding would otherwise establish: a reply packet carries flow info whose `related` flow is
// the original request. See `end_to_end` below for the same behavior through a full NAT pipeline.

// Attach flow info to `reply` linking it to the request described by `fwd_key`, mimicking an
// established session. Returns the request-side flow, which the caller must keep alive so the
// reply's weak `related` reference can still be upgraded.
fn attach_related_flow(reply: &mut Packet<TestBuffer>, fwd_key: FlowKey) -> Arc<FlowInfo> {
    let reply_key = FlowKey::try_from(&*reply).unwrap();
    let expiry = Instant::now() + Duration::from_secs(60);
    let (fwd_flow, reply_flow) = FlowInfo::related_pair(
        expiry,
        fwd_key,
        FlowInfoFlags::default(),
        reply_key,
        FlowInfoFlags::default(),
    );
    reply_flow.update_status(FlowStatus::Active);
    reply.meta_mut().flow_info = Some(reply_flow);
    fwd_flow
}

#[test]
fn flow_scope_allows_reply_for_allowed_request() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-flow",
            AclAction::Allow,
            AclScope::Flow,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    // The request is allowed by the rule directly
    let request = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    let fwd_key = FlowKey::try_from(&request).unwrap();
    assert!(is_allowed(&run(&mut filter, request)));

    // The reply doesn't match any rule directly, but is allowed because it belongs to an allowed
    // flow (scope == Flow)
    let mut reply = packet(
        vpcd(VNI2),
        Some(vpcd(VNI1)),
        build_tcp_packet(v4("20.0.0.5"), v4("10.0.0.5"), 80, 1234),
    );
    let _request_flow = attach_related_flow(&mut reply, fwd_key);
    assert!(is_allowed(&run(&mut filter, reply)));
}

#[test]
fn packet_scope_denies_reply_for_allowed_request() {
    let acl = Acl::new(
        AclAction::Deny,
        vec![rule(
            "allow-packet",
            AclAction::Allow,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    let request = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    let fwd_key = FlowKey::try_from(&request).unwrap();
    assert!(is_allowed(&run(&mut filter, request)));

    // With a 'packet' scope rule, the reply is not covered by the request's authorization: it
    // matches no rule directly and falls through to the default Deny
    let mut reply = packet(
        vpcd(VNI2),
        Some(vpcd(VNI1)),
        build_tcp_packet(v4("20.0.0.5"), v4("10.0.0.5"), 80, 1234),
    );
    let _request_flow = attach_related_flow(&mut reply, fwd_key);
    assert!(is_denied(&run(&mut filter, reply)));
}

// An explicit Deny rule matching the reply direction takes precedence over any flow authorization:
// the reply is dropped even though it belongs to an allowed flow. (A direct rule match is decided
// before the reply's flow relation is ever consulted.)
#[test]
fn explicit_deny_rule_drops_reply_despite_matching_flow() {
    let acl = Acl::new(
        // Default Allow, so the drop can only come from the explicit Deny rule, not the default
        AclAction::Allow,
        vec![
            // Request direction (vpc1 -> vpc2): allowed, with 'flow' scope
            rule(
                "allow-request",
                AclAction::Allow,
                AclScope::Flow,
                pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
            ),
            // Reply direction (vpc2 -> vpc1): explicitly denied
            directional_rule(
                "deny-reply",
                "vpc2",
                "vpc1",
                AclAction::Deny,
                AclScope::Packet,
                pattern(&[V2_IPS], &[V1_IPS], AclProtoMatch::Tcp),
            ),
        ],
    );
    let mut filter = build_filter_v4(Some(acl));

    // The request is allowed by the request-direction rule
    let request = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    let fwd_key = FlowKey::try_from(&request).unwrap();
    assert!(is_allowed(&run(&mut filter, request)));

    // The reply belongs to the established (allowed) flow, but matches the reply-direction Deny
    // rule directly, so it is dropped regardless of the flow
    let mut reply = packet(
        vpcd(VNI2),
        Some(vpcd(VNI1)),
        build_tcp_packet(v4("20.0.0.5"), v4("10.0.0.5"), 80, 1234),
    );
    let _request_flow = attach_related_flow(&mut reply, fwd_key);
    assert!(is_denied(&run(&mut filter, reply)));
}

// A rule's validated src/dst prefixes are bound to its `from`/`to` VPCs. Make sure we process the
// source and destination manifests correctly when building the rule, and that the rule only applies
// to the correct direction.
//
// Here the rule is `vpc1 -> vpc2 Deny` over a default-Allow ACL. A reverse (vpc2 -> vpc1) packet
// carrying addresses that land in the forward rule's prefixes must NOT be denied by that rule; it
// must fall through to the peering default (Allow).
#[test]
fn directional_rule_only_applies_to_correct_direction() {
    let acl = Acl::new(
        // Default Allow: only the explicit Deny rule can drop a packet, so a denied reverse packet
        // could only come from the forward rule "leaking" into the reverse direction.
        AclAction::Allow,
        vec![rule(
            "deny-forward",
            AclAction::Deny,
            AclScope::Packet,
            pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
        )],
    );
    let mut filter = build_filter_v4(Some(acl));

    // Forward direction (vpc1 -> vpc2) matches the Deny rule.
    let forward = packet(
        vpcd(VNI1),
        Some(vpcd(VNI2)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
    );
    assert!(is_denied(&run(&mut filter, forward)));

    // Reverse direction (vpc2 -> vpc1) with addresses that fall in the forward rule's prefixes
    // (the overlapping-address-space case). The forward Deny rule must not apply; the peering
    // default (Allow) does.
    let reverse = packet(
        vpcd(VNI2),
        Some(vpcd(VNI1)),
        build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 80, 1234),
    );
    assert!(is_allowed(&run(&mut filter, reverse)));
}

// -------------------------------------------------------------------------------------------------
// End-to-end flow-scope test
//
// This runs a real NAT pipeline so the `related` flow link is established by masquerade (rather
// than faked). The ACL filter sits right after the flow filter, i.e. where the packet still
// carries pre-NAT addresses that ACL rules are written against. A 'flow'-scoped Allow rule
// authorizes the request; the reply matches no rule directly but must be allowed because it belongs
// to the established flow.

mod end_to_end {
    use super::{
        Acl, AclAction, AclFilterContext, AclFilterContextWriter, AclProtoMatch, AclScope,
        build_udp_packet, expose_masquerade, expose_static, is_allowed, overlay, packet, pattern,
        peering, rule, v4, vpcd,
    };
    use crate::AclFilter;

    use config::external::overlay::ValidatedOverlay;

    use flow_entry::flow_table::{FlowLookup, FlowTable};
    use flow_filter::{FlowFilter, FlowFilterTable, FlowFilterTableWriter};
    use nat::masquerade::{MasqueradeConfig, NatAllocatorWriter};
    use nat::portfw::{PortForwarder, PortFwTableWriter};
    use nat::static_nat::NatTablesWriter;
    use nat::static_nat::setup::build_nat_configuration;
    use nat::{IcmpErrorHandler, Masquerade, StaticNat};

    use net::buffer::TestBuffer;

    use concurrency::sync::Arc;
    use pipeline::{DynPipeline, NetworkFunction};
    use tracing_test::traced_test;

    // Keep every writer handle alive for the lifetime of the pipeline: dropping one would tear down
    // the data it published
    struct PipelineHandles {
        _flow_filter: FlowFilterTableWriter,
        _static_nat: NatTablesWriter,
        _portfw: PortFwTableWriter,
        _masquerade: NatAllocatorWriter,
        _acl: AclFilterContextWriter,
    }

    // vpc1 masquerades (1.2.3.0/24 -> 5.5.5.5/32); vpc2 uses static NAT (192.168.0.0/24 <->
    // 5.6.7.0/24). An ACL allows vpc1 -> vpc2 UDP with 'flow' scope, and denies by default.
    fn build_overlay() -> ValidatedOverlay {
        let acl = Acl::new(
            AclAction::Deny,
            vec![rule(
                "allow-flow-udp",
                AclAction::Allow,
                AclScope::Flow,
                // Empty src/dst: match all traffic of the peering in this direction
                pattern(&[], &[], AclProtoMatch::Udp),
            )],
        );
        overlay(
            &[("vpc1", 100), ("vpc2", 200)],
            vec![peering(
                "vpc1-to-vpc2",
                ("vpc1", vec![expose_masquerade("1.2.3.0/24", "5.5.5.5/32")]),
                ("vpc2", vec![expose_static("192.168.0.0/24", "5.6.7.0/24")]),
                Some(acl),
            )],
        )
    }

    fn setup_pipeline(
        overlay: &ValidatedOverlay,
    ) -> (DynPipeline<TestBuffer>, Arc<FlowTable>, PipelineHandles) {
        let flow_table = Arc::new(FlowTable::default());

        let mut pipeline = DynPipeline::new();
        pipeline = pipeline.add_stage(IcmpErrorHandler::new(flow_table.clone()));
        pipeline = pipeline.add_stage(FlowLookup::new("flow-lookup", flow_table.clone()));

        // Flow filter (determines destination VPC and NAT requirements)
        let mut flow_filter_writer = FlowFilterTableWriter::new();
        flow_filter_writer
            .update_flow_filter_table(FlowFilterTable::build_from_overlay(overlay).unwrap());
        pipeline = pipeline.add_stage(FlowFilter::new(
            "flow-filter",
            flow_filter_writer.get_reader(),
        ));

        // ACL filter: placed here so packets still carry VPC-internal addresses
        let acl_writer = AclFilterContextWriter::new();
        acl_writer.store(AclFilterContext::for_test(overlay));
        pipeline = pipeline.add_stage(AclFilter::new("acl-filter", acl_writer.get_reader()));

        // Static NAT
        let mut static_nat_writer = NatTablesWriter::new();
        static_nat_writer.update_nat_tables(build_nat_configuration(overlay.vpc_table()).unwrap());
        pipeline = pipeline.add_stage(StaticNat::with_reader(
            "static-nat",
            static_nat_writer.get_reader(),
        ));

        // Port forwarding
        let mut portfw_writer = PortFwTableWriter::new();
        portfw_writer
            .update_from_vpc_table(overlay.vpc_table())
            .unwrap();
        pipeline = pipeline.add_stage(PortForwarder::new(
            "port-forwarder",
            portfw_writer.reader(),
            flow_table.clone(),
        ));

        // Masquerade (creates the related flow pair used by 'flow'-scoped replies)
        let mut allocator = NatAllocatorWriter::new();
        allocator.update_nat_allocator(MasqueradeConfig::new(overlay.vpc_table(), 1), &flow_table);
        pipeline = pipeline.add_stage(Masquerade::new(
            "masquerade",
            flow_table.clone(),
            allocator.get_reader(),
        ));

        let handles = PipelineHandles {
            _flow_filter: flow_filter_writer,
            _static_nat: static_nat_writer,
            _portfw: portfw_writer,
            _masquerade: allocator,
            _acl: acl_writer,
        };
        (pipeline, flow_table, handles)
    }

    #[traced_test]
    #[tokio::test]
    async fn flow_scope_end_to_end() {
        let overlay = build_overlay();
        let (mut pipeline, _flow_table, _handles) = setup_pipeline(&overlay);

        // Request: 1.2.3.4:1234 -> 5.6.7.8:5678 (vpc1 -> vpc2). Allowed by the flow-scoped rule and
        // NAT'd on the way out. Only the source VPC is set: the flow filter fills in the rest.
        let request = packet(
            vpcd(100),
            None,
            build_udp_packet(v4("1.2.3.4"), v4("5.6.7.8"), 1234, 5678),
        );
        let out: Vec<_> = pipeline.process(std::iter::once(request)).collect();
        let request_out = out.first().unwrap();
        assert!(
            is_allowed(request_out),
            "request should be allowed and forwarded"
        );
        assert_eq!(request_out.ip_source(), Some(v4("5.5.5.5").into()));
        assert_eq!(request_out.ip_destination(), Some(v4("192.168.0.8").into()));
        let masq_src_port = request_out.transport_src_port().unwrap().get();

        // Reply: 192.168.0.8:5678 -> 5.5.5.5:<masq port> (vpc2 -> vpc1). Matches no ACL rule
        // directly, but belongs to the established flow, so the 'flow' scope authorizes it.
        let reply = packet(
            vpcd(200),
            None,
            build_udp_packet(v4("192.168.0.8"), v4("5.5.5.5"), 5678, masq_src_port),
        );
        let out: Vec<_> = pipeline.process(std::iter::once(reply)).collect();
        let reply_out = out.first().unwrap();
        assert!(
            is_allowed(reply_out),
            "reply of an allowed flow should be allowed"
        );
        // De-NAT'd back to the original request's endpoints
        assert_eq!(reply_out.ip_source(), Some(v4("5.6.7.8").into()));
        assert_eq!(reply_out.ip_destination(), Some(v4("1.2.3.4").into()));
    }
}

// -------------------------------------------------------------------------------------------------
// rte_acl backend differential test
//
// The semantic suite above runs on the reference backend (fast, no EAL). This module builds the
// same overlay on BOTH backends and asserts they return the same verdict for a spread of packets:
// since the reference backend's verdicts are pinned by the suite above, agreement proves the
// production rte_acl path (rule install, positional priority, per-version tables, mask-proto and
// range fields) is correct. Requires the EAL (`#[dpdk::with_eal]`).

mod dpdk_backend {
    use super::{
        Acl, AclAction, AclFilter, AclFilterContext, AclFilterContextWriter, AclProtoMatch,
        AclScope, Packet, TestBuffer, V1_IPS, V2_IPS, VNI1, VNI2, ValidatedOverlay,
        build_icmp_packet, build_tcp_packet, build_udp_packet, expose, is_allowed, overlay, packet,
        pattern, peering, rule, run, v4, vpcd,
    };

    fn filter_with(overlay: &ValidatedOverlay, dpdk: bool) -> AclFilter {
        let writer = AclFilterContextWriter::new();
        let ctx = if dpdk {
            AclFilterContext::for_test_dpdk(overlay).expect("rte_acl backend build")
        } else {
            AclFilterContext::for_test(overlay)
        };
        writer.store(ctx);
        AclFilter::new("diff-acl-filter", writer.get_reader())
    }

    // Run a freshly built packet through a reference-backed and an rte_acl-backed filter and assert
    // both reach the same allow/deny verdict.
    fn assert_backends_agree(
        overlay: &ValidatedOverlay,
        label: &str,
        make_packet: impl Fn() -> Packet<TestBuffer>,
    ) {
        let mut reference = filter_with(overlay, false);
        let mut dpdk = filter_with(overlay, true);
        let reference_allowed = is_allowed(&run(&mut reference, make_packet()));
        let dpdk_allowed = is_allowed(&run(&mut dpdk, make_packet()));
        assert_eq!(
            reference_allowed, dpdk_allowed,
            "reference and rte_acl backends disagree on {label}"
        );
    }

    #[test]
    #[dpdk::with_eal]
    fn dpdk_agrees_with_reference() {
        // A representative ACL exercising first-match ordering, TCP/UDP/ICMP protocol matching, and
        // the peering default. The overlapping allow-before-deny pair pins the priority wiring.
        let acl = Acl::new(
            AclAction::Deny,
            vec![
                rule(
                    "allow-lower-half",
                    AclAction::Allow,
                    AclScope::Packet,
                    pattern(&["10.0.0.0/25"], &[V2_IPS], AclProtoMatch::Tcp),
                ),
                rule(
                    "deny-whole-range",
                    AclAction::Deny,
                    AclScope::Packet,
                    pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Tcp),
                ),
                rule(
                    "allow-icmp",
                    AclAction::Allow,
                    AclScope::Packet,
                    pattern(&[V1_IPS], &[V2_IPS], AclProtoMatch::Other(1)),
                ),
            ],
        );
        let overlay = overlay(
            &[("vpc1", VNI1), ("vpc2", VNI2)],
            vec![peering(
                "vpc1-to-vpc2",
                ("vpc1", vec![expose(V1_IPS)]),
                ("vpc2", vec![expose(V2_IPS)]),
                Some(acl),
            )],
        );

        // First-match: 10.0.0.5 is in the /25 (allow wins); 10.0.0.200 only hits the deny.
        assert_backends_agree(&overlay, "tcp in /25 (allow wins)", || {
            packet(
                vpcd(VNI1),
                Some(vpcd(VNI2)),
                build_tcp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
            )
        });
        assert_backends_agree(&overlay, "tcp outside /25 (deny)", || {
            packet(
                vpcd(VNI1),
                Some(vpcd(VNI2)),
                build_tcp_packet(v4("10.0.0.200"), v4("20.0.0.5"), 1234, 80),
            )
        });
        // UDP matches neither the TCP nor the ICMP rule -> peering default (deny).
        assert_backends_agree(&overlay, "udp (default deny)", || {
            packet(
                vpcd(VNI1),
                Some(vpcd(VNI2)),
                build_udp_packet(v4("10.0.0.5"), v4("20.0.0.5"), 1234, 80),
            )
        });
        // ICMP matches the Other(1) allow.
        assert_backends_agree(&overlay, "icmp (Other(1) allow)", || {
            packet(
                vpcd(VNI1),
                Some(vpcd(VNI2)),
                build_icmp_packet(v4("10.0.0.5"), v4("20.0.0.5")),
            )
        });
        // Destination outside the peering's remote range -> default deny for every protocol.
        assert_backends_agree(&overlay, "tcp to foreign dst (default deny)", || {
            packet(
                vpcd(VNI1),
                Some(vpcd(VNI2)),
                build_tcp_packet(v4("10.0.0.5"), v4("30.0.0.5"), 1234, 80),
            )
        });
    }
}
