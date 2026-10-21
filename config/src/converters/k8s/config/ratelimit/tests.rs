// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used)]

use super::{RATE_LIMITS, rate_limits};
use crate::converters::k8s::FromK8sConversionError;
use crate::external::overlay::Overlay;
use crate::external::overlay::ratelimit::{ColorAction, RateLimitTables};
use k8s_intf::gateway_agent_crd::GatewayAgentSpec;
use net::ip::dscp::Dscp;
use policer::{Profile, Rate};
use serde_json::{Value, json};
use std::num::NonZeroU64;

const PEERING: &str = "vpc-1--vpc-2";
const METER: &str = "vpc-1--vpc-2/web";

fn spec(annotations: &Value) -> GatewayAgentSpec {
    serde_json::from_value(json!({
        "vpcs": {
            "vpc-1": { "internalID": "AAAAA", "vni": 3000, "subnets": { "s": { "cidr": "10.1.0.0/16" } } },
            "vpc-2": { "internalID": "BBBBB", "vni": 3001, "subnets": { "s": { "cidr": "10.2.0.0/16" } } },
        },
        "peerings": { PEERING: {
            "annotations": annotations, "gatewayGroup": "default",
            "peering": {
                "vpc-1": { "expose": [{ "ips": [{ "cidr": "10.1.0.0/16" }] }] },
                "vpc-2": { "expose": [{ "ips": [{ "cidr": "10.2.0.0/16" }] }] },
            },
        }},
    })).unwrap()
}

fn policy(meter: Value) -> Value {
    let mut policy =
        json!({ "version": 0, "meters": {}, "rules": [{ "from": "vpc-1", "meter": "web" }] });
    policy["meters"]["web"] = meter;
    policy
}

fn with_policy(policy: &Value) -> GatewayAgentSpec {
    spec(&json!({ "gateway.alpha.githedgehog.com/rate-limits": policy.to_string() }))
}

fn convert(meter: Value) -> RateLimitTables {
    rate_limits(&with_policy(&policy(meter))).unwrap()
}

fn rate(n: u64) -> Rate {
    Rate::new(NonZeroU64::new(n).unwrap())
}

#[test]
fn no_annotations_no_rate_limits() {
    for annotations in [
        json!({}),
        json!({"gateway.githedgehog.com/other": "not json"}),
    ] {
        assert!(rate_limits(&spec(&annotations)).unwrap().is_empty());
    }
    let mut s = spec(&json!({}));
    s.peerings = None;
    assert!(rate_limits(&s).unwrap().is_empty());
}

#[test]
fn one_meter_has_bits_and_packets_with_useful_defaults() {
    let tables = convert(json!({"bits": {"rate": "80M"}, "pkts": {"rate": "100k"}}));
    assert_eq!(tables.len(), 1);
    assert_eq!(tables.rules.len(), 1);
    let meter = &tables.meters[METER];
    assert_eq!(
        meter.bytes.unwrap().profile,
        Profile::new(rate(10_000_000), 1_000_000, None, 0).unwrap()
    );
    assert_eq!(
        meter.packets.unwrap().profile,
        Profile::new(rate(100_000), 10_000, None, 0).unwrap()
    );
    let actions = meter.bytes.unwrap().actions;
    assert_eq!(actions.green, ColorAction::Pass);
    assert_eq!(actions.yellow, ColorAction::Pass);
    assert_eq!(actions.red, ColorAction::Drop);
}

#[test]
fn small_rates_still_pass_a_whole_packet() {
    let tables = convert(json!({"bits": {"rate": 8}, "pkts": {"rate": 1}}));
    assert_eq!(
        tables.meters[METER]
            .bytes
            .unwrap()
            .profile
            .committed_burst(),
        9216
    );
    assert_eq!(
        tables.meters[METER]
            .packets
            .unwrap()
            .profile
            .committed_burst(),
        1
    );
}

#[test]
fn excess_and_duration_replace_colors_and_bucket_sizes() {
    let tables = convert(
        json!({"bits": {"rate": "1.5G", "burst": "0.05s", "excess": {"rate": "500M", "setDSCP": "10"}}}),
    );
    let component = tables.meters[METER].bytes.unwrap();
    assert_eq!(
        component.profile,
        Profile::new(
            rate(187_500_000),
            9_375_000,
            Some(rate(62_500_000)),
            3_125_000
        )
        .unwrap()
    );
    assert_eq!(
        component.actions.yellow,
        ColorAction::Remark(Dscp::new(10).unwrap())
    );
    let tables =
        convert(json!({"pkts": {"rate": "1.5k", "burst": "1m0.5s", "excess": {"rate": "500"}}}));
    assert_eq!(
        tables.meters[METER]
            .packets
            .unwrap()
            .profile
            .committed_burst(),
        90_750
    );
}

#[test]
fn quantities_use_kubernetes_decimal_binary_and_exponent_forms() {
    for (value, expected) in [
        (json!("1.5Mi"), 196_608),
        (json!("8e6"), 1_000_000),
        (json!("8000m"), 1),
        (json!(8_000_000), 1_000_000),
    ] {
        assert_eq!(
            convert(json!({"bits": {"rate": value}})).meters[METER]
                .bytes
                .unwrap()
                .profile
                .committed_rate(),
            rate(expected)
        );
    }
    assert_eq!(
        convert(json!({"pkts": {"rate": 1e3}})).meters[METER]
            .packets
            .unwrap()
            .profile
            .committed_rate(),
        rate(1000)
    );
}

#[test]
fn ordered_rules_reference_one_shared_meter() {
    let mut p = policy(json!({"pkts": {"rate": "1k"}}));
    p["rules"] = json!([
        {"from": "vpc-1", "match": {"dst": [{"cidr": "10.2.0.0/16"}]}, "meter": "web"},
        {"to": "vpc-2", "match": {"dst": [{"cidr": "10.2.1.0/24"}]}, "meter": "web"},
    ]);
    let tables = rate_limits(&with_policy(&p)).unwrap();
    assert_eq!(tables.meters.len(), 1);
    assert_eq!(tables.rules.len(), 2);
    assert!(
        tables
            .rules
            .iter()
            .all(|r| r.meter == METER && r.from == "vpc-1" && r.to == "vpc-2")
    );
    assert_eq!(
        tables.rules[0].pattern.dst.iter().next().unwrap().prefix(),
        "10.2.0.0/16".parse().unwrap()
    );
    assert_eq!(
        tables.rules[1].pattern.dst.iter().next().unwrap().prefix(),
        "10.2.1.0/24".parse().unwrap()
    );
    let overlay = Overlay::try_from(&with_policy(&p))
        .unwrap()
        .validate()
        .unwrap();
    assert_eq!(overlay.rate_limits().rules.len(), 2);
    assert_eq!(overlay.rate_limits().rules[0].from.as_u32(), 3000);
    assert_eq!(overlay.rate_limits().rules[0].to.as_u32(), 3001);
}

#[test]
fn absent_endpoints_mean_both_directions() {
    let mut p = policy(json!({"pkts": {"rate": "1k"}}));
    p["rules"] = json!([{"meter": "web"}]);
    let overlay = Overlay::try_from(&with_policy(&p))
        .unwrap()
        .validate()
        .unwrap();
    let rules = &overlay.rate_limits().rules;
    assert_eq!(rules.len(), 2);
    assert_eq!((rules[0].from, rules[0].to), (rules[1].to, rules[1].from));
}

#[test]
fn acl_match_supports_protocol_ports_and_subnet_references() {
    let mut p = policy(json!({"pkts": {"rate": "1k"}}));
    p["rules"][0]["match"] = json!({"proto": "tcp", "src": [{"vpcSubnet": "s", "ports": ["1024-65535"]}], "dst": [{"ports": ["443"]}]});
    let overlay = Overlay::try_from(&with_policy(&p))
        .unwrap()
        .validate()
        .unwrap();
    let pattern = &overlay.rate_limits().rules[0].pattern;
    assert_eq!(
        pattern.proto(),
        crate::external::overlay::acl::AclProtoMatch::tcp()
    );
    assert!(pattern.src().uses_ports());
    assert!(pattern.dst().uses_ports());
    p["rules"][0]["match"]["proto"] = json!("icmp");
    assert!(
        Overlay::try_from(&with_policy(&p))
            .and_then(|o| o.validate().map_err(FromK8sConversionError::ConfigError))
            .is_err()
    );
}

#[test]
fn acl_match_supports_tcp_filters() {
    use crate::external::overlay::acl::{AclProtoMatch, AclTcpFlagsMatch};
    use net::tcp::TcpFlags;

    let mut p = policy(json!({"pkts": {"rate": "1k"}}));
    p["rules"][0]["match"] =
        json!({"proto": "tcp", "tcpFilters": {"flags": {"syn": true, "ack": false}}});
    let overlay = Overlay::try_from(&with_policy(&p))
        .unwrap()
        .validate()
        .unwrap();
    assert_eq!(
        overlay.rate_limits().rules[0].pattern.proto(),
        AclProtoMatch::Tcp(
            AclTcpFlagsMatch::ANY
                .require(TcpFlags::SYN, true)
                .require(TcpFlags::ACK, false)
        )
    );
    let refused = |m: Value| {
        let mut p = p.clone();
        p["rules"][0]["match"] = m;
        Overlay::try_from(&with_policy(&p)).is_err()
    };
    assert!(refused(
        json!({"proto": "udp", "tcpFilters": {"flags": {"syn": true}}})
    ));
    assert!(refused(json!({"tcpFilters": {"flags": {"syn": true}}})));
    assert!(refused(
        json!({"proto": "tcp", "tcpFilters": {"flags": {"ns": true}}})
    ));
    assert!(refused(json!({"proto": "tcp", "tcpFilters": {"mask": 2}})));
}

#[test]
fn invalid_meter_settings_are_refused() {
    for (meter, expected) in [
        (json!({}), "needs bits or pkts"),
        (json!({"bytes": {"rate": "1M"}}), "unknown field"),
        (json!({"bits": {"rate": "81"}}), "whole bytes"),
        (json!({"pkts": {"rate": "0.5"}}), "whole packets"),
        (json!({"bits": {"rate": 0}}), "positive"),
        (json!({"bits": {"rate": "1MiB"}}), "quantity suffix"),
        (json!({"bits": {"rate": "1e999"}}), "supported limit"),
        (
            json!({"bits": {"rate": "8k", "burst": "1ms"}}),
            "9216 bytes",
        ),
        (json!({"pkts": {"rate": 1, "burst": "1ms"}}), "one"),
        (json!({"bits": {"rate": "80M", "burst": "0s"}}), "positive"),
        (
            json!({"bits": {"rate": "80M", "burst": "1day"}}),
            "duration unit",
        ),
        (
            json!({"bits": {"rate": "80M", "cir": "1M"}}),
            "unknown field",
        ),
        (
            json!({"bits": {"rate": "80M", "yellow": {"action": "pass"}}}),
            "unknown field",
        ),
        (
            json!({"bits": {"rate": "80M", "excess": {"setDSCP": 10}}}),
            "missing field",
        ),
        (
            json!({"bits": {"rate": "80M", "excess": {"rate": 0}}}),
            "positive",
        ),
        (
            json!({"bits": {"rate": "80M", "excess": {"rate": "8M", "setDSCP": 64}}}),
            "0 to 63",
        ),
    ] {
        let e = rate_limits(&with_policy(&policy(meter.clone())))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(expected) || (expected == "one" && e.contains("1 packet")),
            "{meter}: {e}"
        );
        assert!(e.contains(RATE_LIMITS));
    }
}

#[test]
fn unknown_versions_rules_and_fields_are_refused() {
    let base = policy(json!({"pkts": {"rate": "1k"}}));
    for (pointer, value) in [
        ("/version", json!(1)),
        ("/rules/0/meter", json!("missing")),
        ("/rules/0/from", json!("vpc-3")),
        (
            "/rules/0",
            json!({"from": "vpc-1", "meter": "web", "destination": "10.2.0.0/16"}),
        ),
        (
            "/rules/0",
            json!({"from": "vpc-1", "meter": "web", "match": {"protocol": "tcp"}}),
        ),
        (
            "/rules/0",
            json!({"from": "vpc-1", "meter": "web", "match": {"dst": [{"cidrr": "10.2.0.0/16"}]}}),
        ),
    ] {
        let mut p = base.clone();
        *p.pointer_mut(pointer).unwrap() = value;
        assert!(rate_limits(&with_policy(&p)).is_err(), "{p}");
    }
    for value in [
        json!({"version": 0, "limits": []}),
        json!({"meters": {}, "rules": []}),
    ] {
        assert!(rate_limits(&with_policy(&value)).is_err());
    }
    assert!(
        rate_limits(&spec(
            &json!({"gateway.alpha.githedgehog.com/rate-limit": "{}"})
        ))
        .is_err()
    );
}

#[test]
fn unrelated_annotations_coexist_with_rate_limits() {
    let p = policy(json!({"pkts": {"rate": "1k"}})).to_string();
    let tables = rate_limits(&spec(
        &json!({RATE_LIMITS: p, "gateway.githedgehog.com/other": "not json"}),
    ))
    .unwrap();
    assert_eq!(tables.len(), 1);
}

#[test]
fn a_rate_limit_survives_conversion_and_validation() {
    use crate::ExternalConfig;
    use k8s_intf::bolero::LegalValue;
    use k8s_intf::gateway_agent_crd::GatewayAgent;
    bolero::check!()
        .with_type::<LegalValue<GatewayAgent>>()
        .for_each(|agent| {
            let mut agent = agent.as_ref().clone();
            let Ok(without) = ExternalConfig::try_from(&agent)
                .and_then(|e| e.validate().map_err(FromK8sConversionError::ConfigError))
            else {
                return;
            };
            let Some((name, peering)) = agent
                .spec
                .peerings
                .as_mut()
                .and_then(|p| p.iter_mut().next())
            else {
                return;
            };
            let Some(from) = peering
                .peering
                .as_ref()
                .and_then(|p| p.keys().next())
                .cloned()
            else {
                return;
            };
            let mut p = policy(json!({"bits": {"rate": "80M"}, "pkts": {"rate": "1k"}}));
            p["rules"][0]["from"] = json!(from);
            peering
                .annotations
                .get_or_insert_default()
                .insert(RATE_LIMITS.into(), p.to_string());
            let name = name.clone();
            let with = ExternalConfig::try_from(&agent)
                .unwrap()
                .validate()
                .unwrap();
            assert_eq!(
                with.external().overlay().vpc_table().len(),
                without.external().overlay().vpc_table().len()
            );
            let limits = with.external().overlay().rate_limits();
            assert!(limits.meters.contains_key(&format!("{name}/web")));
            assert_ne!(limits.rules.len(), 0);
            assert!(limits.rules.iter().all(|r| {
                r.from
                    == without
                        .external()
                        .overlay()
                        .vpc_table()
                        .get_vpc(&from)
                        .unwrap()
                        .vni()
            }));
        });
}

#[test]
fn matches_use_source_private_and_destination_public_addresses() {
    let mut p = policy(json!({"bits": {"rate": "80M"}}));
    p["rules"][0]["match"] =
        json!({"src": [{"cidr": "10.1.0.0/16"}], "dst": [{"cidr": "10.12.0.0/16"}]});
    let mut spec = serde_json::to_value(with_policy(&p)).unwrap();
    for (vpc, prefix) in [("vpc-1", "10.11.0.0/16"), ("vpc-2", "10.12.0.0/16")] {
        let expose = &mut spec["peerings"][PEERING]["peering"][vpc]["expose"][0];
        expose["as"] = json!([{ "cidr": prefix }]);
        expose["nat"] = json!({"static": {}});
    }
    let spec: GatewayAgentSpec = serde_json::from_value(spec).unwrap();
    let validated = Overlay::try_from(&spec).unwrap().validate().unwrap();
    let pattern = &validated.rate_limits().rules[0].pattern;
    assert_eq!(
        pattern.src().iter().next().unwrap().prefix(),
        "10.1.0.0/16".parse().unwrap()
    );
    assert_eq!(
        pattern.dst().iter().next().unwrap().prefix(),
        "10.12.0.0/16".parse().unwrap()
    );
    let mut invalid = Overlay::try_from(&spec).unwrap();
    let mut limits = rate_limits(&spec).unwrap();
    limits.rules[0].pattern.dst = [lpm::prefix::PrefixWithOptionalPorts::from(
        "10.2.0.0/16".parse::<lpm::prefix::Prefix>().unwrap(),
    )]
    .into();
    invalid = invalid.with_rate_limits(limits);
    assert!(invalid.validate().is_err());
}

#[test]
fn internal_configuration_validates_meter_and_peering_references() {
    let spec = with_policy(&policy(json!({"pkts": {"rate": 1000}})));
    let base = rate_limits(&spec).unwrap();
    for case in 0..5 {
        let mut limits = base.clone();
        match case {
            0 => limits.meters.get_mut(METER).unwrap().packets = None,
            1 => limits.rules[0].meter = "missing".into(),
            2 => limits.rules[0].from = "missing".into(),
            3 => limits.rules[0].to = "missing".into(),
            _ => limits.rules[0].peering = "missing".into(),
        }
        assert!(
            Overlay::try_from(&spec)
                .unwrap()
                .with_rate_limits(limits)
                .validate()
                .is_err()
        );
    }
}
