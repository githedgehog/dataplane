// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The gateway's ingress policy, from `gateway.alpha.githedgehog.com/ingress-policy`.
//!
//! Versioned JSON on the gateway, with a `meters` map as in the
//! [rate limits](super::ratelimit) and an ordered `rules` list. A rule has an optional `from` (a
//! VPC name; omitted, every VPC), an optional `match` (the peering ACL's `src`, `dst`, `proto` and
//! `tcpFilters`; `vpcSubnet` names a subnet of the `from` VPC, in `src` only), and an `action`:
//! `"drop"`, or `"police"` with a `meter`. First match wins. Meters count outer IP packets.
//!
//! ```json
//! {
//!   "version": 0,
//!   "meters": { "inbound": { "pkts": { "rate": "2M" }, "bits": { "rate": "20G" } } },
//!   "rules": [
//!     { "from": "internet", "match": { "proto": "udp", "src": [{ "ports": ["123"] }] }, "action": "drop" },
//!     { "from": "internet", "action": "police", "meter": "inbound" }
//!   ]
//! }
//! ```

use std::collections::BTreeMap;

use k8s_intf::gateway_agent_crd::GatewayAgentSpec;
use serde::Deserialize;

use super::ratelimit::{Match, MeterSpec};
use super::{SubnetMap, VpcSubnetMap};
use crate::converters::k8s::FromK8sConversionError;
use crate::external::overlay::acl::AclPattern;
use crate::external::overlay::ingress::{IngressAction, IngressPolicy, IngressRule};

/// The gateway annotation carrying its ingress policy.
pub const INGRESS_POLICY: &str = "gateway.alpha.githedgehog.com/ingress-policy";

/// The prefix of ingress meter names, keeping them apart from peering meters in metrics.
pub const METER_PREFIX: &str = "ingress/";

/// The gateway's ingress policy: empty without the annotation.
///
/// # Errors
///
/// Rejects unknown versions and fields, and invalid policies.
pub fn ingress_policy(spec: &GatewayAgentSpec) -> Result<IngressPolicy, FromK8sConversionError> {
    let annotations = spec.gateway.as_ref().and_then(|g| g.annotations.as_ref());
    let Some(value) = annotations.and_then(|a| a.get(INGRESS_POLICY)) else {
        return Ok(IngressPolicy::default());
    };
    let invalid =
        |detail: String| FromK8sConversionError::InvalidData(format!("{INGRESS_POLICY}: {detail}"));
    let subnets = spec
        .vpcs
        .as_ref()
        .map(super::overlay::extract_subnets)
        .transpose()?
        .unwrap_or_default();
    parse(value)
        .and_then(|policy| policy.convert(&subnets))
        .map_err(invalid)
}

fn parse(value: &str) -> Result<Policy, String> {
    #[derive(Deserialize)]
    struct Versioned {
        version: u32,
    }
    let Versioned { version } =
        serde_json::from_str(value).map_err(|e| format!("not versioned JSON: {e}"))?;
    if version != 0 {
        return Err(format!("unknown version {version}"));
    }
    serde_json::from_str(value).map_err(|e| format!("version 0: {e}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    #[serde(rename = "version")]
    _version: u32,
    #[serde(default)]
    meters: BTreeMap<String, MeterSpec>,
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    from: Option<String>,
    r#match: Option<Match>,
    action: ActionSpec,
    meter: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ActionSpec {
    Drop,
    Police,
}

impl Policy {
    fn convert(&self, subnets: &VpcSubnetMap) -> Result<IngressPolicy, String> {
        let mut policy = IngressPolicy::default();
        for (name, spec) in &self.meters {
            policy
                .meters
                .insert(format!("{METER_PREFIX}{name}"), spec.convert(name)?);
        }
        for (i, rule) in self.rules.iter().enumerate() {
            let action = match (&rule.action, &rule.meter) {
                (ActionSpec::Drop, None) => IngressAction::Drop,
                (ActionSpec::Drop, Some(_)) => {
                    return Err(format!("rule {i}: a drop takes no meter"));
                }
                // Whether the meter exists is `IngressPolicy::validate`'s to check, as for every
                // other reference (VPC names too).
                (ActionSpec::Police, Some(meter)) => {
                    IngressAction::Police(format!("{METER_PREFIX}{meter}"))
                }
                (ActionSpec::Police, None) => {
                    return Err(format!("rule {i}: police needs a meter"));
                }
            };
            let empty = SubnetMap::new();
            let own = rule
                .from
                .as_ref()
                .and_then(|from| subnets.get(from))
                .unwrap_or(&empty);
            let pattern = match &rule.r#match {
                Some(m) => AclPattern::try_from((own, &empty, &m.crd()))
                    .map_err(|e| format!("rule {i}: {e}"))?,
                None => AclPattern::default(),
            };
            policy.rules.push(IngressRule {
                from: rule.from.clone(),
                pattern,
                action,
            });
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::{Value, json};

    use super::*;

    fn spec(policy: &Value) -> GatewayAgentSpec {
        serde_json::from_value(json!({
            "gateway": { "annotations": { INGRESS_POLICY: policy.to_string() } }
        }))
        .unwrap()
    }

    /// The documented example converts: a drop, and a police on a prefixed meter.
    #[test]
    fn the_example_converts() {
        let policy = ingress_policy(&spec(&json!({
            "version": 0,
            "meters": { "inbound": { "pkts": { "rate": "2M" }, "bits": { "rate": "20G" } } },
            "rules": [
                { "from": "internet", "match": { "proto": "udp", "src": [{ "ports": ["123"] }] }, "action": "drop" },
                { "from": "internet", "action": "police", "meter": "inbound" }
            ]
        })))
        .unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].action, IngressAction::Drop);
        assert_eq!(
            policy.rules[1].action,
            IngressAction::Police("ingress/inbound".into())
        );
        assert!(policy.meters.contains_key("ingress/inbound"));
    }

    /// No annotation, no policy.
    #[test]
    fn absent_is_empty() {
        let bare: GatewayAgentSpec = serde_json::from_value(json!({})).unwrap();
        assert!(ingress_policy(&bare).unwrap().is_empty());
    }

    /// Actions and meters must agree, and the schema is strict. (Whether a meter exists is
    /// `IngressPolicy::validate`'s.)
    #[test]
    fn invalid_policies_are_rejected() {
        let rejected = |rules: Value| {
            ingress_policy(&spec(&json!({
                "version": 0,
                "meters": { "m": { "pkts": { "rate": "1k" } } },
                "rules": rules
            })))
            .is_err()
        };
        assert!(rejected(json!([{ "action": "drop", "meter": "m" }])));
        assert!(rejected(json!([{ "action": "police" }])));
        assert!(rejected(json!([{ "action": "allow" }])));
        assert!(rejected(json!([{ "action": "drop", "to": "x" }])));
        assert!(!rejected(json!([{ "action": "drop" }])));
        assert!(ingress_policy(&spec(&json!({ "version": 1, "rules": [] }))).is_err());
    }
}
