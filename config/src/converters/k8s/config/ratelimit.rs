// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Peering rate limits from `gateway.alpha.githedgehog.com/rate-limits`.
//!
//! The annotation is versioned JSON with one `meters` map and an ordered `rules` list.
//! A meter has optional `bits` and `pkts` profiles, each with `rate`, optional `burst`,
//! and optional `excess: { rate, setDSCP }`. Rates use Kubernetes Quantity syntax;
//! bursts use metav1.Duration strings and default to 100 ms, with room for one packet.
//! Rules use the peering ACL's `from`, `to`, and `match` fields and name one `meter`.
//! Omitting both endpoints applies the rule in both directions. First match wins.
//!
//! See the [API example](https://github.com/githedgehog/dataplane/pull/1949).

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::time::Duration;

use k8s_intf::gateway_agent_crd::{
    GatewayAgentPeeringsAclRulesMatch, GatewayAgentPeeringsAclRulesMatchDst,
    GatewayAgentPeeringsAclRulesMatchSrc, GatewayAgentPeeringsAclRulesMatchTcpFilters,
    GatewayAgentPeeringsAclRulesMatchTcpFiltersFlags, GatewayAgentSpec,
};
use net::ip::dscp::Dscp;
use policer::{Profile, Rate};
use serde::Deserialize;

use super::{SubnetMap, VpcSubnetMap};
use crate::converters::k8s::FromK8sConversionError;
use crate::external::overlay::acl::AclPattern;
use crate::external::overlay::ratelimit::{
    ColorAction, ColorActions, Meter, MeterProfile, RateLimitRule, RateLimitTables,
};
use units::RateQuantity;

#[cfg(test)]
mod tests;
mod units;

/// The namespace reserved for alpha gateway annotations.
pub const ALPHA_PREFIX: &str = "gateway.alpha.githedgehog.com/";
/// The annotation carrying a peering's rate-limit policy.
pub const RATE_LIMITS: &str = "gateway.alpha.githedgehog.com/rate-limits";

/// Convert each peering's rate-limit annotation.
///
/// # Errors
///
/// Rejects unknown alpha gateway annotations, versions, fields, and invalid policies.
pub fn rate_limits(spec: &GatewayAgentSpec) -> Result<RateLimitTables, FromK8sConversionError> {
    let mut tables = RateLimitTables::default();
    let subnets = spec
        .vpcs
        .as_ref()
        .map(super::overlay::extract_subnets)
        .transpose()?
        .unwrap_or_default();
    for (peering, config) in spec.peerings.iter().flatten() {
        for (key, value) in config.annotations.iter().flatten() {
            if !key.starts_with(ALPHA_PREFIX) {
                continue;
            }
            if key != RATE_LIMITS {
                return Err(FromK8sConversionError::NotAllowed(format!(
                    "unknown alpha gateway annotation {key} on peering {peering}"
                )));
            }
            let invalid = |detail: String| {
                FromK8sConversionError::InvalidData(format!(
                    "{RATE_LIMITS} on peering {peering}: {detail}"
                ))
            };
            let policy = parse(value).map_err(invalid)?;
            let vpcs = config
                .peering
                .as_ref()
                .ok_or_else(|| invalid("peering has no VPCs".into()))?;
            let names: Vec<_> = vpcs.keys().collect();
            let [left, right] = names.as_slice() else {
                return Err(invalid("peering must contain two VPCs".into()));
            };
            policy
                .convert(peering, left, right, &subnets, &mut tables)
                .map_err(invalid)?;
        }
    }
    Ok(tables)
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
    meters: BTreeMap<String, MeterSpec>,
    rules: Vec<RuleSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeterSpec {
    bits: Option<Component>,
    pkts: Option<Component>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    rate: RateQuantity,
    burst: Option<String>,
    excess: Option<Excess>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Excess {
    rate: RateQuantity,
    #[serde(rename = "setDSCP")]
    set_dscp: Option<DscpSpec>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DscpSpec {
    Number(u8),
    Text(String),
}

impl DscpSpec {
    fn convert(&self) -> Result<Dscp, String> {
        let number = match self {
            Self::Number(n) => *n,
            Self::Text(s) => s
                .parse::<u8>()
                .map_err(|_| "setDSCP must be an integer from 0 to 63")?,
        };
        Dscp::new(number).map_err(|_| "setDSCP must be an integer from 0 to 63".into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    from: Option<String>,
    to: Option<String>,
    r#match: Option<Match>,
    meter: String,
}

// Generated CRD types accept unknown fields. Keep the annotation strict, then use the ACL converter.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Match {
    src: Option<Vec<MatchEntry>>,
    dst: Option<Vec<MatchEntry>>,
    proto: Option<String>,
    #[serde(rename = "tcpFilters")]
    tcp_filters: Option<TcpFilters>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpFilters {
    flags: Option<TcpFlagsSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpFlagsSpec {
    fin: Option<bool>,
    syn: Option<bool>,
    rst: Option<bool>,
    psh: Option<bool>,
    ack: Option<bool>,
    urg: Option<bool>,
    ece: Option<bool>,
    cwr: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchEntry {
    cidr: Option<String>,
    #[serde(rename = "vpcSubnet")]
    vpc_subnet: Option<String>,
    ports: Option<Vec<String>>,
}

impl Match {
    fn crd(&self) -> GatewayAgentPeeringsAclRulesMatch {
        GatewayAgentPeeringsAclRulesMatch {
            proto: self.proto.clone(),
            tcp_filters: self.tcp_filters.as_ref().map(|filters| {
                GatewayAgentPeeringsAclRulesMatchTcpFilters {
                    flags: filters.flags.as_ref().map(|f| {
                        GatewayAgentPeeringsAclRulesMatchTcpFiltersFlags {
                            fin: f.fin,
                            syn: f.syn,
                            rst: f.rst,
                            psh: f.psh,
                            ack: f.ack,
                            urg: f.urg,
                            ece: f.ece,
                            cwr: f.cwr,
                        }
                    }),
                }
            }),
            src: self.src.as_ref().map(|entries| {
                entries
                    .iter()
                    .map(|e| GatewayAgentPeeringsAclRulesMatchSrc {
                        cidr: e.cidr.clone(),
                        vpc_subnet: e.vpc_subnet.clone(),
                        ports: e.ports.clone(),
                    })
                    .collect()
            }),
            dst: self.dst.as_ref().map(|entries| {
                entries
                    .iter()
                    .map(|e| GatewayAgentPeeringsAclRulesMatchDst {
                        cidr: e.cidr.clone(),
                        vpc_subnet: e.vpc_subnet.clone(),
                        ports: e.ports.clone(),
                    })
                    .collect()
            }),
        }
    }
}

impl Policy {
    fn convert(
        &self,
        peering: &str,
        left: &str,
        right: &str,
        subnets: &VpcSubnetMap,
        tables: &mut RateLimitTables,
    ) -> Result<(), String> {
        for (name, spec) in &self.meters {
            if name.is_empty() {
                return Err("meter needs a name".into());
            }
            if spec.bits.is_none() && spec.pkts.is_none() {
                return Err(format!("meter {name:?} needs bits or pkts"));
            }
            let invalid = |e| format!("meter {name:?}: {e}");
            let meter = Meter {
                bytes: spec
                    .bits
                    .as_ref()
                    .map(|c| c.convert(8, 9216))
                    .transpose()
                    .map_err(invalid)?,
                packets: spec
                    .pkts
                    .as_ref()
                    .map(|c| c.convert(1, 1))
                    .transpose()
                    .map_err(invalid)?,
            };
            tables.meters.insert(format!("{peering}/{name}"), meter);
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if !self.meters.contains_key(&rule.meter) {
                return Err(format!("rule {i}: unknown meter {:?}", rule.meter));
            }
            let directions = if rule.from.is_none() && rule.to.is_none() {
                vec![
                    (left.to_string(), right.to_string()),
                    (right.to_string(), left.to_string()),
                ]
            } else {
                vec![
                    super::acl::complete_from_to(
                        &format!("rate limit {i}"),
                        rule.from.as_deref().unwrap_or_default(),
                        rule.to.as_deref().unwrap_or_default(),
                        left,
                        right,
                    )
                    .map_err(|e| e.to_string())?,
                ]
            };
            for (from, to) in directions {
                let empty = SubnetMap::new();
                let pattern = match &rule.r#match {
                    Some(m) => AclPattern::try_from((
                        subnets.get(&from).unwrap_or(&empty),
                        subnets.get(&to).unwrap_or(&empty),
                        &m.crd(),
                    ))
                    .map_err(|e| format!("rule {i}: {e}"))?,
                    None => AclPattern::default(),
                };
                tables.rules.push(RateLimitRule {
                    peering: peering.into(),
                    from,
                    to,
                    pattern,
                    meter: format!("{peering}/{}", rule.meter),
                });
            }
        }
        Ok(())
    }
}

impl Component {
    fn convert(&self, divisor: u64, minimum: u64) -> Result<MeterProfile, String> {
        let rate = |q: &RateQuantity| -> Result<Rate, String> {
            let value = q.tokens(divisor)?;
            NonZeroU64::new(value)
                .map(Rate::new)
                .ok_or_else(|| "rate must be positive".into())
        };
        let committed = rate(&self.rate)?;
        let burst = self
            .burst
            .as_deref()
            .map(units::duration)
            .transpose()?
            .unwrap_or(Duration::from_millis(100));
        let capacity = |rate: Rate| -> Result<u64, String> {
            let tokens = u128::from(rate.per_second().get())
                .checked_mul(burst.as_nanos())
                .ok_or("burst is too large")?
                / 1_000_000_000;
            let tokens = u64::try_from(tokens).map_err(|_| "burst is too large")?;
            if self.burst.is_some() && tokens < minimum {
                return Err(format!(
                    "burst must hold at least {minimum} {}",
                    if divisor == 8 { "bytes" } else { "packet" }
                ));
            }
            Ok(tokens.max(minimum))
        };
        let excess = self.excess.as_ref().map(|e| rate(&e.rate)).transpose()?;
        let profile = Profile::new(
            committed,
            capacity(committed)?,
            excess,
            excess.map(capacity).transpose()?.unwrap_or(0),
        )
        .map_err(|e| e.to_string())?;
        let yellow = self
            .excess
            .as_ref()
            .and_then(|e| e.set_dscp.as_ref())
            .map(DscpSpec::convert)
            .transpose()?
            .map_or(ColorAction::Pass, ColorAction::Remark);
        Ok(MeterProfile {
            profile,
            actions: ColorActions {
                yellow,
                ..ColorActions::default()
            },
        })
    }
}
