// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rate limits: policing what a VPC sends towards a destination.
//!
//! Each rate limit meters, as one aggregate, every packet a VPC sends to a destination prefix, and
//! decides what happens to it by the color the meter gives it (RFC 2697, 2698 or 4115).

use super::vpc::ValidatedVpcTable;
use crate::ConfigError;
use lpm::prefix::Prefix;
use net::ip::dscp::Dscp;
use net::vxlan::Vni;
use policer::Limits;
use std::collections::{BTreeMap, HashMap};

/// What happens to a packet of one color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorAction {
    /// Forward it unchanged.
    Pass,
    /// Forward it with its DSCP rewritten.
    Remark(Dscp),
    /// Drop it.
    Drop,
}

/// What happens to a packet of each color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorActions {
    pub green: ColorAction,
    pub yellow: ColorAction,
    pub red: ColorAction,
}

impl Default for ColorActions {
    /// Police: pass what is within the limits, drop the rest.
    fn default() -> Self {
        ColorActions {
            green: ColorAction::Pass,
            yellow: ColorAction::Pass,
            red: ColorAction::Drop,
        }
    }
}

/// One rate limit, as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    /// Names the rate limit; unique among them.
    pub name: String,
    /// The VPC whose traffic is limited.
    pub vpc: String,
    /// Where that traffic is going, as the VPC addresses it (before any NAT).
    pub destination: Prefix,
    pub limits: Limits,
    pub actions: ColorActions,
}

/// Every rate limit, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitTable(BTreeMap<String, RateLimit>);

impl RateLimitTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `limit`.
    ///
    /// # Errors
    ///
    /// Refuses a second rate limit by the same name.
    pub fn add(&mut self, limit: RateLimit) -> Result<(), ConfigError> {
        if self.0.contains_key(&limit.name) {
            return Err(ConfigError::DuplicateRateLimit(limit.name));
        }
        self.0.insert(limit.name.clone(), limit);
        Ok(())
    }

    pub fn values(&self) -> impl Iterator<Item = &RateLimit> {
        self.0.values()
    }

    /// Check every rate limit against `vpcs`.
    ///
    /// # Errors
    ///
    /// Refuses a rate limit on a VPC that does not exist, and two rate limits that would meter the
    /// same packets: one packet is metered by one rate limit, the one whose destination is the longest
    /// match, so two with the same VPC and destination would leave which one ambiguous.
    pub fn validate(&self, vpcs: &ValidatedVpcTable) -> Result<ValidatedRateLimits, ConfigError> {
        let mut seen: HashMap<(Vni, Prefix), &str> = HashMap::new();
        let mut validated = Vec::with_capacity(self.0.len());
        for limit in self.0.values() {
            let vni = vpcs
                .get_vpc(&limit.vpc)
                .ok_or_else(|| ConfigError::RateLimitNoSuchVpc {
                    limit: limit.name.clone(),
                    vpc: limit.vpc.clone(),
                })?
                .vni();
            if let Some(other) = seen.insert((vni, limit.destination), &limit.name) {
                return Err(ConfigError::RateLimitsOverlap(
                    other.to_string(),
                    limit.name.clone(),
                ));
            }
            validated.push(ValidatedRateLimit {
                limit: limit.clone(),
                vni,
            });
        }
        Ok(ValidatedRateLimits(validated))
    }
}

/// A rate limit whose VPC exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRateLimit {
    limit: RateLimit,
    vni: Vni,
}

impl ValidatedRateLimit {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.limit.name
    }

    #[must_use]
    pub fn vpc(&self) -> &str {
        &self.limit.vpc
    }

    /// The VNI of the rate limit's VPC.
    #[must_use]
    pub fn vni(&self) -> Vni {
        self.vni
    }

    #[must_use]
    pub fn destination(&self) -> Prefix {
        self.limit.destination
    }

    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limit.limits
    }

    #[must_use]
    pub fn actions(&self) -> ColorActions {
        self.limit.actions
    }
}

/// Every rate limit, validated, in name order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedRateLimits(Vec<ValidatedRateLimit>);

impl ValidatedRateLimits {
    pub fn iter(&self) -> impl Iterator<Item = &ValidatedRateLimit> {
        self.0.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimit, RateLimitTable};
    use crate::ConfigError;
    use crate::external::overlay::vpc::{Vpc, VpcTable};
    use crate::external::overlay::vpcpeering::VpcPeeringTable;
    use policer::{Limits, Rate, SingleRate};
    use std::num::NonZeroU64;

    fn vpcs() -> crate::external::overlay::vpc::ValidatedVpcTable {
        let mut vpcs = VpcTable::new();
        vpcs.add(Vpc::new("vpc-1", "AAAAA", 3000).unwrap()).unwrap();
        vpcs.collect_peerings(&VpcPeeringTable::new())
            .validate()
            .unwrap()
    }

    fn limit(name: &str, vpc: &str, destination: &str) -> RateLimit {
        let rate = Rate::new(NonZeroU64::new(1_000_000).unwrap());
        RateLimit {
            name: name.to_string(),
            vpc: vpc.to_string(),
            destination: destination.parse().unwrap(),
            limits: Limits::new(Some(SingleRate::new(rate, 10_000, 0).unwrap().into()), None)
                .unwrap(),
            actions: super::ColorActions::default(),
        }
    }

    #[test]
    fn a_rate_limit_resolves_its_vpc_to_a_vni() {
        let mut table = RateLimitTable::new();
        table.add(limit("web", "vpc-1", "10.1.0.0/16")).unwrap();
        let validated = table.validate(&vpcs()).unwrap();
        let only = validated.iter().next().unwrap();
        assert_eq!(only.vni().as_u32(), 3000);
    }

    #[test]
    fn names_are_unique() {
        let mut table = RateLimitTable::new();
        table.add(limit("web", "vpc-1", "10.1.0.0/16")).unwrap();
        assert_eq!(
            table.add(limit("web", "vpc-1", "10.2.0.0/16")),
            Err(ConfigError::DuplicateRateLimit("web".to_string()))
        );
    }

    #[test]
    fn the_vpc_must_exist() {
        let mut table = RateLimitTable::new();
        table.add(limit("web", "vpc-9", "10.1.0.0/16")).unwrap();
        assert_eq!(
            table.validate(&vpcs()),
            Err(ConfigError::RateLimitNoSuchVpc {
                limit: "web".to_string(),
                vpc: "vpc-9".to_string()
            })
        );
    }

    #[test]
    fn two_rate_limits_cannot_meter_the_same_packets() {
        let mut table = RateLimitTable::new();
        table.add(limit("a", "vpc-1", "10.1.0.0/16")).unwrap();
        table.add(limit("b", "vpc-1", "10.1.0.0/16")).unwrap();
        assert_eq!(
            table.validate(&vpcs()),
            Err(ConfigError::RateLimitsOverlap(
                "a".to_string(),
                "b".to_string()
            ))
        );
        // Nested destinations are fine: the longest match decides.
        let mut table = RateLimitTable::new();
        table.add(limit("a", "vpc-1", "10.1.0.0/16")).unwrap();
        table.add(limit("b", "vpc-1", "10.1.1.0/24")).unwrap();
        assert_eq!(table.validate(&vpcs()).unwrap().len(), 2);
    }
}
