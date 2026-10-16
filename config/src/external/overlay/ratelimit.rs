// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rate limits: policing what a VPC sends towards a destination.
//!
//! There are two tables of rate limits: one limits bytes, the other packets. Each rate limit meters,
//! as one aggregate, every packet a VPC sends to a destination prefix, colors it with a MEF 10
//! profile, and decides what happens to it by its color. Within a table, the rate limit with the
//! longest matching destination meters a packet, and the others do not: nested limits in one table do
//! not add up. The two tables are independent, so a packet can be metered by a byte limit and a packet
//! limit on different destinations.
//!
//! A packet meets the byte table first and then the packet table, and the packet table's meter is
//! color-aware: it never colors a packet better than the byte table did. Each table acts on the color
//! it gives, in turn, so a packet the byte table drops never reaches the packet table, and when both
//! remark one, the packet table's remark is the one that stays.

use super::vpc::ValidatedVpcTable;
use crate::ConfigError;
use lpm::prefix::Prefix;
use net::ip::dscp::Dscp;
use net::vxlan::Vni;
use policer::Profile;
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
    /// The rates and bursts, in bytes or packets as the rate limit's table counts.
    pub profile: Profile,
    pub actions: ColorActions,
}

/// One table of rate limits, by name.
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
    /// same packets: one packet is metered by one rate limit of a table, the one whose destination is
    /// the longest match, so two with the same VPC and destination would leave which one ambiguous.
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
    pub fn profile(&self) -> Profile {
        self.limit.profile
    }

    #[must_use]
    pub fn actions(&self) -> ColorActions {
        self.limit.actions
    }
}

/// One table of rate limits, validated, in name order.
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

/// Both tables of rate limits: the byte limits, and the packet limits after them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitTables {
    /// Limits on bytes a second.
    pub bytes: RateLimitTable,
    /// Limits on packets a second, color-aware of what the byte limits did.
    pub packets: RateLimitTable,
}

impl RateLimitTables {
    /// Check both tables against `vpcs`.
    ///
    /// # Errors
    ///
    /// As [`RateLimitTable::validate`], and refuses a name used in both tables: names identify rate
    /// limits wherever they are shown.
    pub fn validate(
        &self,
        vpcs: &ValidatedVpcTable,
    ) -> Result<ValidatedRateLimitTables, ConfigError> {
        if let Some(name) = self
            .bytes
            .0
            .keys()
            .find(|name| self.packets.0.contains_key(*name))
        {
            return Err(ConfigError::DuplicateRateLimit(name.clone()));
        }
        Ok(ValidatedRateLimitTables {
            bytes: self.bytes.validate(vpcs)?,
            packets: self.packets.validate(vpcs)?,
        })
    }

    /// How many rate limits there are, in both tables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.0.len() + self.packets.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Both tables of rate limits, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedRateLimitTables {
    bytes: ValidatedRateLimits,
    packets: ValidatedRateLimits,
}

impl ValidatedRateLimitTables {
    /// The byte limits.
    #[must_use]
    pub fn bytes(&self) -> &ValidatedRateLimits {
        &self.bytes
    }

    /// The packet limits.
    #[must_use]
    pub fn packets(&self) -> &ValidatedRateLimits {
        &self.packets
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimit, RateLimitTable, RateLimitTables};
    use crate::ConfigError;
    use crate::external::overlay::vpc::{Vpc, VpcTable};
    use crate::external::overlay::vpcpeering::VpcPeeringTable;
    use policer::{Profile, Rate};
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
            profile: Profile::new(rate, 10_000, None, 0).unwrap(),
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

    #[test]
    fn a_name_is_used_in_one_table_only() {
        let mut tables = RateLimitTables::default();
        tables
            .bytes
            .add(limit("web", "vpc-1", "10.1.0.0/16"))
            .unwrap();
        tables
            .packets
            .add(limit("web", "vpc-1", "10.2.0.0/16"))
            .unwrap();
        assert_eq!(
            tables.validate(&vpcs()),
            Err(ConfigError::DuplicateRateLimit("web".to_string()))
        );
    }

    #[test]
    fn the_tables_meter_independently() {
        // The same VPC and destination in both tables is a byte limit and a packet limit on the same
        // traffic, not an overlap.
        let mut tables = RateLimitTables::default();
        tables
            .bytes
            .add(limit("bytes", "vpc-1", "10.1.0.0/16"))
            .unwrap();
        tables
            .packets
            .add(limit("packets", "vpc-1", "10.1.0.0/16"))
            .unwrap();
        let validated = tables.validate(&vpcs()).unwrap();
        assert_eq!(validated.bytes().len(), 1);
        assert_eq!(validated.packets().len(), 1);
    }
}
