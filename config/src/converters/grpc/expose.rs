// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ::gateway_config::google;
use gateway_config::config as gateway_config;

use std::convert::TryFrom;

use crate::external::overlay::vpcpeering::{
    VpcExpose, VpcExposeNatConfig, VpcExposeStatefulNat, VpcExposeStatelessNat,
};
use lpm::prefix::{Prefix, PrefixString};

impl TryFrom<&gateway_config::Expose> for VpcExpose {
    type Error = String;

    fn try_from(expose: &gateway_config::Expose) -> Result<Self, Self::Error> {
        // Start with an empty expose
        let mut vpc_expose = VpcExpose::empty();

        // Process PeeringIP rules
        for ip in &expose.ips {
            if let Some(rule) = &ip.rule {
                match rule {
                    gateway_config::peering_i_ps::Rule::Cidr(cidr) => {
                        let prefix = Prefix::try_from(PrefixString(cidr))
                            .map_err(|e| format!("Invalid CIDR format: {cidr}: {e}"))?;
                        vpc_expose = vpc_expose.ip(prefix);
                    }
                    gateway_config::peering_i_ps::Rule::Not(not) => {
                        let prefix = Prefix::try_from(PrefixString(not))
                            .map_err(|e| format!("Invalid CIDR format: {not}: {e}"))?;
                        vpc_expose = vpc_expose.not(prefix);
                    }
                }
            } else {
                return Err("PeeringIPs must have either 'cidr' or 'not' field set".to_string());
            }
        }

        // Process PeeringAs rules
        for as_rule in &expose.r#as {
            if let Some(rule) = &as_rule.rule {
                match rule {
                    gateway_config::peering_as::Rule::Cidr(cidr) => {
                        let prefix = Prefix::try_from(PrefixString(cidr))
                            .map_err(|e| format!("Invalid CIDR format: {cidr}: {e}"))?;
                        vpc_expose = vpc_expose.as_range(prefix);
                    }
                    gateway_config::peering_as::Rule::Not(ip_exclude) => {
                        let prefix = Prefix::try_from(PrefixString(ip_exclude))
                            .map_err(|e| format!("Invalid CIDR format: {ip_exclude}: {e}"))?;
                        vpc_expose = vpc_expose.not_as(prefix);
                    }
                }
            } else {
                return Err("PeeringAs must have either 'cidr' or 'not' field set".to_string());
            }
        }

        if !expose.r#as.is_empty() {
            vpc_expose = vpc_expose.make_nat();
            if let (Some(grpc_nat), Some(nat)) = (expose.nat.as_ref(), vpc_expose.nat.as_mut()) {
                #[allow(clippy::default_constructed_unit_structs)]
                match grpc_nat {
                    gateway_config::expose::Nat::Stateless(_) => {
                        nat.config =
                            VpcExposeNatConfig::Stateless(VpcExposeStatelessNat::default());
                    }
                    gateway_config::expose::Nat::Stateful(grpc_s) => {
                        nat.config = VpcExposeNatConfig::Stateful(VpcExposeStatefulNat {
                            idle_timeout: grpc_s
                                .idle_timeout
                                .ok_or("stateful nat requires idle_timeout, got None".to_string())
                                .and_then(|t| {
                                    std::time::Duration::try_from(t)
                                        .map_err(|e| format!("Invalid duration: {e}"))
                                })?,
                        });
                    }
                }
            }
        }

        Ok(vpc_expose)
    }
}

impl TryFrom<&VpcExpose> for gateway_config::Expose {
    type Error = String;

    fn try_from(expose: &VpcExpose) -> Result<Self, Self::Error> {
        let mut ips = Vec::new();
        let mut as_rules = Vec::new();

        // Convert IP inclusion rules
        for prefix in &expose.ips {
            let rule = gateway_config::peering_i_ps::Rule::Cidr(prefix.to_string());
            ips.push(gateway_config::PeeringIPs { rule: Some(rule) });
        }

        // Convert IP exclusion rules
        for prefix in &expose.nots {
            let rule = gateway_config::peering_i_ps::Rule::Not(prefix.to_string());
            ips.push(gateway_config::PeeringIPs { rule: Some(rule) });
        }

        let nat = if let Some(nat) = expose.nat.as_ref() {
            // Convert AS inclusion rules
            for prefix in &nat.as_range {
                let rule = gateway_config::peering_as::Rule::Cidr(prefix.to_string());
                as_rules.push(gateway_config::PeeringAs { rule: Some(rule) });
            }

            // Convert AS exclusion rules
            for prefix in &nat.not_as {
                let rule = gateway_config::peering_as::Rule::Not(prefix.to_string());
                as_rules.push(gateway_config::PeeringAs { rule: Some(rule) });
            }

            match &nat.config {
                VpcExposeNatConfig::Stateful(config) => {
                    let idle_timeout = google::protobuf::Duration::try_from(config.idle_timeout)
                        .map_err(|e| format!("Unable to convert stateful nat idle timeout: {e}"))?;
                    Some(gateway_config::expose::Nat::Stateful(
                        gateway_config::PeeringStatefulNat {
                            idle_timeout: Some(idle_timeout),
                        },
                    ))
                }
                VpcExposeNatConfig::Stateless(_) => Some(gateway_config::expose::Nat::Stateless(
                    gateway_config::PeeringStatelessNat {},
                )),
            }
        } else {
            None
        };
        Ok(gateway_config::Expose {
            ips,
            r#as: as_rules,
            nat,
        })
    }
}
