// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::convert::TryFrom;

use k8s_intf::gateway_agent_crd::{
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNat,
};
use lpm::prefix::{PortRange, Prefix, PrefixString, PrefixWithOptionalPorts, PrefixWithPorts};

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::k8s::config::SubnetMap;
use crate::external::overlay::vpcpeering::VpcExpose;

fn parse_port_ranges(ports_str: &str) -> Result<Vec<PortRange>, FromK8sConversionError> {
    ports_str
        // Split port ranges for prefix on ','
        .split(',')
        .map(|port_range_str| {
            port_range_str.trim().parse::<PortRange>().map_err(|e| {
                FromK8sConversionError::ParseError(format!(
                    "Invalid port range {port_range_str}: {e}"
                ))
            })
        })
        .collect()
}

fn map_ports(
    prefix: Prefix,
    ports_opt: Option<&str>,
) -> Result<Vec<PrefixWithOptionalPorts>, FromK8sConversionError> {
    let Some(ports_str) = ports_opt else {
        return Ok(vec![PrefixWithOptionalPorts::from(prefix)]);
    };
    parse_port_ranges(ports_str)?
        .into_iter()
        // Derive one PrefixWithOptionalPorts for each port range
        .map(|port_range| {
            Ok(PrefixWithOptionalPorts::PrefixPorts(PrefixWithPorts::new(
                prefix, port_range,
            )))
        })
        .collect::<Result<Vec<_>, _>>()
}

fn process_ip_block(
    mut vpc_expose: VpcExpose,
    ip: &GatewayAgentPeeringsPeeringExposeIps,
    subnets: &SubnetMap,
) -> Result<VpcExpose, FromK8sConversionError> {
    match (&ip.cidr, &ip.vpc_subnet, &ip.not) {
        (None, None, None) => {
            return Err(FromK8sConversionError::MissingData(
                "Expose ip object must specify subnet, cidr, or not".to_string(),
            ));
        }
        (Some(_), None, Some(_)) => {
            return Err(FromK8sConversionError::Invalid(
                "Expose ip block must specify either cidr or not, not both".to_string(),
            ));
        }
        (None, Some(_), Some(_)) => {
            return Err(FromK8sConversionError::Invalid(
                "Expose ip block must specify either subnet or not, not both".to_string(),
            ));
        }
        (Some(_), Some(_), None) => {
            return Err(FromK8sConversionError::Invalid(
                "Expose ip block must specify either subnet or cidr, not both".to_string(),
            ));
        }
        (Some(_), Some(_), Some(_)) => {
            return Err(FromK8sConversionError::Invalid(
                "Expose ip block must specify either subnet, cidr, or not, not all three"
                    .to_string(),
            ));
        }
        (None, Some(subnet_name), None) => {
            let prefix = subnets.get(subnet_name.as_str()).ok_or_else(|| {
                FromK8sConversionError::Invalid(format!(
                    "Expose references unknown VPC subnet {subnet_name}"
                ))
            })?;
            for prefix in map_ports(*prefix, ip.ports.as_deref())? {
                vpc_expose = vpc_expose.ip(prefix);
            }
        }
        (Some(cidr), None, None) => {
            let prefix = cidr.parse::<Prefix>().map_err(|e| {
                FromK8sConversionError::ParseError(format!("Invalid CIDR format: {cidr}: {e}"))
            })?;
            for prefix in map_ports(prefix, ip.ports.as_deref())? {
                vpc_expose = vpc_expose.ip(prefix);
            }
        }
        (None, None, Some(not)) => {
            let prefix = Prefix::try_from(PrefixString(not.as_str())).map_err(|e| {
                FromK8sConversionError::Invalid(format!("Invalid CIDR format: {not}: {e}"))
            })?;
            for prefix in map_ports(prefix, ip.ports.as_deref())? {
                vpc_expose = vpc_expose.not(prefix);
            }
        }
    }
    Ok(vpc_expose)
}

fn process_as_block(
    mut vpc_expose: VpcExpose,
    ip: &GatewayAgentPeeringsPeeringExposeAs,
) -> Result<VpcExpose, FromK8sConversionError> {
    match (&ip.cidr, &ip.not) {
        (None, None) => {
            return Err(FromK8sConversionError::MissingData(
                "Expose as object must specify cidr or not".to_string(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(FromK8sConversionError::Invalid(
                "Expose as block must specify either cidr or not, not both".to_string(),
            ));
        }
        (Some(cidr), None) => {
            let prefix = cidr.parse::<Prefix>().map_err(|e| {
                FromK8sConversionError::ParseError(format!("Invalid CIDR format: {cidr}: {e}"))
            })?;
            for prefix in map_ports(prefix, ip.ports.as_deref())? {
                vpc_expose = vpc_expose.as_range(prefix);
            }
        }
        (None, Some(not)) => {
            let prefix = Prefix::try_from(PrefixString(not.as_str())).map_err(|e| {
                FromK8sConversionError::Invalid(format!("Invalid CIDR format: {not}: {e}"))
            })?;
            for prefix in map_ports(prefix, ip.ports.as_deref())? {
                vpc_expose = vpc_expose.not_as(prefix);
            }
        }
    }
    Ok(vpc_expose)
}

fn process_nat_block(
    vpc_expose: VpcExpose,
    nat: Option<&GatewayAgentPeeringsPeeringExposeNat>,
) -> Result<VpcExpose, FromK8sConversionError> {
    match nat {
        Some(nat) => match (&nat.stateful, &nat.stateless) {
            (Some(_), Some(_)) => Err(FromK8sConversionError::Invalid(
                "Cannot have both stateful and stateless nat configured on the same expose block"
                    .to_string(),
            )),
            (Some(stateful), None) => {
                let idle_timeout = stateful.idle_timeout.map(std::time::Duration::from);
                vpc_expose
                    .make_stateful_nat(idle_timeout)
                    .map_err(|e| FromK8sConversionError::Invalid(e.to_string()))
            }
            (None, Some(_)) => vpc_expose
                .make_stateless_nat()
                .map_err(|e| FromK8sConversionError::Invalid(e.to_string())),
            (None, None) => Ok(vpc_expose), // Rely on default behavior for NAT
        },
        None => Ok(vpc_expose),
    }
}
impl TryFrom<(&SubnetMap, &GatewayAgentPeeringsPeeringExpose)> for VpcExpose {
    type Error = FromK8sConversionError;

    fn try_from(
        (subnets, expose): (&SubnetMap, &GatewayAgentPeeringsPeeringExpose),
    ) -> Result<Self, Self::Error> {
        let mut vpc_expose = VpcExpose::empty();

        // check if it is a default expose
        vpc_expose.default = expose.default.unwrap_or(false);
        if vpc_expose.default {
            if expose.ips.as_ref().is_some_and(|ips| !ips.is_empty()) {
                return Err(FromK8sConversionError::Invalid(
                    "A Default expose can't contain prefixes".to_string(),
                ));
            }
            if expose.r#as.as_ref().is_some_and(|r#as| !r#as.is_empty()) {
                return Err(FromK8sConversionError::Invalid(
                    "A Default expose can't contain 'as' prefixes".to_string(),
                ));
            }
            return Ok(vpc_expose);
        }

        // Process PeeringIP rules
        if let Some(ips) = expose.ips.as_ref() {
            if ips.is_empty() {
                return Err(FromK8sConversionError::MissingData(
                    "Expose must expose something, ips block is empty vector".to_string(),
                ));
            }
            for ip in ips {
                vpc_expose = process_ip_block(vpc_expose, ip, subnets)?;
            }
        } else {
            return Err(FromK8sConversionError::MissingData(
                "Expose must expose some IPs, ips block is missing".to_string(),
            ));
        }

        vpc_expose = process_nat_block(vpc_expose, expose.nat.as_ref())?;

        if let Some(ases) = expose.r#as.as_ref() {
            for r#as in ases {
                vpc_expose = process_as_block(vpc_expose, r#as)?;
            }
        }

        Ok(vpc_expose)
    }
}

#[cfg(test)]
mod test {
    use crate::external::overlay::vpcpeering::VpcExposeNatConfig;

    use super::*;

    #[test]
    fn test_map_ports_no_ports() {
        let prefix = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, None).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix(), prefix);
    }

    #[test]
    fn test_map_ports_single_port() {
        let prefix = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, Some("80")).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix(), prefix);
        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[0] {
            assert_eq!(pp.ports().start(), 80);
            assert_eq!(pp.ports().end(), 80);
        } else {
            panic!("Expected PrefixPorts variant");
        }
    }

    #[test]
    fn test_map_ports_single_range() {
        let prefix = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, Some("8000-8080")).unwrap();

        assert_eq!(result.len(), 1);
        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[0] {
            assert_eq!(pp.ports().start(), 8000);
            assert_eq!(pp.ports().end(), 8080);
        } else {
            panic!("Expected PrefixPorts variant");
        }
    }

    #[test]
    fn test_map_ports_multiple_ranges() {
        let prefix = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, Some("80,443,8000-8080")).unwrap();

        assert_eq!(result.len(), 3);

        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[0] {
            assert_eq!(pp.prefix(), prefix);
            assert_eq!(pp.ports().start(), 80);
            assert_eq!(pp.ports().end(), 80);
        } else {
            panic!("Expected PrefixPorts variant");
        }

        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[1] {
            assert_eq!(pp.prefix(), prefix);
            assert_eq!(pp.ports().start(), 443);
            assert_eq!(pp.ports().end(), 443);
        } else {
            panic!("Expected PrefixPorts variant");
        }

        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[2] {
            assert_eq!(pp.prefix(), prefix);
            assert_eq!(pp.ports().start(), 8000);
            assert_eq!(pp.ports().end(), 8080);
        } else {
            panic!("Expected PrefixPorts variant");
        }
    }

    #[test]
    fn test_map_ports_invalid_port_in_list() {
        let prefix = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, Some("80,invalid,443"));

        assert!(result.is_err());
        assert!(matches!(result, Err(FromK8sConversionError::ParseError(_))));
    }

    #[test]
    fn test_map_ports_empty_string() {
        let prefix = "10.0.0.0/24".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, Some(""));

        assert!(result.is_err());
    }

    #[test]
    fn test_map_ports_ipv6_prefix() {
        let prefix = "2001:db8::/32".parse::<Prefix>().unwrap();
        let result = map_ports(prefix, Some("80,443,8000-8080")).unwrap();

        assert_eq!(result.len(), 3);

        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[0] {
            assert_eq!(pp.prefix(), prefix);
            assert_eq!(pp.ports().start(), 80);
            assert_eq!(pp.ports().end(), 80);
        } else {
            panic!("Expected PrefixPorts variant");
        }

        if let PrefixWithOptionalPorts::PrefixPorts(pp) = &result[1] {
            assert_eq!(pp.prefix(), prefix);
            assert_eq!(pp.ports().start(), 443);
            assert_eq!(pp.ports().end(), 443);
        } else {
            panic!("Expected PrefixPorts variant");
        }
    }

    // See https://github.com/githedgehog/gateway/pull/268/changes#diff-a0a0f9914d0cR239-R271
    #[test]
    fn test_parse_port_ranges() {
        assert!(parse_port_ranges("").is_err()); // Reject empty string, we expect None
        assert!(parse_port_ranges("80").is_ok());
        assert!(parse_port_ranges("80-80").is_ok());
        assert!(parse_port_ranges("80,443").is_ok());
        assert!(parse_port_ranges("80,443,3000-3100").is_ok());
        assert!(parse_port_ranges("80,443,3000-3100,8080").is_ok());
        assert!(parse_port_ranges("80,443,3000-3100,8080").is_ok());
        assert!(parse_port_ranges("  80  ").is_ok());
        assert!(parse_port_ranges("  80  ,  443  ").is_ok());
        assert!(parse_port_ranges("  80  ,  443  ,  3000-3100  ").is_ok());
        assert!(parse_port_ranges("  80  ,443,3000-3100,8080").is_ok());
        assert!(parse_port_ranges("80-79").is_err());
        //assert!(parse_port_ranges("0").is_err()); // We support this internally
        assert!(parse_port_ranges("65536").is_err());
        assert!(parse_port_ranges("1-65536").is_err());
        //assert!(parse_port_ranges("0-80").is_err()); // We support this internally
        assert!(parse_port_ranges("-80").is_err());
        assert!(parse_port_ranges("80-").is_err());
        assert!(parse_port_ranges("  -  80  ").is_err());
        assert!(parse_port_ranges("  80  -  ").is_err());
        assert!(parse_port_ranges("1-80,65536").is_err());
        // Add another one: multiple commas
        assert!(parse_port_ranges("80,,443").is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_vpc_conversion() {
        let subnets = SubnetMap::from([
            (
                "subnet1".to_string(),
                "10.0.1.0/24".parse::<Prefix>().unwrap(),
            ),
            (
                "subnet2".to_string(),
                "10.0.2.0/24".parse::<Prefix>().unwrap(),
            ),
            (
                "subnet3".to_string(),
                "10.0.3.0/24".parse::<Prefix>().unwrap(),
            ),
            (
                "subnet4".to_string(),
                "10.0.4.0/24".parse::<Prefix>().unwrap(),
            ),
        ]);
        let expose_gen = k8s_intf::bolero::expose::LegalValueExposeGenerator::new(&subnets);
        bolero::check!()
            .with_generator(expose_gen)
            .for_each(|k8s_expose| {
                let expose = VpcExpose::try_from((&subnets, k8s_expose)).unwrap();
                let mut ips = expose
                    .ips
                    .iter()
                    .map(|p| {
                        (
                            p.prefix().to_string(),
                            p.ports().map(|pr| pr.to_string()).unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>();
                ips.sort();
                let mut nots = expose
                    .nots
                    .iter()
                    .map(|p| {
                        (
                            p.prefix().to_string(),
                            p.ports().map(|pr| pr.to_string()).unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>();
                nots.sort();

                let r#as = expose.nat.as_ref().map(|nat| {
                    let mut ret = nat
                        .as_range
                        .iter()
                        .map(|p| {
                            (
                                p.prefix().to_string(),
                                p.ports().map(|pr| pr.to_string()).unwrap_or_default(),
                            )
                        })
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });
                let not_as = expose.nat.as_ref().map(|nat| {
                    let mut ret = nat
                        .not_as
                        .iter()
                        .map(|p| {
                            (
                                p.prefix().to_string(),
                                p.ports().map(|pr| pr.to_string()).unwrap_or_default(),
                            )
                        })
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });

                let mut k8s_ips = k8s_expose
                    .ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .filter(|ip| ip.cidr.is_some())
                            .map(|ip| {
                                (
                                    ip.cidr.as_ref().unwrap().clone(),
                                    ip.ports.clone().unwrap_or_default(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or(vec![]);
                let mut k8s_nots = k8s_expose
                    .ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .filter(|ip| ip.not.is_some())
                            .map(|ip| {
                                (
                                    ip.not.as_ref().unwrap().clone(),
                                    ip.ports.clone().unwrap_or_default(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or(vec![]);
                k8s_nots.sort();
                let k8s_subnets = k8s_expose
                    .ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .filter(|ip| ip.vpc_subnet.is_some())
                            .map(|ip| {
                                (
                                    subnets
                                        .get(ip.vpc_subnet.as_ref().unwrap())
                                        .unwrap()
                                        .to_string(),
                                    ip.ports.clone().unwrap_or_default(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or(vec![]);
                k8s_ips.extend(k8s_subnets);
                k8s_ips.sort();

                let k8s_as = k8s_expose.r#as.as_ref().map(|r#as| {
                    let mut ret = r#as
                        .iter()
                        .filter(|r#as| r#as.cidr.is_some())
                        .map(|r#as| {
                            (
                                r#as.cidr.as_ref().unwrap().clone(),
                                r#as.ports.clone().unwrap_or_default(),
                            )
                        })
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });

                let k8s_not_as = k8s_expose.r#as.as_ref().map(|r#as| {
                    let mut ret = r#as
                        .iter()
                        .filter(|r#as| r#as.not.is_some())
                        .map(|r#as| {
                            (
                                r#as.not.as_ref().unwrap().clone(),
                                r#as.ports.clone().unwrap_or_default(),
                            )
                        })
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });

                assert_eq!(ips, k8s_ips);
                assert_eq!(nots, k8s_nots);
                assert_eq!(r#as, k8s_as);
                assert_eq!(not_as, k8s_not_as);
                match (expose.nat.as_ref(), k8s_expose.nat.as_ref()) {
                    (Some(nat), None) => {
                        assert!(
                            k8s_expose.r#as.is_some(),
                            "K8s does not have NAT set, but nat is configured: {expose}"
                        );
                        assert!(
                            nat.is_stateless(),
                            "Default NAT configured via 'as' by k8s, but nat is not stateless: {expose}"
                        );
                    }
                    (None, Some(_)) => {
                        panic!("K8s has NAT configured, but dataplane config does not")
                    }
                    (Some(nat), Some(k8s_nat)) => match &nat.config {
                        VpcExposeNatConfig::Stateful(c) => {
                            if let Some(k8s_stateful) = k8s_nat.stateful.as_ref() {
                                if let Some(k8s_idle_timeout) = k8s_stateful.idle_timeout {
                                    assert_eq!(c.idle_timeout, k8s_idle_timeout);
                                } else {
                                    assert_eq!(c.idle_timeout, std::time::Duration::new(2 * 60, 0));
                                }
                            } else {
                                panic!("Stateful NAT configured but not by K8s");
                            }
                        }
                        VpcExposeNatConfig::Stateless(_) => {
                            assert!(k8s_nat.stateful.is_none(),"Stateless NAT configured but K8s configured stateful NAT: {expose:#?}\nk8s: {k8s_nat:#?}");
                            if k8s_nat.stateless.is_none() {
                                assert!(k8s_expose.r#as.is_some());
                            }
                        }
                    },
                    (None, None) => {
                        assert!(k8s_expose.r#as.is_none());
                    }
                }
            });
    }
}
