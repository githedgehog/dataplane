// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::convert::TryFrom;

use k8s_intf::gateway_agent_crd::{
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps,
};
use lpm::prefix::{Prefix, PrefixString};

use crate::converters::k8s::{FromK8sConversionError, SubnetMap};
use crate::external::overlay::vpcpeering::VpcExpose;

fn process_ip_block(
    vpc_expose: VpcExpose,
    ip: &GatewayAgentPeeringsPeeringExposeIps,
    subnets: &SubnetMap,
) -> Result<VpcExpose, FromK8sConversionError> {
    Ok(match (&ip.cidr, &ip.vpc_subnet, &ip.not) {
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
            vpc_expose.ip(*prefix)
        }
        (Some(cidr), None, None) => {
            let prefix = cidr.parse::<Prefix>().map_err(|e| {
                FromK8sConversionError::ParseError(format!("Invalid CIDR format: {cidr}: {e}"))
            })?;
            vpc_expose.ip(prefix)
        }
        (None, None, Some(not)) => {
            let prefix = Prefix::try_from(PrefixString(not.as_str())).map_err(|e| {
                FromK8sConversionError::Invalid(format!("Invalid CIDR format: {not}: {e}"))
            })?;
            vpc_expose.not(prefix)
        }
    })
}

fn process_as_block(
    vpc_expose: VpcExpose,
    ip: &GatewayAgentPeeringsPeeringExposeAs,
) -> Result<VpcExpose, FromK8sConversionError> {
    Ok(match (&ip.cidr, &ip.not) {
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
            vpc_expose.as_range(prefix)
        }
        (None, Some(not)) => {
            let prefix = Prefix::try_from(PrefixString(not.as_str())).map_err(|e| {
                FromK8sConversionError::Invalid(format!("Invalid CIDR format: {not}: {e}"))
            })?;
            vpc_expose.not_as(prefix)
        }
    })
}

impl TryFrom<(&SubnetMap, &GatewayAgentPeeringsPeeringExpose)> for VpcExpose {
    type Error = FromK8sConversionError;

    fn try_from(
        (subnets, expose): (&SubnetMap, &GatewayAgentPeeringsPeeringExpose),
    ) -> Result<Self, Self::Error> {
        let mut vpc_expose = VpcExpose::empty();

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
    use super::*;

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
                let mut ips = expose.ips.iter().map(Prefix::to_string).collect::<Vec<_>>();
                ips.sort();
                let mut nots = expose
                    .nots
                    .iter()
                    .map(Prefix::to_string)
                    .collect::<Vec<_>>();
                nots.sort();

                let r#as = expose.nat.as_ref().map(|nat| {
                    let mut ret = nat
                        .as_range
                        .iter()
                        .map(Prefix::to_string)
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });
                let not_as = expose.nat.as_ref().map(|nat| {
                    let mut ret = nat.not_as.iter().map(Prefix::to_string).collect::<Vec<_>>();
                    ret.sort();
                    ret
                });

                let mut k8s_ips = k8s_expose
                    .ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .filter(|ip| ip.cidr.is_some())
                            .map(|ip| ip.cidr.as_ref().unwrap().clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or(vec![]);
                let mut k8s_nots = k8s_expose
                    .ips
                    .as_ref()
                    .map(|ips| {
                        ips.iter()
                            .filter(|ip| ip.not.is_some())
                            .map(|ip| ip.not.as_ref().unwrap().clone())
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
                                subnets
                                    .get(ip.vpc_subnet.as_ref().unwrap())
                                    .unwrap()
                                    .to_string()
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
                        .map(|r#as| r#as.cidr.as_ref().unwrap().clone())
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });

                let k8s_not_as = k8s_expose.r#as.as_ref().map(|r#as| {
                    let mut ret = r#as
                        .iter()
                        .filter(|r#as| r#as.not.is_some())
                        .map(|r#as| r#as.not.as_ref().unwrap().clone())
                        .collect::<Vec<_>>();
                    ret.sort();
                    ret
                });

                assert_eq!(ips, k8s_ips);
                assert_eq!(nots, k8s_nots);
                assert_eq!(r#as, k8s_as);
                assert_eq!(not_as, k8s_not_as);
            });
    }
}
