// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_intf::gateway_agent_crd::{
    GatewayAgentPeeringsAcl, GatewayAgentPeeringsAclDefault, GatewayAgentPeeringsAclRules,
    GatewayAgentPeeringsAclRulesAction, GatewayAgentPeeringsAclRulesMatch,
    GatewayAgentPeeringsAclRulesMatchDst, GatewayAgentPeeringsAclRulesMatchSrc,
    GatewayAgentPeeringsAclRulesScope,
};
use lpm::prefix::{PortRange, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::k8s::config::expose::parse_port_ranges;
use crate::converters::k8s::config::{SubnetMap, VpcSubnetMap};
use crate::external::overlay::acl::{Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope};

fn resolve_prefix(
    cidr: Option<&str>,
    vpc_subnet: Option<&str>,
    subnets: &SubnetMap,
) -> Result<Prefix, FromK8sConversionError> {
    match (cidr, vpc_subnet) {
        // unreachable as we only call this function if at least one of these fields is not None
        (None, None) => Err(FromK8sConversionError::MissingData(
            "ACL match entry must specify either cidr or vpcSubnet".to_string(),
        )),
        (Some(_), Some(_)) => Err(FromK8sConversionError::NotAllowed(
            "ACL match entry must specify either cidr or vpcSubnet, not both".to_string(),
        )),
        (Some(cidr), None) => cidr
            .parse::<Prefix>()
            .map_err(|e| FromK8sConversionError::InvalidData(format!("CIDR format: {cidr}: {e}"))),
        (None, Some(subnet_name)) => subnets.get(subnet_name).copied().ok_or_else(|| {
            FromK8sConversionError::NotAllowed(format!(
                "ACL match references unknown VPC subnet {subnet_name}"
            ))
        }),
    }
}

fn parse_proto(proto: Option<&str>) -> Result<AclProtoMatch, FromK8sConversionError> {
    let Some(proto) = proto else {
        return Ok(AclProtoMatch::Any);
    };
    match proto {
        "tcp" => Ok(AclProtoMatch::Tcp),
        "udp" => Ok(AclProtoMatch::Udp),
        other => other.parse::<u8>().map(AclProtoMatch::Other).map_err(|_| {
            FromK8sConversionError::InvalidData(format!(
                "ACL protocol '{other}': expected \"tcp\", \"udp\", or a numeric protocol"
            ))
        }),
    }
}

/// Common shape of an ACL match entry (`match.src[]` / `match.dst[]`).
///
/// The CRD generates distinct `...MatchSrc`/`...MatchDst` types with identical fields; this lets
/// [`convert_match_side`] handle both sides without duplicating the resolution logic.
trait AclMatchEntry {
    fn cidr(&self) -> Option<&str>;
    fn vpc_subnet(&self) -> Option<&str>;
    fn ports(&self) -> Option<&[String]>;
}

impl AclMatchEntry for GatewayAgentPeeringsAclRulesMatchSrc {
    fn cidr(&self) -> Option<&str> {
        self.cidr.as_deref()
    }
    fn vpc_subnet(&self) -> Option<&str> {
        self.vpc_subnet.as_deref()
    }
    fn ports(&self) -> Option<&[String]> {
        self.ports.as_deref()
    }
}

impl AclMatchEntry for GatewayAgentPeeringsAclRulesMatchDst {
    fn cidr(&self) -> Option<&str> {
        self.cidr.as_deref()
    }
    fn vpc_subnet(&self) -> Option<&str> {
        self.vpc_subnet.as_deref()
    }
    fn ports(&self) -> Option<&[String]> {
        self.ports.as_deref()
    }
}

/// Parse a `ports` list shared by both concrete and "any address" match entries.
///
/// A present-but-empty list is rejected rather than silently treated as "all ports" or "no
/// ports" — the CRD does not require callers to omit the field instead of sending an empty list,
/// so guessing which meaning was intended would be unsafe for an access-control rule.
fn parse_entry_ports(ports: &[String]) -> Result<Vec<PortRange>, FromK8sConversionError> {
    if ports.is_empty() {
        return Err(FromK8sConversionError::MissingData(
            "ACL match entry ports list must not be empty; omit the field to match all ports"
                .to_string(),
        ));
    }
    ports.iter().try_fold(Vec::new(), |mut ranges, port_str| {
        ranges.extend(parse_port_ranges(port_str)?);
        Ok(ranges)
    })
}

/// Build a [`PrefixPortsSet`] plus any "any address within the peering" port ranges from one side
/// (`src` or `dst`) of an ACL rule's `match` block.
fn convert_match_side<T: AclMatchEntry>(
    entries: Option<&[T]>,
    subnets: &SubnetMap,
) -> Result<(PrefixPortsSet, Vec<PortRange>), FromK8sConversionError> {
    let Some(entries) = entries else {
        return Ok((PrefixPortsSet::new(), Vec::new()));
    };
    let mut items = Vec::new();
    let mut any_ports = Vec::new();
    for entry in entries {
        match (entry.cidr(), entry.vpc_subnet(), entry.ports()) {
            // All fields omitted, the rule matches all traffic
            (None, None, None) => return Ok((PrefixPortsSet::new(), Vec::new())),
            // Match all addresses, ports returned separately since we need the peering manifest
            // to resolve them to prefixes
            (None, None, Some(ports)) => any_ports.extend(parse_entry_ports(ports)?),
            (cidr, vpc_subnet, ports) => {
                let prefix = resolve_prefix(cidr, vpc_subnet, subnets)?;
                match ports {
                    None => items.push(PrefixWithOptionalPorts::from(prefix)),
                    Some(ports) => {
                        for range in parse_entry_ports(ports)? {
                            items.push(PrefixWithOptionalPorts::new(prefix, Some(range)));
                        }
                    }
                }
            }
        }
    }
    Ok((items.into_iter().collect(), any_ports))
}

impl From<GatewayAgentPeeringsAclRulesAction> for AclAction {
    fn from(action: GatewayAgentPeeringsAclRulesAction) -> Self {
        match action {
            GatewayAgentPeeringsAclRulesAction::Deny => AclAction::Deny,
            GatewayAgentPeeringsAclRulesAction::Allow => AclAction::Allow,
        }
    }
}

impl From<&GatewayAgentPeeringsAclRulesScope> for AclScope {
    fn from(scope: &GatewayAgentPeeringsAclRulesScope) -> Self {
        match scope {
            GatewayAgentPeeringsAclRulesScope::Flow
            | GatewayAgentPeeringsAclRulesScope::KopiumEmpty => AclScope::Flow,
            GatewayAgentPeeringsAclRulesScope::Packet => AclScope::Packet,
        }
    }
}

/// Convert a rule's `match` block.
///
/// `src_subnets`/`dst_subnets` are the subnet maps of the rule's (already-resolved) `from`/`to`
/// VPCs, respectively, since `vpcSubnet` references in `src` resolve against the from-side VPC
/// and in `dst` against the to-side VPC.
impl TryFrom<(&SubnetMap, &SubnetMap, &GatewayAgentPeeringsAclRulesMatch)> for AclPattern {
    type Error = FromK8sConversionError;

    fn try_from(
        (src_subnets, dst_subnets, m): (&SubnetMap, &SubnetMap, &GatewayAgentPeeringsAclRulesMatch),
    ) -> Result<Self, Self::Error> {
        let (src, src_any_ports) = convert_match_side(m.src.as_deref(), src_subnets)?;
        let (dst, dst_any_ports) = convert_match_side(m.dst.as_deref(), dst_subnets)?;
        let proto = parse_proto(m.proto.as_deref())?;
        Ok(AclPattern::new(
            src,
            dst,
            src_any_ports,
            dst_any_ports,
            proto,
        ))
    }
}

/// Complete a rule's `from`/`to` pair against the two VPC names of a peering.
///
/// At most one of `from`/`to` may be blank; if so, it is inferred from the other side and the two
/// known VPC names.
///
/// # Errors
///
/// Returns an error if both values are blank, or if a non-blank value matches neither VPC name.
fn complete_from_to(
    rule_name: &str,
    from: &str,
    to: &str,
    left_name: &str,
    right_name: &str,
) -> Result<(String, String), FromK8sConversionError> {
    match (from, to) {
        // Accept if values match the names of the two VPCs
        (from, to) if from == left_name && to == right_name => {
            Ok((from.to_string(), to.to_string()))
        }
        (from, to) if from == right_name && to == left_name => {
            Ok((from.to_string(), to.to_string()))
        }

        // Accept, and complete, if one value matches a VPC, and the other is empty
        (from, to) if from == left_name && to.is_empty() => {
            Ok((from.to_string(), right_name.to_string()))
        }
        (from, to) if from == right_name && to.is_empty() => {
            Ok((from.to_string(), left_name.to_string()))
        }
        (from, to) if from.is_empty() && to == left_name => {
            Ok((right_name.to_string(), to.to_string()))
        }
        (from, to) if from.is_empty() && to == right_name => {
            Ok((left_name.to_string(), to.to_string()))
        }

        // Reject both values empty
        (from, to) if from.is_empty() && to.is_empty() => Err(FromK8sConversionError::MissingData(
            format!("Rule '{rule_name}' must specify at least one of 'from' or 'to' fields"),
        )),
        // Reject if one value is non-empty but does not match either VPC
        (from, to) => Err(FromK8sConversionError::NotAllowed(format!(
            "Rule '{rule_name}' has invalid 'from' or 'to' fields: '{from}' -> '{to}'",
        ))),
    }
}

fn convert_rule(
    vpc_subnets: &VpcSubnetMap,
    left_name: &str,
    right_name: &str,
    rule: &GatewayAgentPeeringsAclRules,
) -> Result<AclRule, FromK8sConversionError> {
    let rule_name = rule.name.clone().unwrap_or_default();
    let (from, to) = complete_from_to(
        &rule_name,
        rule.from.as_deref().unwrap_or_default(),
        rule.to.as_deref().unwrap_or_default(),
        left_name,
        right_name,
    )?;

    let empty_map = SubnetMap::new();
    let from_subnets = vpc_subnets.get(&from).unwrap_or(&empty_map);
    let to_subnets = vpc_subnets.get(&to).unwrap_or(&empty_map);

    let pattern = match rule.r#match.as_ref() {
        Some(m) => AclPattern::try_from((from_subnets, to_subnets, m))?,
        None => AclPattern::default(),
    };

    let scope = rule.scope.as_ref().map(AclScope::from).unwrap_or_default();

    Ok(AclRule::new(
        rule_name,
        from,
        to,
        rule.action.clone().into(),
        pattern,
        scope,
        rule.log.unwrap_or(false),
    ))
}

impl TryFrom<(&VpcSubnetMap, &str, &str, &GatewayAgentPeeringsAcl)> for Acl {
    type Error = FromK8sConversionError;

    fn try_from(
        (vpc_subnets, left_name, right_name, acl): (
            &VpcSubnetMap,
            &str,
            &str,
            &GatewayAgentPeeringsAcl,
        ),
    ) -> Result<Self, Self::Error> {
        // "deny-unless-exposed" maps to "allow" in dataplane
        let default = match acl.default {
            GatewayAgentPeeringsAclDefault::Deny => AclAction::Deny,
            GatewayAgentPeeringsAclDefault::DenyUnlessExposed
            | GatewayAgentPeeringsAclDefault::KopiumEmpty => AclAction::Allow,
        };

        let rules = acl
            .rules
            .as_ref()
            .map(|rules| {
                rules
                    .iter()
                    .map(|rule| convert_rule(vpc_subnets, left_name, right_name, rule))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Acl::new(default, rules))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k8s_intf::gateway_agent_crd::GatewayAgentPeeringsAclRulesScope;
    use lpm::prefix::Prefix as LpmPrefix;

    fn subnets(entries: &[(&str, &str)]) -> VpcSubnetMap {
        let mut vpc_subnets = VpcSubnetMap::new();
        for (vpc, subnet_map) in [("VPC-1", entries), ("VPC-2", &[])] {
            let mut map = SubnetMap::new();
            for (name, cidr) in subnet_map {
                map.insert((*name).to_string(), cidr.parse::<LpmPrefix>().unwrap());
            }
            vpc_subnets.insert(vpc.to_string(), map);
        }
        vpc_subnets
    }

    fn rule(
        name: &str,
        from: &str,
        to: &str,
        action: GatewayAgentPeeringsAclRulesAction,
        r#match: Option<GatewayAgentPeeringsAclRulesMatch>,
    ) -> GatewayAgentPeeringsAclRules {
        GatewayAgentPeeringsAclRules {
            action,
            from: (!from.is_empty()).then(|| from.to_string()),
            log: None,
            r#match,
            name: (!name.is_empty()).then(|| name.to_string()),
            scope: None,
            to: (!to.is_empty()).then(|| to.to_string()),
        }
    }

    #[test]
    fn test_default_action_mapping() {
        for (default, expected) in [
            (GatewayAgentPeeringsAclDefault::Deny, AclAction::Deny),
            (
                GatewayAgentPeeringsAclDefault::DenyUnlessExposed,
                AclAction::Allow,
            ),
            // CRD doc: "deny-unless-exposed" is the default when the field is empty/unset.
            (
                GatewayAgentPeeringsAclDefault::KopiumEmpty,
                AclAction::Allow,
            ),
        ] {
            let acl = GatewayAgentPeeringsAcl {
                default,
                rules: None,
            };
            let converted = Acl::try_from((&subnets(&[]), "VPC-1", "VPC-2", &acl)).unwrap();
            assert_eq!(converted.default_action(), expected);
        }
    }

    #[test]
    fn test_proto_parsing() {
        assert_eq!(parse_proto(None).unwrap(), AclProtoMatch::Any);
        assert_eq!(parse_proto(Some("tcp")).unwrap(), AclProtoMatch::Tcp);
        assert_eq!(parse_proto(Some("udp")).unwrap(), AclProtoMatch::Udp);
        assert_eq!(parse_proto(Some("47")).unwrap(), AclProtoMatch::Other(47));
        assert!(parse_proto(Some("bogus")).is_err());
        // "icmp" is not supported yet
        assert!(parse_proto(Some("icmp")).is_err());
    }

    #[test]
    fn test_scope_mapping() {
        assert_eq!(
            AclScope::from(&GatewayAgentPeeringsAclRulesScope::Flow),
            AclScope::Flow
        );
        assert_eq!(
            AclScope::from(&GatewayAgentPeeringsAclRulesScope::Packet),
            AclScope::Packet
        );
        assert_eq!(
            AclScope::from(&GatewayAgentPeeringsAclRulesScope::KopiumEmpty),
            AclScope::Flow
        );
    }

    #[test]
    fn test_resolve_prefix_cidr_xor_subnet() {
        let subnets = SubnetMap::from([(
            "subnet-1".to_string(),
            "10.0.1.0/24".parse::<LpmPrefix>().unwrap(),
        )]);
        assert!(resolve_prefix(None, None, &subnets).is_err());
        assert!(resolve_prefix(Some("10.0.0.0/24"), Some("subnet-1"), &subnets).is_err());
        assert_eq!(
            resolve_prefix(Some("10.0.0.0/24"), None, &subnets).unwrap(),
            "10.0.0.0/24".parse::<LpmPrefix>().unwrap()
        );
        assert_eq!(
            resolve_prefix(None, Some("subnet-1"), &subnets).unwrap(),
            "10.0.1.0/24".parse::<LpmPrefix>().unwrap()
        );
        assert!(resolve_prefix(None, Some("unknown"), &subnets).is_err());
    }

    #[test]
    fn test_convert_rule_from_to_completion() {
        let vpc_subnets = subnets(&[]);

        // Both explicit
        let r = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                None,
            ),
        )
        .unwrap();
        assert_eq!(r.action, AclAction::Allow);

        // 'to' blank, inferred from 'from'
        assert!(
            convert_rule(
                &vpc_subnets,
                "VPC-1",
                "VPC-2",
                &rule(
                    "r",
                    "VPC-1",
                    "",
                    GatewayAgentPeeringsAclRulesAction::Allow,
                    None,
                ),
            )
            .is_ok()
        );

        // Both blank: rejected
        assert!(
            convert_rule(
                &vpc_subnets,
                "VPC-1",
                "VPC-2",
                &rule("r", "", "", GatewayAgentPeeringsAclRulesAction::Allow, None),
            )
            .is_err()
        );

        // Unknown VPC name: rejected
        assert!(
            convert_rule(
                &vpc_subnets,
                "VPC-1",
                "VPC-2",
                &rule(
                    "r",
                    "VPC-X",
                    "VPC-2",
                    GatewayAgentPeeringsAclRulesAction::Allow,
                    None,
                ),
            )
            .is_err()
        );
    }

    #[test]
    fn test_convert_rule_vpc_subnet_resolution_uses_from_to_sides() {
        let vpc_subnets = subnets(&[("web", "10.0.1.0/24")]);

        let m = GatewayAgentPeeringsAclRulesMatch {
            dst: None,
            proto: None,
            src: Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: None,
                ports: None,
                vpc_subnet: Some("web".to_string()),
            }]),
        };

        // "web" exists under VPC-1's subnets: resolves when VPC-1 is the "from" side
        let r = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                Some(m.clone()),
            ),
        )
        .unwrap();
        assert!(!r.pattern.src.is_empty());

        // Same subnet name doesn't exist under VPC-2: fails when VPC-2 is the "from" side
        assert!(
            convert_rule(
                &vpc_subnets,
                "VPC-1",
                "VPC-2",
                &rule(
                    "r",
                    "VPC-2",
                    "VPC-1",
                    GatewayAgentPeeringsAclRulesAction::Allow,
                    Some(m),
                ),
            )
            .is_err()
        );
    }

    // An explicitly-empty (but present) `ports` list must not be silently treated as "all ports":
    // that would silently expand an empty PrefixPortsSet into "match the entire manifest" via
    // `AclRule::validate_pattern_coverage`, turning a scoped rule into an unscoped one.
    #[test]
    fn test_convert_rule_rejects_empty_ports_list() {
        let vpc_subnets = subnets(&[]);
        let m = GatewayAgentPeeringsAclRulesMatch {
            dst: None,
            proto: None,
            src: Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: Some("10.0.0.0/24".to_string()),
                ports: Some(vec![]),
                vpc_subnet: None,
            }]),
        };
        let result = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                Some(m),
            ),
        );
        assert!(
            matches!(result, Err(FromK8sConversionError::MissingData(_))),
            "{result:?}"
        );
    }

    // Per the spec, a match entry with neither `cidr` nor `vpcSubnet` matches any address within
    // the peering. A fully empty entry (no ports either) makes the whole side unrestricted.
    #[test]
    fn test_convert_rule_fully_empty_match_entry_is_unrestricted() {
        let vpc_subnets = subnets(&[]);
        let m = GatewayAgentPeeringsAclRulesMatch {
            dst: None,
            proto: None,
            src: Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: None,
                ports: None,
                vpc_subnet: None,
            }]),
        };
        let r = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                Some(m),
            ),
        )
        .unwrap();
        assert!(r.pattern.src.is_empty());
    }

    // An entry with ports but neither cidr nor vpcSubnet is legal ("any address, these ports") but
    // can't be resolved to concrete prefixes without the peering's manifest, so at conversion time
    // it leaves `pattern.src()` empty; a present-but-empty ports list on such an entry is still
    // rejected, same as for a concrete-prefix entry.
    #[test]
    fn test_convert_rule_any_address_with_ports() {
        let vpc_subnets = subnets(&[]);

        let ports_only = GatewayAgentPeeringsAclRulesMatch {
            dst: None,
            proto: None,
            src: Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: None,
                ports: Some(vec!["443".to_string()]),
                vpc_subnet: None,
            }]),
        };
        let r = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                Some(ports_only),
            ),
        )
        .unwrap();
        assert!(r.pattern.src.is_empty());

        let empty_ports = GatewayAgentPeeringsAclRulesMatch {
            dst: None,
            proto: None,
            src: Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: None,
                ports: Some(vec![]),
                vpc_subnet: None,
            }]),
        };
        let result = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                Some(empty_ports),
            ),
        );
        assert!(
            matches!(result, Err(FromK8sConversionError::MissingData(_))),
            "{result:?}"
        );
    }

    // End-to-end: an "any address, these ports" match entry, once converted and validated against
    // a real peering, resolves to the manifest's advertised prefixes restricted to those ports.
    #[test]
    fn test_convert_rule_any_address_with_ports_resolves_against_manifest() {
        use crate::external::overlay::vpcpeering::{VpcExpose, VpcManifest};

        let vpc_subnets = subnets(&[]);
        let m = GatewayAgentPeeringsAclRulesMatch {
            dst: None,
            proto: Some("tcp".to_string()),
            src: Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: None,
                ports: Some(vec!["443".to_string()]),
                vpc_subnet: None,
            }]),
        };
        let converted_rule = convert_rule(
            &vpc_subnets,
            "VPC-1",
            "VPC-2",
            &rule(
                "r",
                "VPC-1",
                "VPC-2",
                GatewayAgentPeeringsAclRulesAction::Allow,
                Some(m),
            ),
        )
        .unwrap();

        let left = VpcManifest::with_exposes(
            "VPC-1",
            vec![VpcExpose::empty().ip(PrefixWithOptionalPorts::from(
                "10.0.0.0/24".parse::<LpmPrefix>().unwrap(),
            ))],
        )
        .validate()
        .unwrap();
        let right = VpcManifest::with_exposes(
            "VPC-2",
            vec![VpcExpose::empty().ip(PrefixWithOptionalPorts::from(
                "10.1.0.0/24".parse::<LpmPrefix>().unwrap(),
            ))],
        )
        .validate()
        .unwrap();

        let acl = Acl::new(AclAction::Deny, vec![converted_rule])
            .validate(&left, &right)
            .unwrap();
        assert_eq!(
            acl.rules()[0].pattern().src(),
            &PrefixPortsSet::from([PrefixWithOptionalPorts::new(
                "10.0.0.0/24".parse::<LpmPrefix>().unwrap(),
                Some(PortRange::new(443, 443).unwrap()),
            )])
        );
    }

    #[test]
    fn test_full_acl_conversion() {
        let vpc_subnets = subnets(&[]);
        let acl = GatewayAgentPeeringsAcl {
            default: GatewayAgentPeeringsAclDefault::Deny,
            rules: Some(vec![
                rule(
                    "web",
                    "VPC-1",
                    "VPC-2",
                    GatewayAgentPeeringsAclRulesAction::Allow,
                    Some(GatewayAgentPeeringsAclRulesMatch {
                        dst: Some(vec![GatewayAgentPeeringsAclRulesMatchDst {
                            cidr: Some("10.1.0.0/24".to_string()),
                            ports: Some(vec!["443".to_string()]),
                            vpc_subnet: None,
                        }]),
                        proto: Some("tcp".to_string()),
                        src: None,
                    }),
                ),
                rule(
                    "return",
                    "VPC-2",
                    "VPC-1",
                    GatewayAgentPeeringsAclRulesAction::Allow,
                    None,
                ),
            ]),
        };

        let mut rule_with_scope = rule(
            "scoped",
            "VPC-1",
            "VPC-2",
            GatewayAgentPeeringsAclRulesAction::Deny,
            None,
        );
        rule_with_scope.scope = Some(GatewayAgentPeeringsAclRulesScope::Packet);
        rule_with_scope.log = Some(true);
        let mut acl_with_scope = acl.clone();
        acl_with_scope.rules.as_mut().unwrap().push(rule_with_scope);

        let converted = Acl::try_from((&vpc_subnets, "VPC-1", "VPC-2", &acl_with_scope)).unwrap();
        assert_eq!(converted.default_action(), AclAction::Deny);
        assert_eq!(converted.rules().len(), 3);

        // The two rules built via `rule()` default to no explicit scope (CRD `None`), which maps to
        // `AclScope::Flow`; the third rule explicitly requested `Packet` scope, which must survive
        // the conversion.
        assert_eq!(converted.rules()[0].scope, AclScope::Flow);
        assert_eq!(converted.rules()[1].scope, AclScope::Flow);
        assert_eq!(converted.rules()[2].scope, AclScope::Packet);

        // Same for `log`: the two rules built via `rule()` default to no explicit `log` (CRD
        // `None`), which maps to `false`; the third rule explicitly requested `log: true`, which
        // must survive the conversion too.
        assert!(!converted.rules()[0].log);
        assert!(!converted.rules()[1].log);
        assert!(converted.rules()[2].log);
    }
}
