// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port-forwarding build configuration routines.
//! These are the functions to convert the configuration into port-forwarding rules.

use crate::portfw::{PortFwEntry, PortFwKey, PortFwTableError};
use config::ConfigError;
use config::external::overlay::vpc::{ValidatedPeering, ValidatedVpc, ValidatedVpcTable};
use config::external::overlay::vpcpeering::ValidatedExpose;
use lpm::prefix::L4Protocol;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;

fn port_fw_proto(expose: &ValidatedExpose) -> L4Protocol {
    expose.nat().unwrap_or_else(|| unreachable!()).proto
}

fn expose_to_portfw_rule(
    expose: &ValidatedExpose,
    proto: NextHeader,
    src_vpc: VpcDiscriminant,
    dst_vpc: VpcDiscriminant,
) -> Result<PortFwEntry, PortFwTableError> {
    let nat = expose.nat().unwrap_or_else(|| unreachable!());
    debug_assert!(nat.is_port_forwarding());
    debug_assert_eq!(nat.as_range.len(), 1);
    debug_assert_eq!(expose.ips().len(), 1);

    // in a port forwarding expose, the range must always be Some(range) because a None
    // would imply a Some(max_range) which includes port 0 which is forbidden. So, finding
    // `None` would be a validation failure
    let prefix = expose.ips().first().unwrap_or_else(|| unreachable!());
    let (prefix, ports) = (
        prefix.prefix(),
        prefix.ports().unwrap_or_else(|| unreachable!()),
    );

    let as_range = nat.as_range.first().unwrap_or_else(|| unreachable!());
    let (ext_prefix, ext_ports) = (
        as_range.prefix(),
        as_range.ports().unwrap_or_else(|| unreachable!()),
    );

    // the idle timeout of the api gets mapped to the established timeout in port-forwarding
    let idle_timeout = expose.idle_timeout();

    // build the rule
    let key = PortFwKey::new(src_vpc, proto);
    PortFwEntry::new(
        key,
        dst_vpc,
        ext_prefix,
        prefix,
        (ext_ports.start(), ext_ports.end()),
        (ports.start(), ports.end()),
        None,
        idle_timeout,
    )
}
fn vpc_port_fw_peering(
    vpc_table: &ValidatedVpcTable,
    dst_vpc: VpcDiscriminant,
    peering: &ValidatedPeering,
) -> Result<Vec<PortFwEntry>, PortFwTableError> {
    let mut rules = vec![];
    for expose in peering.local().port_forwarding_exposes() {
        let remote_vpc_vni = vpc_table.get_remote_vni(peering);
        let src_vpc = VpcDiscriminant::from_vni(remote_vpc_vni);
        match port_fw_proto(expose) {
            L4Protocol::Tcp => {
                let rule = expose_to_portfw_rule(expose, NextHeader::TCP, src_vpc, dst_vpc)?;
                rules.push(rule);
            }
            L4Protocol::Udp => {
                let rule = expose_to_portfw_rule(expose, NextHeader::UDP, src_vpc, dst_vpc)?;
                rules.push(rule);
            }
            L4Protocol::Any => {
                let rule = expose_to_portfw_rule(expose, NextHeader::TCP, src_vpc, dst_vpc)?;
                rules.push(rule);

                let rule = expose_to_portfw_rule(expose, NextHeader::UDP, src_vpc, dst_vpc)?;
                rules.push(rule);
            }
        }
    }
    Ok(rules)
}
fn vpc_port_fw(
    vpc_table: &ValidatedVpcTable,
    vpc: &ValidatedVpc,
) -> Result<Vec<PortFwEntry>, PortFwTableError> {
    let mut collected = vec![];
    let dst_vpc = VpcDiscriminant::from_vni(vpc.vni());
    for peering in vpc.peerings() {
        let mut rules = vpc_port_fw_peering(vpc_table, dst_vpc, peering)?;
        collected.append(&mut rules);
    }
    Ok(collected)
}

pub fn build_port_forwarding_configuration(
    vpc_table: &ValidatedVpcTable,
) -> Result<Vec<PortFwEntry>, ConfigError> {
    let mut ruleset = vec![];
    for vpc in vpc_table.values() {
        let mut rules =
            vpc_port_fw(vpc_table, vpc).map_err(|e| ConfigError::PortForwarding(e.to_string()))?;
        ruleset.append(&mut rules);
    }
    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::external::overlay::vpcpeering::VpcExpose;
    use config::external::overlay::vpcpeering::contract::{
        LOCAL_VNI, PortForwardingExpose, REMOTE_VNI, overlay_offering,
    };

    #[test]
    fn an_expose_becomes_the_rules_it_describes() {
        bolero::check!()
            .with_generator(PortForwardingExpose::default())
            .cloned()
            .for_each(|expose: VpcExpose| {
                let nat = expose.nat.as_ref().expect("port forwarding sets nat");
                let proto = nat.proto;
                let internal = *expose.ips.first().expect("one prefix");
                let external = *nat.as_range.first().expect("one prefix");

                let overlay = overlay_offering(expose.clone()).expect("overlay");
                let rules = build_port_forwarding_configuration(overlay.vpc_table())
                    .expect("a validated port-forwarding expose should build");

                let expected = if proto == L4Protocol::Any { 2 } else { 1 };
                assert_eq!(rules.len(), expected, "for {expose}");

                for rule in &rules {
                    assert_eq!(rule.ext_prefix, external.prefix(), "external prefix");
                    assert_eq!(rule.int_prefix, internal.prefix(), "internal prefix");
                    // Both ends of both ranges. Checking only the first port let a rule
                    // that had collapsed a range of up to a thousand ports down to a
                    // single one pass, silently dropping every other port's traffic.
                    let (want_ext, want_int) = (
                        external.ports().expect("ports"),
                        internal.ports().expect("ports"),
                    );
                    assert_eq!(
                        rule.ext_ports.first().get(),
                        want_ext.start(),
                        "external first"
                    );
                    assert_eq!(rule.ext_ports.last().get(), want_ext.end(), "external last");
                    assert_eq!(
                        rule.int_ports.first().get(),
                        want_int.start(),
                        "internal first"
                    );
                    assert_eq!(rule.int_ports.last().get(), want_int.end(), "internal last");
                    assert_eq!(rule.dst_vpcd, VpcDiscriminant::from_vni(vni(LOCAL_VNI)));
                    assert_eq!(
                        rule.key.src_vpcd(),
                        VpcDiscriminant::from_vni(vni(REMOTE_VNI))
                    );
                }

                // The rules have to name the protocols the expose asked for. Counting them
                // does not say that: installing TCP twice for an `any` expose gives two
                // rules and no UDP forwarding at all, and nothing here read the protocol.
                let mut protocols: Vec<NextHeader> =
                    rules.iter().map(|rule| rule.key.proto()).collect();
                protocols.sort_unstable();
                let wanted = match proto {
                    L4Protocol::Tcp => vec![NextHeader::TCP],
                    L4Protocol::Udp => vec![NextHeader::UDP],
                    L4Protocol::Any => {
                        let mut both = vec![NextHeader::TCP, NextHeader::UDP];
                        both.sort_unstable();
                        both
                    }
                };
                assert_eq!(protocols, wanted, "protocols installed for {expose}");
            });
    }

    fn vni(raw: u32) -> net::vxlan::Vni {
        net::vxlan::Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
    }
}
