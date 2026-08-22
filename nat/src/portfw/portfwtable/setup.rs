// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port-forwarding build configuration routines.
//! These are the functions to convert the configuration into port-forwarding rules.

use crate::portfw::{PortFwEntry, PortFwKey, PortFwTableError};
use config::ConfigError;
use config::external::overlay::vpc::{ValidatedPeering, ValidatedVpc, ValidatedVpcTable};
use config::external::overlay::vpcpeering::{PortForwardExpose, ValidatedExpose};
use lpm::prefix::L4Protocol;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;

/// Narrow an expose already known to do port forwarding.
///
/// `ValidatedExpose::as_port_forward` is total, so `None` here does not mean bad configuration --
/// `VpcExpose::validate` has rejected that already. It means validation has a hole, which is worth
/// an error naming the expose rather than a panic inside `config`.
fn as_port_forward(expose: &ValidatedExpose) -> Result<PortForwardExpose, PortFwTableError> {
    expose.as_port_forward().ok_or_else(|| {
        PortFwTableError::Unsupported(format!(
            "expose is not a well-formed port-forwarding expose: {expose:?}"
        ))
    })
}

fn expose_to_portfw_rule(
    expose: PortForwardExpose,
    proto: NextHeader,
    src_vpc: VpcDiscriminant,
    dst_vpc: VpcDiscriminant,
) -> Result<PortFwEntry, PortFwTableError> {
    let (internal, external) = (expose.internal(), expose.external());

    // build the rule; the idle timeout of the api maps to the established timeout here
    let key = PortFwKey::new(src_vpc, proto);
    PortFwEntry::new(
        key,
        dst_vpc,
        external.prefix(),
        internal.prefix(),
        (external.ports().start(), external.ports().end()),
        (internal.ports().start(), internal.ports().end()),
        None,
        expose.idle_timeout(),
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
        let expose = as_port_forward(expose)?;
        match expose.proto() {
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

    /// A port-forwarding expose becomes exactly the rules it describes.
    ///
    /// The interesting part is not that rules come out, but that the two sides do not get crossed:
    /// the expose's `as_range` is what traffic arrives on and its `ips` is where traffic goes, and
    /// a rule that has them the other way round forwards to the wrong place while satisfying every
    /// check the rule itself makes.
    #[test]
    fn an_expose_becomes_the_rules_it_describes() {
        bolero::check!()
            .with_generator(PortForwardingExpose)
            .cloned()
            .for_each(|expose: VpcExpose| {
                let nat = expose.nat.as_ref().expect("port forwarding sets nat");
                let proto = nat.proto;
                let internal = *expose.ips.first().expect("one prefix");
                let external = *nat.as_range.first().expect("one prefix");

                let overlay = overlay_offering(expose.clone()).expect("overlay");
                let rules = build_port_forwarding_configuration(overlay.vpc_table())
                    .expect("a validated port-forwarding expose should build");

                // `Any` is served by one rule per protocol; anything else by one.
                let expected = if proto == L4Protocol::Any { 2 } else { 1 };
                assert_eq!(rules.len(), expected, "for {expose}");

                for rule in &rules {
                    assert_eq!(rule.ext_prefix, external.prefix(), "external prefix");
                    assert_eq!(rule.int_prefix, internal.prefix(), "internal prefix");
                    assert_eq!(
                        rule.ext_ports.first().get(),
                        external.ports().expect("ports").start(),
                        "external ports"
                    );
                    assert_eq!(
                        rule.int_ports.first().get(),
                        internal.ports().expect("ports").start(),
                        "internal ports"
                    );
                    // The rule forwards into the local VPC, and admits traffic from the peer.
                    assert_eq!(rule.dst_vpcd, VpcDiscriminant::from_vni(vni(LOCAL_VNI)));
                    assert_eq!(
                        rule.key.src_vpcd(),
                        VpcDiscriminant::from_vni(vni(REMOTE_VNI))
                    );
                }
            });
    }

    fn vni(raw: u32) -> net::vxlan::Vni {
        net::vxlan::Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
    }
}
