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
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::contract::PortForwardingExpose;
    use config::external::overlay::vpcpeering::{
        VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable,
    };
    use lpm::prefix::Prefix;

    const LOCAL_VNI: u32 = 100;
    const REMOTE_VNI: u32 = 200;

    // A two-VPC overlay whose local side offers exactly the expose under test. The remote side
    // exposes an unrelated prefix, since a manifest with no exposes is rejected.
    fn overlay_offering(expose: VpcExpose) -> config::external::overlay::ValidatedOverlay {
        let mut vpc_table = VpcTable::new();
        vpc_table
            .add(Vpc::new("VPC-1", "AAAAA", LOCAL_VNI).expect("local vpc"))
            .expect("add local vpc");
        vpc_table
            .add(Vpc::new("VPC-2", "BBBBB", REMOTE_VNI).expect("remote vpc"))
            .expect("add remote vpc");

        // Both manifests of a peering must be of one IP version, so the remote side follows
        // whichever family the expose under test was drawn from.
        let remote_prefix = match expose.ips.first().expect("one prefix").prefix() {
            Prefix::IPV4(_) => "3.3.3.0/24",
            Prefix::IPV6(_) => "2001:db8:ffff::/64",
        };
        let local = VpcManifest::new("VPC-1").exposing(expose);
        let remote =
            VpcManifest::new("VPC-2").exposing(VpcExpose::empty().ip(remote_prefix.into()));
        let mut peerings = VpcPeeringTable::new();
        peerings
            .add(VpcPeering::with_default_group(
                "VPC-1--VPC-2",
                local,
                remote,
            ))
            .expect("add peering");

        Overlay::new(vpc_table, peerings)
            .validate()
            .expect("the overlay around a valid expose should validate")
    }

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

                let overlay = overlay_offering(expose.clone());
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
