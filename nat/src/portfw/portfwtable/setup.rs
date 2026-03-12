// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port-forwarding build configuration routines.
//! These are the functions to convert the configuration into port-forwarding rules.

use crate::portfw::{PortFwEntry, PortFwKey, PortFwTableError};
use config::ConfigError;
use config::external::overlay::vpc::{Peering, Vpc, VpcTable};
use config::external::overlay::vpcpeering::VpcExpose;
use lpm::prefix::{L4Protocol, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;

fn port_fw_proto(expose: &VpcExpose) -> L4Protocol {
    expose.nat.as_ref().unwrap_or_else(|| unreachable!()).proto
}

fn expose_to_portfw_rule(
    expose: &VpcExpose,
    proto: NextHeader,
    src_vpc: VpcDiscriminant,
    dst_vpc: VpcDiscriminant,
) -> Result<PortFwEntry, PortFwTableError> {
    let nat = expose.nat.as_ref().unwrap_or_else(|| unreachable!());
    debug_assert!(nat.is_port_forwarding());
    debug_assert_eq!(nat.as_range.len(), 1);
    debug_assert_eq!(expose.ips.len(), 1);
    let ips = expose.ips.first().unwrap_or_else(|| unreachable!());
    let (prefix, ports) = match ips {
        PrefixWithOptionalPorts::Prefix(_) => unreachable!(),
        PrefixWithOptionalPorts::PrefixPorts(e) => (e.prefix(), e.ports()),
    };

    let as_range = nat.as_range.first().unwrap_or_else(|| unreachable!());
    let (ext_prefix, ext_ports) = match as_range {
        PrefixWithOptionalPorts::Prefix(_) => unreachable!(),
        PrefixWithOptionalPorts::PrefixPorts(e) => (e.prefix(), e.ports()),
    };

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
        None,
    )
}
fn vpc_port_fw_peering(
    vpc_table: &VpcTable,
    dst_vpc: VpcDiscriminant,
    peering: &Peering,
) -> Result<Vec<PortFwEntry>, PortFwTableError> {
    let mut rules = vec![];
    for expose in peering.local.port_forwarding_exposes() {
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
fn vpc_port_fw(vpc_table: &VpcTable, vpc: &Vpc) -> Result<Vec<PortFwEntry>, PortFwTableError> {
    let mut collected = vec![];
    let dst_vpc = VpcDiscriminant::from_vni(vpc.vni);
    for peering in &vpc.peerings {
        let mut rules = vpc_port_fw_peering(vpc_table, dst_vpc, peering)?;
        collected.append(&mut rules);
    }
    Ok(collected)
}

pub fn build_port_forwarding_configuration(
    vpc_table: &VpcTable,
) -> Result<Vec<PortFwEntry>, ConfigError> {
    let mut ruleset = vec![];
    for vpc in vpc_table.values() {
        let mut rules =
            vpc_port_fw(vpc_table, vpc).map_err(|e| ConfigError::PortForwarding(e.to_string()))?;
        ruleset.append(&mut rules);
    }
    Ok(ruleset)
}
