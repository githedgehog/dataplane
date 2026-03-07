// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Overlay routing tables display

use super::routing::Action;
use super::routing::IngressKey;
use super::routing::IngressMap;
use super::routing::OvelayRoute;
use super::routing::PacketSummary;
use super::routing::VpcRoutingTable;
use net::ip::NextHeader;

use std::fmt::Display;

/* Routing */

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Drop => write!(f, "drop"),
            Action::Forward => write!(f, "forward"),
            Action::PortForward => write!(f, "port-forward"),
            Action::Masquerade => write!(f, "masquerade"),
            Action::StaticNat => write!(f, "static-nat"),
        }
    }
}

impl Display for OvelayRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(proto) = self.proto {
            let portrange = self.portrange.map_or("[]".to_string(), |r| r.to_string());
            write!(
                f,
                "{proto} {portrange} {} to {} ",
                self.action,
                self.dst_vpcd,
                // don't show prefix as it is misleading
            )
        } else {
            write!(
                f,
                "{} to {}",
                self.action,
                self.dst_vpcd,
                // don't show prefix as it is misleading
            )
        }
    }
}

impl Display for VpcRoutingTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix, route) in self.iter() {
            writeln!(f, "  {prefix} {route}")?;
        }
        if let Some(route) = self.default_route.as_ref() {
            writeln!(f, " * default: {route}")?;
        }
        Ok(())
    }
}

impl Display for IngressKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = self.proto.map_or("other".to_string(), |p| p.to_string());
        write!(f, "{} proto: {proto}", self.src_vpcd)
    }
}

impl Display for IngressMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "───────────────── Overlay routing ─────────────────")?;
        for (key, table) in self.iter() {
            writeln!(f, "from: {key}")?;
            write!(f, "{table}")?;
        }

        Ok(())
    }
}

/* policy */

use super::routing::EgressVpcPolicy;
use super::routing::EgressVpcPolicyMap;
use super::routing::PeerMap;
use super::routing::PrefixPolicy;

impl Display for PrefixPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.action)
    }
}
impl Display for PeerMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (remote_vpcd, policy) in self.iter() {
            writeln!(f, "      {remote_vpcd} -> {policy}")?;
        }
        Ok(())
    }
}
impl Display for EgressVpcPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix, peermap) in self.0.iter() {
            write!(f, "   for {prefix}:\n{peermap}")?;
        }
        Ok(())
    }
}
impl Display for EgressVpcPolicyMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "──────────── Egress policy map ────────────")?;
        for (vpcd, vpc_policy) in self.iter() {
            write!(f, " {vpcd}:\n {vpc_policy}")?;
        }
        Ok(())
    }
}

/* packet summary */

impl Display for PacketSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.proto == NextHeader::TCP || self.proto == NextHeader::UDP {
            let src_port = self.src_port.unwrap();
            let dst_port = self.dst_port.unwrap();
            write!(
                f,
                "{} {}:{src_port} -> {}:{dst_port} ({})",
                self.src_vpcd, self.src_addr, self.dst_addr, self.proto
            )
        } else {
            write!(
                f,
                "{} {} -> {} ({})",
                self.src_vpcd, self.src_addr, self.dst_addr, self.proto
            )
        }
    }
}
