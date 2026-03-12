// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display of model objects

#![allow(clippy::manual_string_new)]

use crate::external::overlay::vpc::Vpc;
use std::fmt::Display;

use crate::external::overlay::Overlay;
use crate::external::overlay::vpc::{Peering, VpcId, VpcTable};
use crate::external::overlay::vpcpeering::{
    VpcExpose, VpcExposeNatConfig, VpcExposePortForwarding, VpcExposeStatefulNat,
    VpcExposeStatelessNat,
};
use crate::external::overlay::vpcpeering::{VpcManifest, VpcPeering, VpcPeeringTable};

struct Heading(String);
const LINE_WIDTH: usize = 81;
impl Display for Heading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = (LINE_WIDTH - (self.0.len() + 2)) / 2;
        write!(f, " {0:─<width$}", "─", width = len)?;
        write!(f, " {} ", self.0)?;
        writeln!(f, " {0:─<width$}", "─", width = len)
    }
}

const SEP: &str = "       ";

impl Display for VpcExposeStatefulNat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "masquerade, idle timeout: {}",
            self.idle_timeout.as_secs()
        )
    }
}
impl Display for VpcExposeStatelessNat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "static")
    }
}
impl Display for VpcExposePortForwarding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "port-forwarding, idle timeout: {}",
            self.idle_timeout.as_secs()
        )
    }
}

impl Display for VpcExposeNatConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stateless(config) => config.fmt(f),
            Self::Stateful(config) => config.fmt(f),
            Self::PortForwarding(config) => config.fmt(f),
        }
    }
}

impl Display for VpcExpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut carriage = false;
        if self.default {
            write!(f, "{SEP} prefixes: default")?;
        }
        if !self.ips.is_empty() {
            write!(f, "{SEP} prefixes:")?;
            self.ips.iter().for_each(|x| {
                let _ = write!(f, " {x}");
            });
        }
        if !self.nots.is_empty() {
            write!(f, "\n{SEP}   except:")?;
            self.nots.iter().for_each(|x| {
                let _ = write!(f, " {x}");
            });
        }

        writeln!(f)?;

        if let Some(nat) = self.nat.as_ref() {
            if !nat.as_range.is_empty() {
                write!(f, "{SEP}       as:")?;
                nat.as_range.iter().for_each(|pfx| {
                    let _ = write!(f, " {pfx} proto: {:?} NAT:{}", nat.proto, &nat.config);
                });
                carriage = true;
            }

            if !nat.not_as.is_empty() {
                write!(f, "\n{SEP}      but:")?;
                nat.not_as.iter().for_each(|x| {
                    let _ = write!(f, " {x}");
                });
                carriage = true;
            }
        }
        if carriage { writeln!(f) } else { Ok(()) }
    }
}

// Vpc manifest is common to VpcPeering and Peering
fn fmt_local_manifest(f: &mut std::fmt::Formatter<'_>, manifest: &VpcManifest) -> std::fmt::Result {
    writeln!(f, "     local:")?;
    for e in &manifest.exposes {
        e.fmt(f)?;
    }
    Ok(())
}
fn fmt_remote_manifest(
    f: &mut std::fmt::Formatter<'_>,
    manifest: &VpcManifest,
    remote_id: &VpcId,
) -> std::fmt::Result {
    writeln!(
        f,
        "     remote VPC is {} (id:{}):",
        manifest.name, remote_id
    )?;
    for e in &manifest.exposes {
        e.fmt(f)?;
    }
    Ok(())
}

impl Display for Peering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ■ {}:", self.name)?;
        writeln!(
            f,
            "   gwgroup: {}",
            self.gwgroup.as_ref().map_or("none", |v| v)
        )?;
        fmt_local_manifest(f, &self.local)?;
        writeln!(f)?;
        fmt_remote_manifest(f, &self.remote, &self.remote_id)?;
        writeln!(f)
    }
}

/* ========= VPCs and peerings =========*/

macro_rules! VPC_TBL_FMT {
    () => {
        " {:<18} {:<6} {:<8} {:<9} {:<18} {:<18}"
    };
}
fn fmt_vpc_table_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            VPC_TBL_FMT!(),
            "VPC", "Id", "VNI", "peers", "remote", "peering name"
        )
    )
}

impl Display for VpcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}{}{}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4]
        )
    }
}

pub struct VpcDetailed<'a>(pub &'a Vpc);
impl Display for VpcDetailed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vpc = self.0;
        Heading(format!(
            "Peerings of VPC:{} Id:{} vni :{} ({})",
            vpc.name,
            vpc.id,
            vpc.vni,
            vpc.peerings.len()
        ))
        .fmt(f)?;
        for peering in &vpc.peerings {
            peering.fmt(f)?;
        }
        Ok(())
    }
}

pub struct VpcSummary<'a>(&'a Vpc);
impl Display for VpcSummary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vpc = self.0;

        // VPC that has no peerings
        if vpc.peerings.is_empty() {
            writeln!(
                f,
                "{}",
                format_args!(VPC_TBL_FMT!(), &vpc.name, vpc.id, vpc.vni, "", "", "")
            )?;
        } else {
            // VPC that has peerings
            for (num, peering) in vpc.peerings.iter().enumerate() {
                let (name, id, vni, num_peers) = if num == 0 {
                    (
                        vpc.name.as_str(),
                        vpc.id.to_string(),
                        vpc.vni.to_string(),
                        vpc.peerings.len().to_string(),
                    )
                } else {
                    ("", "".to_string(), "".to_string(), "".to_string())
                };
                writeln!(
                    f,
                    "{}",
                    format_args!(
                        VPC_TBL_FMT!(),
                        name, id, vni, num_peers, peering.remote.name, peering.name
                    )
                )?;
            }
        }
        Ok(())
    }
}

pub struct VpcTableSummary<'a>(&'a VpcTable);
impl Display for VpcTableSummary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("VPCs ({})", self.0.len())).fmt(f)?;
        fmt_vpc_table_heading(f)?;
        for vpc in self.0.values() {
            vpc.as_summary().fmt(f)?;
        }
        Ok(())
    }
}

pub struct VpcTablePeerings<'a>(&'a VpcTable);
impl Display for VpcTablePeerings<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for vpc in self.0.values() {
            vpc.as_detailed().fmt(f)?;
        }
        Ok(())
    }
}

impl VpcTable {
    #[must_use]
    pub fn as_summary(&self) -> VpcTableSummary<'_> {
        VpcTableSummary(self)
    }
    #[must_use]
    pub fn as_peerings(&self) -> VpcTablePeerings<'_> {
        VpcTablePeerings(self)
    }
}

impl Vpc {
    #[must_use]
    pub fn as_summary(&self) -> VpcSummary<'_> {
        VpcSummary(self)
    }
    #[must_use]
    pub fn as_detailed(&self) -> VpcDetailed<'_> {
        VpcDetailed(self)
    }
}

/* ===== VPC peerings as received via API =====*/

fn fmt_peering_manifest(
    f: &mut std::fmt::Formatter<'_>,
    manifest: &VpcManifest,
) -> std::fmt::Result {
    writeln!(f, "    {}:", manifest.name)?;
    for e in &manifest.exposes {
        e.fmt(f)?;
    }
    Ok(())
}

impl Display for VpcPeering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " ■ {}:", self.name)?;
        fmt_peering_manifest(f, &self.left)?;
        writeln!(f)?;
        fmt_peering_manifest(f, &self.right)?;
        writeln!(f)
    }
}
impl Display for VpcPeeringTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("VPC Peering Table ({})", self.len())).fmt(f)?;
        for peering in self.values() {
            peering.fmt(f)?;
        }
        Ok(())
    }
}

impl Display for Overlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.vpc_table.as_summary().fmt(f)?;
        self.peering_table.fmt(f)
    }
}
