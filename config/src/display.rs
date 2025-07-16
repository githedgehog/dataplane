// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display of model objects

use crate::external::overlay::vpc::Vpc;
// use routing::pretty_utils::Heading;
use std::fmt::Display;

use crate::external::overlay::vpc::{Peering, VpcId, VpcTable};
use crate::external::overlay::vpcpeering::VpcManifest;
use crate::external::overlay::vpcpeering::{VpcExpose, VpcPeering, VpcPeeringTable};

const SEP: &str = "       ";

impl Display for VpcExpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut carriage = false;
        if !self.ips.is_empty() {
            write!(f, "{SEP} prefixes:")?;
            self.ips.iter().for_each(|x| {
                let _ = write!(f, " {x}");
            });
        }
        if !self.nots.is_empty() {
            write!(f, ", except")?;
            self.nots.iter().for_each(|x| {
                let _ = write!(f, " {x}");
            });
        }

        writeln!(f)?;

        if !self.as_range.is_empty() {
            write!(f, "{SEP}       as:")?;
            self.as_range.iter().for_each(|x| {
                let _ = write!(f, " {x}");
            });
            carriage = true;
        }

        if !self.not_as.is_empty() {
            write!(f, ", excluding")?;
            self.not_as.iter().for_each(|x| {
                let _ = write!(f, " {x}");
            });
            carriage = true;
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
    writeln!(f, "     remote ({}, id {}):", manifest.name, remote_id)?;
    for e in &manifest.exposes {
        e.fmt(f)?;
    }
    Ok(())
}

impl Display for Peering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ■ {}:", self.name)?;
        fmt_local_manifest(f, &self.local)?;
        writeln!(f)?;
        fmt_remote_manifest(f, &self.remote, &self.remote_id)?;
        writeln!(f)
    }
}

/* ========= VPCs =========*/

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

// Auxiliary type to implement detailed VPC display
pub struct VpcDetailed<'a>(pub &'a Vpc);
impl Display for VpcDetailed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vpc = self.0;
        // Heading(format!("vpc: {}", vpc.name)).fmt(f)?; // BROKEN
        writeln!(f, " name: {} Id: {}", vpc.name, vpc.id)?;
        writeln!(f, " vni : {}", vpc.vni)?;
        writeln!(f, " peerings: {}", vpc.peerings.len())?;
        // Heading(format!("Peerings of {}", vpc.name)).fmt(f)?; //BROKEN
        for peering in &vpc.peerings {
            peering.fmt(f)?;
        }
        Ok(())
    }
}

impl Display for Vpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // VPC that has no peerings
        if self.peerings.is_empty() {
            writeln!(
                f,
                "{}",
                format_args!(VPC_TBL_FMT!(), &self.name, self.id, self.vni, "", "", "")
            )?;
        } else {
            // VPC that has peerings
            for (num, peering) in self.peerings.iter().enumerate() {
                let (name, id, vni, num_peers) = if num == 0 {
                    (
                        self.name.as_str(),
                        self.id.to_string(),
                        self.vni.to_string(),
                        self.peerings.len().to_string(),
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
impl Display for VpcTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //Heading(format!("VPCs ({})", self.len())).fmt(f)?; //BROKEN
        fmt_vpc_table_heading(f)?;
        for vpc in self.values() {
            vpc.fmt(f)?;
        }
        Ok(())
    }
}

/* ===== VPC peerings =====*/

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
        //  Heading(format!("VPC Peering Table ({})", self.len())).fmt(f)?; // BROKEN
        for peering in self.values() {
            peering.fmt(f)?;
        }
        Ok(())
    }
}

/*
// TODO(fredi)
impl Display for GwConfigMeta {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        Ok(())
    }
}
// TODO(fredi)
impl Display for ExternalConfig {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        Ok(())
    }
}
// TODO(fredi)
impl Display for InternalConfig {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO
        Ok(())
    }
}
// TODO(fredi)
impl Display for GwConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.meta.fmt(f)?;
        self.external.fmt(f)?;
        if let Some(internal) = &self.internal {
            internal.fmt(f)?;
        }
        Ok(())
    }
}
*/
