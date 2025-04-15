// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::rpc::overlay::vpc::Vpc;
use routing::pretty_utils::Heading;
use std::fmt::Display;

use crate::rpc::overlay::VpcManifest;
use crate::rpc::overlay::vpc::Peering;
use crate::rpc::overlay::vpc::VpcTable;
use crate::rpc::overlay::vpcpeering::{VpcExpose, VpcPeering, VpcPeeringTable};

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
fn fmt_manifest(
    f: &mut std::fmt::Formatter<'_>,
    is_local: bool,

    manifest: &VpcManifest,
) -> std::fmt::Result {
    if is_local {
        writeln!(f, "     local:")?;
    } else {
        writeln!(f, "     remote, {}:", manifest.name)?;
    }

    for e in &manifest.exposes {
        e.fmt(f)?;
    }
    Ok(())
}

impl Display for Peering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  ■ {}:", self.name)?;
        fmt_manifest(f, true, &self.local)?;
        writeln!(f)?;
        fmt_manifest(f, false, &self.remote)?;
        writeln!(f)
    }
}

/* ========= VPCs =========*/

macro_rules! VPC_TBL_FMT {
    () => {
        " {:<18} {:<8} {:<9} {:<18} {:<18}"
    };
}
fn fmt_vpc_table_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            VPC_TBL_FMT!(),
            "VPC", "VNI", "peers", "remote", "peering name"
        )
    )
}

// Auxiliary type to implement detailed VPC display
pub struct VpcDetailed<'a>(pub &'a Vpc);
impl Display for VpcDetailed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vpc = self.0;
        Heading(format!("vpc: {}", vpc.name)).fmt(f)?;
        writeln!(f, " name: {}", vpc.name)?;
        writeln!(f, " vni : {}", vpc.vni)?;
        writeln!(f, " peerings: {}", vpc.peerings.len())?;
        Heading(format!("Peerings of {}", vpc.name)).fmt(f)?;
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
                format_args!(VPC_TBL_FMT!(), &self.name, self.vni, "", "", "")
            )?;
        } else {
            // VPC that has peerings
            for (num, peering) in self.peerings.iter().enumerate() {
                let (name, vni, num_peers) = if num == 0 {
                    (
                        self.name.as_str(),
                        self.vni.to_string(),
                        self.peerings.len().to_string(),
                    )
                } else {
                    ("", "".to_string(), "".to_string())
                };
                writeln!(
                    f,
                    "{}",
                    format_args!(
                        VPC_TBL_FMT!(),
                        name, vni, num_peers, peering.remote.name, peering.name
                    )
                )?;
            }
        }
        Ok(())
    }
}
impl Display for VpcTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("VPCs ({})", self.len())).fmt(f)?;
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
        Heading(format!("VPC Peering Table ({})", self.len())).fmt(f)?;
        for peering in self.values() {
            peering.fmt(f)?;
        }
        Ok(())
    }
}
