// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the forwarding table objects

use std::fmt::Display;

use crate::portfw::portfwtable::objects::{PortFwEntry, PortFwGroup, PortFwKey, PortFwTable};

macro_rules! PORTFW_KEY {
    ($vpc:expr, $proto:expr) => {
        format_args!("{:>} {:<3}", $vpc, $proto)
    };
}
macro_rules! PORTFW_ENTRY {
    ($extip:expr, $extports:expr, $dstip:expr, $ports:expr, $vpc:expr, $initial:expr, $estab:expr) => {
        format_args!(
            "{}:{} -> {:}:{:<} at {} timers:[init:{}s estab:{}s]",
            $extip, $extports, $dstip, $ports, $vpc, $initial, $estab
        )
    };
}
impl Display for PortFwKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", PORTFW_KEY!(self.src_vpcd(), self.proto()),)
    }
}
impl Display for PortFwEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            self.key,
            PORTFW_ENTRY!(
                self.ext_dst_ip,
                self.ext_ports,
                self.dst_ip,
                self.dst_ports,
                self.dst_vpcd,
                self.init_timeout().as_secs(),
                self.estab_timeout().as_secs()
            )
        )
    }
}
impl Display for PortFwGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for e in self.iter() {
            write!(f, "{e}")?;
        }
        writeln!(f)
    }
}
fn fmt_port_fw_table_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Port forwarding table ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
}

impl Display for PortFwTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_port_fw_table_heading(f)?;
        if self.is_empty() {
            return writeln!(f, " (empty)");
        }
        for entry in self.values() {
            writeln!(f, "{entry}")?;
        }
        Ok(())
    }
}
