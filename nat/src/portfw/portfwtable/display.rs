// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations for the forwarding table objects

use crate::portfw::portfwtable::objects::{PortFwEntry, PortFwKey, PortFwTable};
use common::cliprovider::{CliSource, Heading};
use std::fmt::Display;

impl CliSource for PortFwTable {}

macro_rules! PORTFW_KEY {
    ($vpc:expr, $proto:expr) => {
        format_args!("{:>} {:<3}", $vpc, $proto)
    };
}
macro_rules! PORTFW_ENTRY {
    ($extip:expr, $extports:expr, $dstip:expr, $ports:expr, $vpc:expr, $initial:expr, $estab:expr) => {
        format_args!(
            "{}:{:<6} -> {:}:{:<6} at {} timers:[init:{}s estab:{}s]",
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
            " {}: {}",
            self.key,
            PORTFW_ENTRY!(
                self.ext_prefix,
                self.ext_ports,
                self.int_prefix,
                self.int_ports,
                self.dst_vpcd,
                self.init_timeout().as_secs(),
                self.estab_timeout().as_secs()
            )
        )
    }
}

impl Display for PortFwTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Port forwarding table").fmt(f)?;
        if self.is_empty() {
            return writeln!(f, " (empty)");
        }
        for entry in self.values() {
            writeln!(f, "{entry}")?;
        }
        Ok(())
    }
}
