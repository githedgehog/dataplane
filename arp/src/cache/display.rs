// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display of ARP/ND cache

use crate::cache::{NeighCache, NeighEntry, NeighState};
use common::cliprovider::{Age, CliSource, Heading};
use std::fmt::Display;

impl CliSource for NeighCache {}

macro_rules! NEIGH_ENTRY_FMT {
    () => {
        " {:<16} {:<10} {:<20} {:<18} {:<10} {}"
    };
}
fn fmt_neigh_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            NEIGH_ENTRY_FMT!(),
            "interface", "ifindex", "address", "mac", "state", "last-update"
        )
    )
}

impl Display for NeighEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mac = self.mac().map_or("--".to_string(), |mac| mac.to_string());
        write!(
            f,
            "{}",
            format_args!(
                NEIGH_ENTRY_FMT!(),
                self.ifname().map_or("unknown", |v| v),
                self.ifindex(),
                self.ip(),
                mac,
                self.state(),
                Age::from_instant(self.updated.into())
            )
        )
    }
}
impl Display for NeighCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("ARP/ND cache ({} entries)", self.len())).fmt(f)?;
        fmt_neigh_heading(f)?;
        for a in self.values() {
            writeln!(f, "{a}")?;
        }
        Ok(())
    }
}
impl Display for NeighState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            NeighState::Unset => "unset",
            NeighState::Incomplete => "incomplete",
            NeighState::Reachable => "reachable",
            NeighState::Stale => "stale",
            NeighState::Delay => "delay",
            NeighState::Probe => "probe",
            NeighState::Failed => "failed",
            NeighState::Noarp => "noarp",
            NeighState::Permanent => "permanent",
        };
        f.pad(state)
    }
}
