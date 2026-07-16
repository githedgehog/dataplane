// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display implementations

use common::cliprovider::{CliSource, Heading};
use indenter::indented;

use std::collections::BTreeMap;
use std::fmt::Display;
use std::fmt::Write;

use crate::tables::{DstConnectionData, PortRangeMap, VpcConnectionsTable};
use crate::{FlowFilterTable, RemoteData, VpcdLookupResult};

impl CliSource for FlowFilterTable {}

impl Display for FlowFilterTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Flow filter").fmt(f)?;

        // Collect into a BTreeMap to get a deterministic order when dumping the entries
        writeln!(f, "subtable for TCP/UDP:")?;
        for (src_vpcd, table) in self
            .with_ports
            .0
            .clone()
            .into_iter()
            .collect::<BTreeMap<_, _>>()
        {
            writeln!(f, "  source VPC {src_vpcd}:")?;
            write!(indented(f).with_str("    "), "{table}")?;
            writeln!(f)?;
        }

        writeln!(f, "subtable for ICMP:")?;
        for (src_vpcd, table) in self
            .no_ports
            .0
            .clone()
            .into_iter()
            .collect::<BTreeMap<_, _>>()
        {
            writeln!(f, "  source VPC {src_vpcd}:")?;
            write!(indented(f).with_str("    "), "{table}")?;
            writeln!(f)?;
        }
        Ok(())
    }
}

impl Display for VpcConnectionsTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix, port_range_map) in self.trie.iter() {
            match port_range_map {
                PortRangeMap::AllPorts(data) => {
                    writeln!(f, "source: {prefix}")?;
                    write!(indented(f).with_str("  "), "{data}")?;
                }
                PortRangeMap::Ranges(port_ranges) => {
                    for (port_range, data) in port_ranges.iter() {
                        writeln!(f, "source: {prefix}:{port_range}")?;
                        write!(indented(f).with_str("  "), "{data}")?;
                    }
                }
            }
        }
        if let Some(default_source) = &self.default_source {
            writeln!(f, "local default:")?;
            match default_source {
                PortRangeMap::AllPorts(data) => {
                    write!(indented(f).with_str("  "), "{data}")?;
                }
                PortRangeMap::Ranges(port_ranges) => {
                    for (port_range, data) in port_ranges.iter() {
                        writeln!(f, "  ports: {port_range}")?;
                        write!(indented(f).with_str("    "), "{data}")?;
                    }
                }
            }
        } else {
            writeln!(f, "no local default")?;
        }
        Ok(())
    }
}

impl Display for DstConnectionData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (prefix, port_range_map) in self.trie.iter() {
            match port_range_map {
                PortRangeMap::AllPorts(result) => {
                    writeln!(f, "destination: {prefix}, data:")?;
                    write!(indented(f).with_str("  "), "{result}")?;
                }
                PortRangeMap::Ranges(port_ranges) => {
                    for (port_range, result) in port_ranges.iter() {
                        writeln!(f, "destination: {prefix}:{port_range}, data:")?;
                        write!(indented(f).with_str("  "), "{result}")?;
                    }
                }
            }
        }
        if let Some(port_range_map) = &self.default_remote_data {
            match port_range_map {
                PortRangeMap::AllPorts(result) => {
                    writeln!(f, "remote default data:")?;
                    write!(indented(f).with_str("  "), "{result}")?;
                }
                PortRangeMap::Ranges(port_ranges) => {
                    writeln!(f, "remote default:")?;
                    for (port_range, result) in port_ranges.iter() {
                        writeln!(f, "  ports: {port_range}, data:")?;
                        write!(indented(f).with_str("    "), "{result}")?;
                    }
                }
            }
        } else {
            writeln!(f, "no remote default")?;
        }
        Ok(())
    }
}

impl Display for VpcdLookupResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpcdLookupResult::Single(remote_data) => {
                writeln!(f, "{remote_data}")
            }
            VpcdLookupResult::MultipleMatches(remote_data_set) => {
                for remote_data in remote_data_set {
                    writeln!(f, "{remote_data}")?;
                }
                Ok(())
            }
        }
    }
}

impl Display for RemoteData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "destination VPC: {}, ", self.vpcd)?;
        if let Some(src_nat_req) = &self.src_nat_req {
            write!(f, "source NAT: {src_nat_req:?}, ")?;
        } else {
            write!(f, "source NAT: -, ")?;
        }
        if let Some(dst_nat_req) = &self.dst_nat_req {
            write!(f, "destination NAT: {dst_nat_req:?}")?;
        } else {
            write!(f, "destination NAT: -")?;
        }
        Ok(())
    }
}
