// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::flow_key::IcmpProtoKey;
use super::{FlowKey, FlowKeyData, FlowTable, IpProtoKey};
use std::fmt::Display;

// Copied from crates "config" and "routing"
// TODO: Move to a shared location
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

impl Display for FlowKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (protocol, source, destination, icmp_data) = match self.proto_key_info() {
            IpProtoKey::Tcp(key) => (
                "TCP",
                format!("{}:{}", self.src_ip(), key.src_port.as_u16()),
                format!("{}:{}", self.dst_ip(), key.dst_port.as_u16()),
                String::new(),
            ),
            IpProtoKey::Udp(key) => (
                "UDP",
                format!("{}:{}", self.src_ip(), key.src_port.as_u16()),
                format!("{}:{}", self.dst_ip(), key.dst_port.as_u16()),
                String::new(),
            ),
            IpProtoKey::Icmp(key) => {
                let icmp_data_str = match key {
                    IcmpProtoKey::QueryMsgData(id) => format!("id:{id}"),
                    IcmpProtoKey::ErrorMsgData(Some(_)) => "<embedded datagram>".to_string(),
                    IcmpProtoKey::ErrorMsgData(None) | IcmpProtoKey::Unsupported => String::new(),
                };
                (
                    "ICMP",
                    format!("{}", self.src_ip()),
                    format!("{}", self.dst_ip()),
                    icmp_data_str,
                )
            }
        };

        match self.src_vpcd() {
            Some(vpcd) => write!(f, "{{ VPCs({vpcd}->"),
            None => write!(f, "{{ VPCs(None->"),
        }?;
        match self.dst_vpcd() {
            Some(vpcd) => write!(f, "{vpcd})"),
            None => write!(f, "None)"),
        }?;
        write!(f, " {protocol} ({source}, {destination}){icmp_data} }}")
    }
}

impl Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowKey::Unidirectional(data) => write!(f, "{data}"),
        }
    }
}

impl Display for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let table = self.table.read().unwrap();
        Heading(format!("Flow Table ({})", table.len())).fmt(f)?;
        for entry in table.iter() {
            if let Some(value) = entry.value().upgrade() {
                let value = value.locked.read().unwrap();
                let nat_state = value.nat_state.as_ref();
                let dst_vpcd = value.dst_vpcd.as_ref();
                write!(f, "{} -> ", entry.key())?;
                match nat_state {
                    Some(state) => write!(f, "{{ {state}, "),
                    None => write!(f, "{{ None, "),
                }?;
                match dst_vpcd {
                    Some(vpcd) => writeln!(f, "dst_vpcd: {vpcd} }}"),
                    None => writeln!(f, "dst_vpcd: None }}"),
                }?;
            }
        }
        Ok(())
    }
}
