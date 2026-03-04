// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow keys

use super::flow_key::{FlowKey, FlowKeyData, IcmpProtoKey, IpProtoKey};
use std::fmt::Display;

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
            Some(vpcd) => write!(f, "{{ VPCs({vpcd}"),
            None => write!(f, "{{ VPCs(None->"),
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
