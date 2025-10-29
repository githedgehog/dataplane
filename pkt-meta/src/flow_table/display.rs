// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::flow_key::IcmpProtoKey;
use super::{FlowKeyData, IpProtoKey};
use net::packet::VpcDiscriminant;

impl std::fmt::Display for FlowKeyData {
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

        write!(
            f,
            "{{ VPCs({}->{}) [proto: {}] ({}, {}){} }}",
            self.src_vpcd()
                .as_ref()
                .map_or(String::new(), VpcDiscriminant::to_string),
            self.dst_vpcd()
                .as_ref()
                .map_or(String::new(), VpcDiscriminant::to_string),
            protocol,
            source,
            destination,
            icmp_data,
        )
    }
}
