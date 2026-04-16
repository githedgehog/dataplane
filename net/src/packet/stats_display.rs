// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Display of `PacketStats`

use common::cliprovider::{CliDataProvider, Heading};
use std::fmt::Display;

use super::meta::DoneReason;
use super::stats::PacketStats;

impl Display for DoneReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InternalFailure => f.pad("Internal failure"),

            Self::InterfaceDetached => f.pad("Interface: detached"),
            Self::InterfaceAdmDown => f.pad("Interface: admin down"),
            Self::InterfaceOperDown => f.pad("Interface: oper down"),
            Self::InterfaceUnknown => f.pad("Interface: unknown"),
            Self::InterfaceUnsupported => f.pad("Interface: unsupported"),

            Self::NotEthernet => f.pad("Not Ethernet"),
            Self::Unhandled => f.pad("Unhandled"),
            Self::MacNotForUs => f.pad("Frame not for us"),
            Self::MissingEtherType => f.pad("Missing ether type"),
            Self::InvalidDstMac => f.pad("Invalid dst MAC"),

            Self::NotIp => f.pad("IP:  packet is not IP"),
            Self::RouteFailure => f.pad("IP:  missing routing info"),
            Self::RouteDrop => f.pad("IP:  route drop"),
            Self::HopLimitExceeded => f.pad("IP:  TTL exceeded"),
            Self::MissL2resolution => f.pad("IP:  L2 resolution failure"),

            Self::Filtered => f.pad("Filtered"),

            Self::NatOutOfResources => f.pad("NAT: out of resources"),
            Self::NatFailure => f.pad("NAT: failure"),
            Self::NatUnsupportedProto => f.pad("NAT: Unsupported protocol"),
            Self::NatNotPortForwarded => f.pad("NAT: not port-forwarded"),

            Self::Malformed => f.pad("Malformed packet"),
            Self::Unroutable => f.pad("Unroutable"),
            Self::InvalidChecksum => f.pad("Invalid checksum"),
            Self::IcmpErrorIncomplete => f.pad("Incomplete ICMP error"),

            Self::InternalDrop => f.pad("Internal drop"),
            Self::Local => f.pad("Locally delivered"),
            Self::Delivered => f.pad("Delivered"),
        }
    }
}

macro_rules! PKT_STATS {
    () => {
        "    {:<30} {}"
    };
}

impl Display for PacketStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Packet stats").fmt(f)?;
        writeln!(f, PKT_STATS!(), "Packet result", "count")?;
        for (index, counter) in self.snapshot().iter().enumerate() {
            let reason_u8 = u8::try_from(index).unwrap_or_else(|_| unreachable!());
            if let Some(reason) = DoneReason::from_repr(reason_u8) {
                writeln!(f, PKT_STATS!(), reason, counter)?;
            }
        }
        Ok(())
    }
}

impl CliDataProvider for PacketStats {
    fn provide(&self) -> String {
        self.to_string()
    }
}
