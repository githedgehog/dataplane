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
            Self::InternalFailure => write!(f, "Internal failure"),

            Self::InterfaceDetached => write!(f, "Interface: detached"),
            Self::InterfaceAdmDown => write!(f, "Interface: admin down"),
            Self::InterfaceOperDown => write!(f, "Interface: oper down"),
            Self::InterfaceUnknown => write!(f, "Interface: unknown"),
            Self::InterfaceUnsupported => write!(f, "Interface: unsupported"),

            Self::NotEthernet => write!(f, "Not Ethernet"),
            Self::Unhandled => write!(f, "Unhandled"),
            Self::MacNotForUs => write!(f, "Frame not for us"),
            Self::MissingEtherType => write!(f, "Missing ether type"),
            Self::InvalidDstMac => write!(f, "Invalid dst MAC"),

            Self::NotIp => write!(f, "IP:  packet is not IP"),
            Self::RouteFailure => write!(f, "IP:  missing routing info"),
            Self::RouteDrop => write!(f, "IP:  route drop"),
            Self::HopLimitExceeded => write!(f, "IP:  TTL exceeded"),
            Self::MissL2resolution => write!(f, "IP:  L2 resolution failure"),

            Self::Filtered => write!(f, "Filtered"),

            Self::NatOutOfResources => write!(f, "NAT: out of resources"),
            Self::NatFailure => write!(f, "NAT: failure"),
            Self::NatUnsupportedProto => write!(f, "NAT: Unsupported protocol"),
            Self::NatNotPortForwarded => write!(f, "NAT: not port-forwarded"),

            Self::Malformed => write!(f, "Malformed packet"),
            Self::Unroutable => write!(f, "Unroutable"),
            Self::InvalidChecksum => write!(f, "Invalid checksum"),
            Self::IcmpErrorIncomplete => write!(f, "Incomplete ICMP error"),

            Self::InternalDrop => write!(f, "Internal drop"),
            Self::Local => write!(f, "Locally delivered"),
            Self::Delivered => write!(f, "Delivered"),
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
        for (reason, counter) in self.snapshot() {
            writeln!(f, PKT_STATS!(), reason, counter)?;
        }
        Ok(())
    }
}

impl CliDataProvider for PacketStats {
    fn provide(&self) -> String {
        self.to_string()
    }
}
