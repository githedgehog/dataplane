// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to compute packet processing counters

use super::meta::DoneReason;
use common::cliprovider::{CliDataProvider, Heading};
use std::fmt::Display;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use strum::EnumCount;

/// A tiny table of packet counts per `DoneReason`
pub struct PacketStats {
    counts: Vec<AtomicU64>,
}
impl PacketStats {
    #[must_use]
    #[allow(clippy::new_without_default)]
    /// Build an instance of `PacketStats`
    pub fn new() -> Self {
        Self {
            counts: (0..DoneReason::COUNT).map(|_| AtomicU64::new(0)).collect(),
        }
    }
    /// Increment the count for a given `DoneReason`
    pub fn incr(&self, done_reason: DoneReason) {
        self.counts[done_reason as usize].fetch_add(1, Ordering::Relaxed);
    }
    /// Provide a snapshot of the `PacketStats`
    pub fn snapshot(&self) -> impl Iterator<Item = (DoneReason, u64)> {
        self.counts.iter().enumerate().map(|(reason, count)| {
            (
                DoneReason::from(u8::try_from(reason).unwrap_or_else(|_| unreachable!())),
                count.load(Ordering::Relaxed),
            )
        })
    }
}

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
        for (reason, count) in self.snapshot() {
            writeln!(f, PKT_STATS!(), reason.to_string(), count)?;
        }
        Ok(())
    }
}

impl CliDataProvider for PacketStats {
    fn provide(&self, _what: Option<common::cliprovider::CliData>) -> String {
        self.to_string()
    }
}

#[cfg(test)]
mod test {
    use crate::packet::DoneReason;
    use crate::packet::stats::PacketStats;

    #[test]
    fn test_packet_stats_display() {
        let stats = PacketStats::new();
        stats.incr(DoneReason::Delivered);
        stats.incr(DoneReason::InvalidChecksum);
        stats.incr(DoneReason::NatFailure);
        println!("{stats}");
    }
}
