// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding table and lookups

#![allow(clippy::struct_field_names)]
#![allow(clippy::new_without_default)]

use ahash::RandomState;
use arc_swap::ArcSwapOption;
use arc_swap::Guard;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;

/// A `PortFwEntry` contains the essential data required to perform port forwarding
#[derive(Copy, Clone, PartialEq)]
pub struct PortFwEntry {
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) dst_ip: IpAddr,
    pub(crate) dst_port: NonZero<u16>,
}

/// A `PortFwEntry` can be accessed by a `PortFwKey`
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct PortFwKey {
    src_vpcd: VpcDiscriminant,
    dst_ip: IpAddr,
    proto: NextHeader,
    dst_port: NonZero<u16>,
}
impl PortFwKey {
    #[must_use]
    pub fn new(
        src_vpcd: VpcDiscriminant,
        dst_ip: IpAddr,
        proto: NextHeader,
        dst_port: NonZero<u16>,
    ) -> Self {
        Self {
            src_vpcd,
            dst_ip,
            proto,
            dst_port,
        }
    }
    #[must_use]
    pub fn dst_ip(&self) -> IpAddr {
        self.dst_ip
    }

    #[must_use]
    pub fn dst_port(&self) -> NonZero<u16> {
        self.dst_port
    }
}
impl Debug for PortFwKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// A `PortFwGroup` is just a vector of `PortFwEntry`s. Instead of associating
/// a single `PortFwEntry` to a `PortFwKey`, we allow associating a `PortFwGroup`
/// which is just a vector of them in order to support load-balancing in the future
/// (at least within a VPC).
#[derive(Clone, Default)]
struct PortFwGroup(Vec<PortFwEntry>);
impl PortFwGroup {
    #[must_use]
    fn new() -> Self {
        Self::default()
    }
    #[must_use]
    fn new_with_entry(entry: PortFwEntry) -> Self {
        Self(vec![entry])
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PortFwTableError {
    #[error("Duplicate key: {0}")]
    DuplicateKey(PortFwKey),
    #[error("Unsupported: {0}")]
    Unsupported(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(IpAddr),
}

/// Port Forwarding table.
///
/// This table tells data-path how to perform port forwarding; which
/// IP addresses and ports to re-write and among which VPCs, when that
/// cannot determined from the flow table.
pub struct PortFwTable(HashMap<PortFwKey, PortFwGroup, RandomState>);
impl PortFwTable {
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }

    fn check_rule(key: PortFwKey, entry: PortFwEntry) -> Result<(), PortFwTableError> {
        if key.dst_ip.is_unspecified() {
            return Err(PortFwTableError::InvalidAddress(key.dst_ip));
        }
        if entry.dst_ip.is_unspecified() {
            return Err(PortFwTableError::InvalidAddress(entry.dst_ip));
        }
        if key.dst_ip.is_ipv4() && !entry.dst_ip.is_ipv4()
            || key.dst_ip.is_ipv6() && !entry.dst_ip.is_ipv6()
        {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding between distinct IP versions".to_string(),
            ));
        }
        if key.dst_ip.is_multicast() || entry.dst_ip.is_multicast() {
            return Err(PortFwTableError::Unsupported(
                "Port-forwarding is not supported for multicast".to_string(),
            ));
        }

        // N.B: we allow
        //   1) forwarding to distinct ip and port (NAT+PAT)
        //   2) forwarding to the same address (PAT)
        //   3) forwarding to the same port (NAT)
        //   4) forwarding to the same port and address (no translation at all)
        //      FIXME: decide if we complain for 4). If we don't packets
        //      may be admitted. If we complain, it's somebody else's responsibility.
        //
        // Also, we don't allow port forwarding within the same vpc atm. This may be
        // a legitimate case in some circumstances. However, we'd need to define a
        // peering between the same VPC, which we can't currently do.

        if key.src_vpcd == entry.dst_vpcd {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding within the same VPC".to_string(),
            ));
        }
        Ok(())
    }

    pub fn add_entry(
        &mut self,
        key: PortFwKey,
        entry: PortFwEntry,
    ) -> Result<(), PortFwTableError> {
        // check if the (key, entry) pair is legal
        Self::check_rule(key, entry)?;

        // At the moment we don't allow more than one entry per group.
        // We allow adding the same rule multiple times (idempotence).
        if let Some(group) = self.0.get(&key) {
            if let Some(exist) = group.0.first()
                && exist == &entry
            {
                return Ok(());
            }
            return Err(PortFwTableError::DuplicateKey(key));
        }
        if let Some(group) = self.0.get_mut(&key) {
            group.0.push(entry);
        } else {
            self.0.insert(key, PortFwGroup::new_with_entry(entry));
        }
        Ok(())
    }
    #[must_use]
    fn get_group(&self, key: &PortFwKey) -> Option<&PortFwGroup> {
        self.0.get(key)
    }
    #[must_use]
    pub fn lookup_rule(&self, key: &PortFwKey) -> Option<&PortFwEntry> {
        self.0.get(key).and_then(|group| group.0.first())
    }
}

/// An object to read from or write to a `PortFwTable`.
/// The use of two types -one for reads and one for both- is not needed.
#[derive(Clone)]
pub struct PortFwTableRw(Arc<ArcSwapOption<PortFwTable>>);

impl PortFwTableRw {
    #[must_use]
    pub fn new() -> Self {
        PortFwTableRw(Arc::new(ArcSwapOption::empty()))
    }
    /// Set a `PortFwTable`
    pub fn update(&self, fwtable: Arc<PortFwTable>) {
        self.0.store(Some(fwtable));
    }
    #[must_use]
    /// Get a temporary access to the inner `PortFwTable`
    pub fn load(&self) -> Guard<Option<Arc<PortFwTable>>> {
        self.0.load()
    }
    #[must_use]
    /// Tell if the inner `PortFwTable` has been configured
    pub fn is_configured(&self) -> bool {
        self.0.load().is_some()
    }
}

// Display implementations
macro_rules! PORTFW_KEY {
    ($vpc:expr, $proto:expr, $dstip:expr, $dstport:expr) => {
        format_args!(" {:>6} {:>16}:{:<} {:>5}", $vpc, $dstip, $dstport, $proto)
    };
}
macro_rules! PORTFW_ENTRY {
    ($dstip:expr, $dstport:expr, $vpc:expr) => {
        format_args!(" {:}:{:<} at {}", $dstip, $dstport, $vpc)
    };
}
impl Display for PortFwKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            PORTFW_KEY!(self.src_vpcd, self.proto, self.dst_ip, self.dst_port.get()),
        )
    }
}
impl Display for PortFwEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            PORTFW_ENTRY!(self.dst_ip, self.dst_port.get(), self.dst_vpcd)
        )
    }
}
impl Display for PortFwGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for e in &self.0 {
            write!(f, "{e}")?;
        }
        writeln!(f)
    }
}
fn fmt_port_fw_table_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        " ━━━━━━━━━━━━━━━━━━━━━━ Port forwarding table ━━━━━━━━━━━━━━━━━━━━━━"
    )
}

impl Display for PortFwTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_port_fw_table_heading(f)?;
        if self.0.is_empty() {
            return writeln!(f, " (empty)");
        }
        for (key, group) in &self.0 {
            write!(f, "{key} -> {group}")?;
        }
        Ok(())
    }
}
impl Display for PortFwTableRw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.load();
        if let Some(table) = g.as_ref() {
            table.fmt(f)
        } else {
            fmt_port_fw_table_heading(f)?;
            writeln!(f, " (not configured) ")
        }
    }
}

