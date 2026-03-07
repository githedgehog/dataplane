// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding objects

use ahash::RandomState;
use lpm::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, Prefix};
use net::ip::NextHeader;
use net::ip::UnicastIpAddr;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::PortFwTableError;
use super::portforwarder::PortForwarder;
use super::portrange::PortRange;

/// A `PortFwEntry` contains the essential data required to perform port forwarding
#[derive(Clone, Debug)]
pub struct PortFwEntry {
    pub(crate) key: PortFwKey,
    pub(crate) dst_vpcd: VpcDiscriminant, // vpc to send packet to
    pub(crate) ext_prefix: Prefix,        // external prefix to translate
    pub(crate) int_prefix: Prefix,        // internal prefix we translate into
    pub(crate) ext_ports: PortRange,      // external ports to translate
    pub(crate) int_ports: PortRange,      // internal ports we translate into
    pub(crate) init_timeout: Arc<AtomicU64>,
    pub(crate) estab_timeout: Arc<AtomicU64>,
}

impl PartialEq for PortFwEntry {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
            && self.estab_timeout() == other.estab_timeout()
            && self.init_timeout() == other.init_timeout()
    }
}

impl PortFwEntry {
    pub const DEFAULT_INITIAL_TOUT: Duration = Duration::from_secs(10);
    pub const DEFAULT_ESTABLISHED_TOUT_TCP: Duration = Duration::from_mins(30);
    pub const DEFAULT_ESTABLISHED_TOUT_UDP: Duration = Duration::from_secs(30);

    /// Provide the default established timeout for flows in port-forwarding,
    /// according to protocol
    fn default_established_timeout(proto: NextHeader) -> Duration {
        match proto {
            NextHeader::TCP => PortFwEntry::DEFAULT_ESTABLISHED_TOUT_TCP,
            NextHeader::UDP => PortFwEntry::DEFAULT_ESTABLISHED_TOUT_UDP,
            _ => unreachable!(),
        }
    }

    /// Create a port-forwarding rule
    ///
    /// # Errors
    ///
    /// This function returns a `PortFwTableError` if the rule is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: PortFwKey,
        dst_vpcd: VpcDiscriminant,
        ext_dst_ip: Prefix,
        dst_ip: Prefix,
        ext_ports: (u16, u16),
        dst_ports: (u16, u16),
        init_timeout: Option<Duration>,
        estab_timeout: Option<Duration>,
    ) -> Result<Self, PortFwTableError> {
        // create rule
        let entry = Self {
            key,
            dst_vpcd,
            ext_prefix: ext_dst_ip,
            int_prefix: dst_ip,
            ext_ports: PortRange::new(ext_ports.0, ext_ports.1)?,
            int_ports: PortRange::new(dst_ports.0, dst_ports.1)?,
            init_timeout: Arc::from(AtomicU64::new(
                init_timeout
                    .unwrap_or(PortFwEntry::DEFAULT_INITIAL_TOUT)
                    .as_secs(),
            )),
            estab_timeout: Arc::from(AtomicU64::new(
                estab_timeout
                    .unwrap_or(Self::default_established_timeout(key.proto))
                    .as_secs(),
            )),
        };

        // do further checks
        entry.is_valid()?;
        Ok(entry)
    }

    #[cfg(test)]
    pub(crate) fn arced(self) -> Arc<Self> {
        Arc::from(self)
    }

    #[must_use]
    pub fn init_timeout(&self) -> Duration {
        Duration::from_secs(self.init_timeout.load(std::sync::atomic::Ordering::Relaxed))
    }

    #[must_use]
    pub fn estab_timeout(&self) -> Duration {
        Duration::from_secs(
            self.estab_timeout
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn set_init_timeout(&self, duration: Duration) {
        self.init_timeout
            .store(duration.as_secs(), Ordering::Relaxed);
    }

    pub fn set_estab_timeout(&self, duration: Duration) {
        self.estab_timeout
            .store(duration.as_secs(), Ordering::Relaxed);
    }

    fn is_valid(&self) -> Result<(), PortFwTableError> {
        let key = &self.key;

        if !self.int_prefix.matches_version(self.ext_prefix) {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding between distinct IP versions".to_string(),
            ));
        }
        if self.int_prefix.length() != self.ext_prefix.length() {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding between prefixes of distinct length".to_string(),
            ));
        }
        if key.src_vpcd == self.dst_vpcd {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding within the same VPC".to_string(),
            ));
        }
        if self.ext_ports.len() != self.int_ports.len() {
            return Err(PortFwTableError::InvalidPortRangeMapping(
                self.ext_ports.to_string(),
                self.int_ports.to_string(),
            ));
        }
        Ok(())
    }

    /// Tell if one entry is equivalent to the other one, except for the timeouts
    /// We need this to be able to treat those as identical, even if they aren't
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.key == other.key
            && self.ext_prefix == other.ext_prefix
            && self.int_prefix == other.int_prefix
            && self.ext_ports == other.ext_ports
            && self.int_ports == other.int_ports
            && self.dst_vpcd == other.dst_vpcd
    }

    fn map_ipv4(address: Ipv4Addr, from: Ipv4Prefix, to: Ipv4Prefix) -> IpAddr {
        let offset = address.to_bits() - from.network().to_bits();
        Ipv4Addr::from_bits(to.network().to_bits() + offset).into()
    }
    fn map_ipv6(address: Ipv6Addr, from: Ipv6Prefix, to: Ipv6Prefix) -> IpAddr {
        let offset = address.to_bits() - from.network().to_bits();
        Ipv6Addr::from_bits(to.network().to_bits() + offset).into()
    }
    fn map_ip(address: IpAddr, from: Prefix, to: Prefix) -> Option<IpAddr> {
        match address {
            IpAddr::V4(a) => Some(Self::map_ipv4(
                a,
                from.try_into().ok()?,
                to.try_into().ok()?,
            )),
            IpAddr::V6(a) => Some(Self::map_ipv6(
                a,
                from.try_into().ok()?,
                to.try_into().ok()?,
            )),
        }
    }

    /// Transform an address and a port according to this rule. It is assumed that the
    /// input address and port fall within the prefix and port range represented by this rule.
    #[must_use]
    pub fn map_address_port(
        &self,
        dst_ip: IpAddr,
        dst_port: NonZero<u16>,
    ) -> Option<(UnicastIpAddr, NonZero<u16>)> {
        let new_dst_port = self.ext_ports.map_port_to(dst_port, self.int_ports)?;
        let new_dst_ip = Self::map_ip(dst_ip, self.ext_prefix, self.int_prefix)?;
        let new_ip = UnicastIpAddr::try_from(new_dst_ip).ok()?;
        Some((new_ip, new_dst_port))
    }
}

/// A `PortFwEntry` can be accessed by a `PortFwKey`
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct PortFwKey {
    src_vpcd: VpcDiscriminant,
    proto: NextHeader,
}

impl PortFwKey {
    #[must_use]
    pub fn new(src_vpcd: VpcDiscriminant, proto: NextHeader) -> Self {
        Self { src_vpcd, proto }
    }

    #[must_use]
    pub fn proto(&self) -> NextHeader {
        self.proto
    }

    #[must_use]
    pub fn src_vpcd(&self) -> VpcDiscriminant {
        self.src_vpcd
    }
}

impl Debug for PortFwKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// Port Forwarding table.
///
/// This table tells the data-path NF how to perform port forwarding; which
/// IP addresses and ports to re-write and among which VPCs, when that
/// cannot determined from the flow table. That is, this table is only consulted
/// in the slow path when no flow state exists in the flow table.
pub struct PortFwTable(HashMap<PortFwKey, PortForwarder, RandomState>);
impl Default for PortFwTable {
    fn default() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
}
impl PortFwTable {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add a `Arc<PortFwEntry>` to this `PortFwTable`.
    fn add_entry(&mut self, entry: Arc<PortFwEntry>) -> Result<(), PortFwTableError> {
        let key = &entry.key;
        let forwarder = self.0.entry(*key).or_default();

        // check if an identical entry exists, except for the timers
        // This could be done in the base definition of `RangeSet`. However, that would require us to
        // implement `PartialEq` or add a trait bound for equivalence
        if let Some(exist) = forwarder.get_rule(entry.ext_prefix, entry.ext_ports)
            && exist.matches(&entry)
        {
            exist.set_init_timeout(entry.init_timeout());
            exist.set_estab_timeout(entry.estab_timeout());
            return Ok(());
        }

        forwarder
            .insert_rule(entry)
            .map_err(|e| PortFwTableError::OverlappingRange(e.to_string()))
    }

    /// Remove the `PortFwEntry` that matches the provided one from the table.
    fn remove_entry(&mut self, entry: &PortFwEntry) -> Option<Arc<PortFwEntry>> {
        let forwarder = self.0.get_mut(&entry.key)?;
        forwarder.remove_rule(entry)
    }

    #[allow(unused)]
    /// Update the `PortFwTable` with a set of `PortFwEntry`
    pub(crate) fn update(&mut self, ruleset: &[PortFwEntry]) {
        let mut delete: Vec<PortFwEntry> = vec![];
        for entry in self.values() {
            if !Self::rule_in_ruleset(entry, ruleset) {
                delete.push(entry.clone());
            }
        }
        for e in &delete {
            self.remove_entry(e);
        }
        let mut ruleset = ruleset.to_vec();
        while let Some(rule) = ruleset.pop().map(Arc::from) {
            if let Err(e) = self.add_entry(rule.clone()) {
                // FIXME(fredi): these should never fail with the validation
                unreachable!()
            }
        }
    }

    #[must_use]
    /// Lookup a `PortFwEntry` with the given `PortFwKey` matching (including) the given port.
    pub(crate) fn lookup_matching_rule(
        &self,
        key: PortFwKey,
        address: IpAddr,
        port: NonZero<u16>,
    ) -> Option<&Arc<PortFwEntry>> {
        self.0
            .get(&key)
            .and_then(|forwarder| forwarder.lookup(address, port))
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &PortFwEntry> {
        self.0.values().flat_map(PortForwarder::iter)
    }

    /// Tell if an entry is within the provided ruleset
    fn rule_in_ruleset(entry: &PortFwEntry, ruleset: &[PortFwEntry]) -> bool {
        ruleset.iter().any(|e| e.matches(entry))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
impl PortFwTable {
    #[must_use]
    /// Lookup a `PortFwEntry` in the `PortFwTable`. For an entry to be returned, it must
    /// match the provided `PortFwEntry`, except for the timers configuration.
    /// This is only for TESTING.
    pub(crate) fn lookup_rule(&self, entry: &PortFwEntry) -> Option<&Arc<PortFwEntry>> {
        self.0
            .get(&entry.key)
            .and_then(|forwarder| forwarder.get_rule(entry.ext_prefix, entry.ext_ports))
    }

    #[must_use]
    /// Lookup a `PortFwEntry` in the `PortFwTable` and return a `Weak` reference to it if found.
    pub(crate) fn lookup_rule_ref(&self, entry: &PortFwEntry) -> Option<Weak<PortFwEntry>> {
        self.lookup_rule(entry).map(Arc::downgrade)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contains_rule(&self, entry: &PortFwEntry) -> bool {
        if let Some(exist) = self.lookup_rule(entry) {
            exist.as_ref() == entry
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::{PortFwEntry, PortFwKey, PortFwTable, PortFwTableError};
    use lpm::prefix::Prefix;
    use net::ip::NextHeader;
    use net::packet::VpcDiscriminant;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing_test::traced_test;

    // build a sample port forwarding table
    fn build_sample_port_forwarding_table() -> PortFwTable {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry.clone()).unwrap();
        assert!(fwtable.contains_rule(&entry));

        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(4000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (4022, 4022),
            (22, 22),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry.clone()).unwrap();
        assert!(fwtable.contains_rule(&entry));

        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3080, 3080),
            (80, 80),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry.clone()).unwrap();
        assert!(fwtable.contains_rule(&entry));

        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::UDP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.2/32").unwrap(),
            (3053, 3053),
            (53, 53),
            None,
            None,
        )
        .unwrap();
        fwtable.add_entry(Arc::from(entry)).unwrap();

        fwtable
    }

    #[test]
    fn test_port_forwarding_table_dup_keys() {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let entry1 = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry1.clone()).unwrap();
        assert_eq!(fwtable.0.len(), 1);

        // idempotence -- nothing gets added
        fwtable.add_entry(entry1).unwrap();
        assert_eq!(fwtable.0.len(), 1);

        // add a second entry, for the same key but distinct ports. Should succeed
        let entry2 = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(4000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3023, 3023),
            (23, 23),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry2).unwrap();
        assert_eq!(fwtable.0.len(), 1);
    }

    #[test]
    fn test_port_forwarding_entry_reject_distinct_ip_ver() {
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let r = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("2002:a:b:c::1/128").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        );
        assert!(r.is_err_and(|e| matches!(e, PortFwTableError::Unsupported(_))));
    }

    #[test]
    fn test_port_forwarding_entry_reject_common_vpcd() {
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::UDP,
        };
        let r = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        );
        assert!(r.is_err_and(|e| matches!(e, PortFwTableError::Unsupported(_))));
    }

    #[test]
    #[traced_test]
    fn test_port_forwarding_table_removals() {
        let mut fwtable = build_sample_port_forwarding_table();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        )
        .unwrap();

        // check that entry exists
        assert!(fwtable.contains_rule(&entry));

        // lookup
        let found = fwtable.lookup_rule(&entry).unwrap();
        assert_eq!(found.as_ref(), &entry);

        // lookup + weak ref
        let weak = fwtable.lookup_rule_ref(&entry).unwrap();
        assert_eq!(weak.upgrade().unwrap().as_ref(), &entry);

        // remove
        fwtable.remove_entry(&entry);
        assert!(!fwtable.contains_rule(&entry));
        assert!(fwtable.lookup_rule(&entry).is_none());
        assert!(weak.upgrade().is_none());
    }

    #[test]
    #[traced_test]
    fn test_port_forwarding_table_updates() {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        )
        .unwrap()
        .arced();

        // add rule and check it exists in table
        fwtable.add_entry(entry.clone()).unwrap();
        assert!(fwtable.contains_rule(&entry));

        // get a weak reference to the rule
        let weak = fwtable.lookup_rule_ref(&entry).unwrap();
        assert_eq!(weak.upgrade().unwrap().as_ref(), entry.as_ref());

        // add same rule but with modified timeouts
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            Prefix::from_str("70.71.72.73/32").unwrap(),
            Prefix::from_str("192.168.1.1/32").unwrap(),
            (3022, 3022),
            (22, 22),
            Some(Duration::from_secs(13)),
            Some(Duration::from_secs(99)),
        )
        .unwrap()
        .arced();

        let _r = fwtable.add_entry(entry.clone());

        // check that the weak reference is still valid and that entry was updated
        assert_eq!(weak.upgrade().unwrap().as_ref(), entry.as_ref());
    }
}
