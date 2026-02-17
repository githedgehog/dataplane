// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding objects

#![allow(clippy::struct_field_names)]
#![allow(clippy::new_without_default)]

use ahash::RandomState;
use net::ip::NextHeader;
use net::ip::UnicastIpAddr;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::PortFwTableError;
use super::portrange::PortRange;

/// A `PortFwEntry` contains the essential data required to perform port forwarding
#[derive(Clone, Debug)]
pub struct PortFwEntry {
    pub(crate) key: PortFwKey,
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) dst_ip: UnicastIpAddr,
    pub(crate) ext_ports: PortRange,
    pub(crate) dst_ports: PortRange,
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
    pub const ESTABLISHED_TIMEOUT: Duration = Duration::from_mins(3);
    pub const INITIAL_TIMEOUT: Duration = Duration::from_secs(3);

    /// Create a port-forwarding rule
    ///
    /// # Errors
    ///
    /// This function returns a `PortFwTableError` if the rule is invalid.
    pub fn new(
        key: PortFwKey,
        dst_vpcd: VpcDiscriminant,
        dst_ip: IpAddr,
        ext_ports: (u16, u16),
        dst_ports: (u16, u16),
        init_timeout: Option<Duration>,
        estab_timeout: Option<Duration>,
    ) -> Result<Self, PortFwTableError> {
        // create rule
        let entry = Self {
            key,
            dst_vpcd,
            dst_ip: UnicastIpAddr::try_from(dst_ip).map_err(PortFwTableError::InvalidAddress)?,
            ext_ports: PortRange::new(ext_ports.0, ext_ports.1)?,
            dst_ports: PortRange::new(dst_ports.0, dst_ports.1)?,
            init_timeout: Arc::from(AtomicU64::new(
                init_timeout
                    .unwrap_or(PortFwEntry::INITIAL_TIMEOUT)
                    .as_secs(),
            )),
            estab_timeout: Arc::from(AtomicU64::new(
                estab_timeout
                    .unwrap_or(PortFwEntry::ESTABLISHED_TIMEOUT)
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

        if key.dst_ip.inner().is_unspecified() {
            return Err(PortFwTableError::InvalidAddress(key.dst_ip.inner()));
        }
        if self.dst_ip.inner().is_unspecified() {
            return Err(PortFwTableError::InvalidAddress(self.dst_ip.inner()));
        }
        if key.dst_ip.is_ipv4() && !self.dst_ip.is_ipv4()
            || key.dst_ip.is_ipv6() && !self.dst_ip.is_ipv6()
        {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding between distinct IP versions".to_string(),
            ));
        }
        if key.src_vpcd == self.dst_vpcd {
            return Err(PortFwTableError::Unsupported(
                "Can't do port-forwarding within the same VPC".to_string(),
            ));
        }
        if self.ext_ports.len() != self.dst_ports.len() {
            return Err(PortFwTableError::InvalidPortRangeMapping(
                self.ext_ports.to_string(),
                self.dst_ports.to_string(),
            ));
        }
        Ok(())
    }

    /// Tell if one entry is equivalent to the other one, except for the timeouts
    /// We need this to be able to treat those as identical, even if they aren't
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.key == other.key
            && self.dst_ip == other.dst_ip
            && self.ext_ports == other.ext_ports
            && self.dst_ports == other.dst_ports
            && self.dst_vpcd == other.dst_vpcd
    }
}

/// A `PortFwEntry` can be accessed by a `PortFwKey`
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct PortFwKey {
    src_vpcd: VpcDiscriminant,
    dst_ip: UnicastIpAddr,
    proto: NextHeader,
}

impl PortFwKey {
    #[must_use]
    pub fn new(src_vpcd: VpcDiscriminant, dst_ip: UnicastIpAddr, proto: NextHeader) -> Self {
        Self {
            src_vpcd,
            dst_ip,
            proto,
        }
    }

    #[must_use]
    pub fn proto(&self) -> NextHeader {
        self.proto
    }

    #[must_use]
    pub fn src_vpcd(&self) -> VpcDiscriminant {
        self.src_vpcd
    }

    #[must_use]
    pub fn dst_ip(&self) -> UnicastIpAddr {
        self.dst_ip
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
pub(crate) struct PortFwGroup(Vec<Arc<PortFwEntry>>);
impl PortFwGroup {
    #[must_use]
    #[allow(unused)]
    fn new() -> Self {
        Self::default()
    }
    #[must_use]
    fn new_with_entry(entry: Arc<PortFwEntry>) -> Self {
        Self(vec![entry])
    }

    /// Add a `PortFwEntry`  to a `PortFwGroup`.
    /// We allow adding the same rule multiple times (idempotence) or updating an existing entry if it is
    /// equivalent to the provided one, except for the values of the timeouts. Equivalence is dealt with by
    /// `PortFwEntry::matches()` method.
    fn add_mod_rule(&mut self, entry: Arc<PortFwEntry>) -> Result<(), PortFwTableError> {
        if let Some(index) = self.0.iter().position(|e| e.matches(&entry)) {
            let exist = self.0.get(index).unwrap_or_else(|| unreachable!());
            exist.set_init_timeout(entry.init_timeout());
            exist.set_estab_timeout(entry.estab_timeout());
            Ok(())
        } else {
            // We allow overlap in ports. There's no reason not to allow this
            // and it allows some load-balancing if needed.
            #[allow(clippy::overly_complex_bool_expr)]
            if false
                && self
                    .0
                    .iter()
                    .any(|e| e.ext_ports.overlaps_with(entry.ext_ports))
            {
                return Err(PortFwTableError::OverlappingRange(
                    entry.ext_ports.to_string(),
                ));
            }

            self.0.push(entry);
            Ok(())
        }
    }

    /// Return the rule containing the given port. Only one rule should contain a port.
    /// This should be enforced by construction. This method will return the first
    /// rule that includes the port.
    pub fn get_rule_for_port(&self, port: NonZero<u16>) -> Option<&Arc<PortFwEntry>> {
        self.0.iter().find(|e| e.ext_ports.contains(port))
    }

    /// Get a reference to the entry in this group matching the provided one
    #[cfg(test)]
    pub fn get_rule(&self, entry: &PortFwEntry) -> Option<&Arc<PortFwEntry>> {
        self.0.iter().find(|e| e.matches(entry))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Arc<PortFwEntry>> {
        self.0.iter()
    }

    #[allow(unused)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[allow(unused)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Port Forwarding table.
///
/// This table tells the data-path NF how to perform port forwarding; which
/// IP addresses and ports to re-write and among which VPCs, when that
/// cannot determined from the flow table. That is, this table is only consulted
/// in the slow path when no flow state exists in the flow table.
pub struct PortFwTable(HashMap<PortFwKey, PortFwGroup, RandomState>);
impl PortFwTable {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add a `Arc<PortFwEntry>` to this `PortFwTable`.
    /// This method is never called directly, but from `Self::update()`.
    fn add_entry(&mut self, entry: Arc<PortFwEntry>) -> Result<(), PortFwTableError> {
        let key = &entry.key;
        if let Some(group) = self.0.get_mut(key) {
            group.add_mod_rule(entry)
        } else {
            self.0.insert(*key, PortFwGroup::new_with_entry(entry));
            Ok(())
        }
    }

    /// Remove the `PortFwEntry` that matches the provided one from the table.
    /// This method is never called directly, but from `Self::update()`.
    fn remove_entry(&mut self, entry: &PortFwEntry) -> Option<Arc<PortFwEntry>> {
        let group = self.0.get_mut(&entry.key)?;
        let index = group.0.iter().position(|e| e.matches(entry))?;
        Some(group.0.swap_remove(index))
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
    #[cfg(test)]
    pub(crate) fn get_group(&self, key: &PortFwKey) -> Option<&PortFwGroup> {
        self.0.get(key)
    }

    #[must_use]
    #[cfg(test)]
    /// Lookup a `PortFwEntry` in the `PortFwTable`. For an entry to be returned, it must
    /// match the provided `PortFwEntry`, except for the timers configuration.
    /// This is only for TESTING.
    pub(crate) fn lookup_rule(&self, entry: &PortFwEntry) -> Option<&Arc<PortFwEntry>> {
        self.0
            .get(&entry.key)
            .and_then(|group| group.get_rule(entry))
    }

    #[must_use]
    #[cfg(test)]
    /// Lookup a `PortFwEntry` in the `PortFwTable` and return a `Weak` reference to it if found.
    /// For an entry to be returned, it must match the provided `PortFwEntry`, except for the timers
    /// configuration. This is only for TESTING.
    pub(crate) fn lookup_rule_ref(&self, entry: &PortFwEntry) -> Option<Weak<PortFwEntry>> {
        self.lookup_rule(entry).map(Arc::downgrade)
    }

    #[must_use]
    /// Lookup a `PortFwEntry` with the given `PortFwKey` matching (including) the given port.
    pub(crate) fn lookup_matching_rule(
        &self,
        key: &PortFwKey,
        port: NonZero<u16>,
    ) -> Option<&Arc<PortFwEntry>> {
        self.0
            .get(key)
            .and_then(|group| group.get_rule_for_port(port))
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contains_rule(&self, entry: &PortFwEntry) -> bool {
        match self.get_group(&entry.key) {
            None => false,
            Some(group) => group.0.iter().any(|e| e.as_ref() == entry),
        }
    }

    #[allow(unused)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &PortFwEntry> {
        self.0
            .values()
            .flat_map(|v| v.0.iter().map(std::convert::AsRef::as_ref))
    }

    /// Tell if an entry is within the provided ruleset
    fn rule_in_ruleset(entry: &PortFwEntry, ruleset: &[PortFwEntry]) -> bool {
        ruleset.iter().any(|e| e.matches(entry))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for PortFwTable {
    fn default() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
}

#[cfg(test)]
mod test {
    use super::{PortFwEntry, PortFwKey, PortFwTable, PortFwTableError};
    use net::ip::NextHeader;
    use net::ip::UnicastIpAddr;
    use net::packet::VpcDiscriminant;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing_test::traced_test;

    // build a sample port forwarding table
    fn build_sample_port_forwarding_table() -> PortFwTable {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(4000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::UDP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.2").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let entry1 = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            (3022, 3022),
            (22, 22),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry1.clone()).unwrap();
        assert_eq!(fwtable.0.len(), 1);
        assert_eq!(fwtable.get_group(&key).unwrap().len(), 1);

        // idempotence -- nothing gets added
        fwtable.add_entry(entry1).unwrap();
        assert_eq!(fwtable.0.len(), 1);
        assert_eq!(fwtable.get_group(&key).unwrap().len(), 1);

        // add a second entry, for the same key but distinct ports. Should succeed
        let entry2 = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(4000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.2").unwrap(),
            (3022, 3022),
            (23, 23),
            None,
            None,
        )
        .unwrap()
        .arced();

        fwtable.add_entry(entry2).unwrap();
        assert_eq!(fwtable.0.len(), 1);
        assert_eq!(fwtable.get_group(&key).unwrap().len(), 2);
    }

    #[test]
    fn test_port_forwarding_entry_reject_distinct_ip_ver() {
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let r = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("2002:a:b:c::1").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("192.168.1.1").unwrap(),
            proto: NextHeader::UDP,
        };
        let r = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            IpAddr::from_str("70.71.72.73").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
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
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
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
            IpAddr::from_str("192.168.1.1").unwrap(),
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
