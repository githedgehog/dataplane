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

/// A `PortFwEntry` contains the essential data required to perform port forwarding
#[derive(Clone, Debug)]
pub struct PortFwEntry {
    pub(crate) key: PortFwKey,
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) dst_ip: UnicastIpAddr,
    pub(crate) dst_port: NonZero<u16>,
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

    pub fn new(
        key: PortFwKey,
        dst_vpcd: VpcDiscriminant,
        dst_ip: IpAddr,
        dst_port: u16,
        init_timeout: Option<Duration>,
        estab_timeout: Option<Duration>,
    ) -> Result<Self, PortFwTableError> {
        let entry = Self {
            key,
            dst_vpcd,
            dst_ip: UnicastIpAddr::try_from(dst_ip).map_err(PortFwTableError::InvalidAddress)?,
            dst_port: NonZero::try_from(dst_port)
                .map_err(|_| PortFwTableError::InvalidPort(dst_port))?,
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
        Ok(())
    }

    /// Tell if one entry is equivalent to the other one, except for the timeouts
    /// We need this to be able to treat those as identical, even if they aren't
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.key == other.key
            && self.dst_ip == other.dst_ip
            && self.dst_port == other.dst_port
            && self.dst_vpcd == other.dst_vpcd
    }
}

/// A `PortFwEntry` can be accessed by a `PortFwKey`
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct PortFwKey {
    src_vpcd: VpcDiscriminant,
    dst_ip: UnicastIpAddr,
    proto: NextHeader,
    dst_port: NonZero<u16>,
}
impl PortFwKey {
    #[must_use]
    pub fn new(
        src_vpcd: VpcDiscriminant,
        dst_ip: UnicastIpAddr,
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
    /// Add a `PortFwEntry`  to a `PortFwGroup`. At the moment we don't allow more than ONE entry per group.
    /// We allow adding the same rule multiple times (idempotence) or updating an existing entry if it is
    /// equivalent to the provided one, except for the values of the timeouts. Equivalence is dealt with by
    /// `PortFwEntry::matches()` method.
    fn add_mod_rule(&mut self, entry: Arc<PortFwEntry>) -> Result<(), PortFwTableError> {
        if let Some(index) = self.0.iter().position(|e| e.matches(&entry)) {
            let exist = self.0.get(index).unwrap_or_else(|| unreachable!());
            exist.set_init_timeout(entry.init_timeout());
            exist.set_estab_timeout(entry.estab_timeout());
            Ok(())
        } else if self.is_empty() {
            self.0.push(entry);
            Ok(())
        } else {
            Err(PortFwTableError::DuplicateKey(entry.key))
        }
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
/// cannot determined from the flow table.
pub struct PortFwTable(HashMap<PortFwKey, PortFwGroup, RandomState>);
impl PortFwTable {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_entry(&mut self, entry: Arc<PortFwEntry>) -> Result<(), PortFwTableError> {
        let key = &entry.key;
        if let Some(group) = self.0.get_mut(key) {
            group.add_mod_rule(entry)
        } else {
            self.0.insert(*key, PortFwGroup::new_with_entry(entry));
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn remove_entry_by_key(&mut self, key: &PortFwKey) {
        self.0.remove(key);
    }

    #[allow(unused)]
    pub(crate) fn remove_entry(&mut self, entry: &PortFwEntry) {
        let Some(group) = self.0.get_mut(&entry.key) else {
            return;
        };
        if let Some(index) = group.0.iter().position(|e| e.matches(entry)) {
            group.0.remove(index);
        }
    }

    #[must_use]
    #[allow(unused)]
    #[cfg(test)]
    fn get_group(&self, key: &PortFwKey) -> Option<&PortFwGroup> {
        self.0.get(key)
    }

    #[must_use]
    pub(crate) fn lookup_rule(&self, key: &PortFwKey) -> Option<&Arc<PortFwEntry>> {
        self.0.get(key).and_then(|group| group.0.first())
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn lookup_rule_ref(&self, key: &PortFwKey) -> Option<Weak<PortFwEntry>> {
        self.0
            .get(key)
            .map(|group| group.0.first().map(Arc::downgrade))?
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contains_rule(&self, entry: &PortFwEntry) -> bool {
        match self.lookup_rule(&entry.key) {
            None => false,
            Some(e) => e.as_ref() == entry,
        }
    }

    #[allow(unused)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &PortFwEntry> {
        self.0
            .values()
            .flat_map(|v| v.0.iter().map(std::convert::AsRef::as_ref))
    }

    fn rule_can_be_deleted(entry: &PortFwEntry, ruleset: &[PortFwEntry]) -> bool {
        ruleset.iter().any(|e| e.matches(entry))
    }

    #[allow(unused)]
    pub(crate) fn update(&mut self, ruleset: &[PortFwEntry]) {
        let mut delete: Vec<PortFwEntry> = vec![];
        for entry in self.values() {
            if !Self::rule_can_be_deleted(entry, ruleset) {
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
    use std::num::NonZero;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing_test::traced_test;

    // build a sample port forwarding table
    fn build_sample_port_forwarding_table() -> Arc<PortFwTable> {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
            dst_port: NonZero::new(3022).unwrap(),
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
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
            dst_port: NonZero::new(4022).unwrap(),
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(4000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
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
            dst_port: NonZero::new(3080).unwrap(),
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            80,
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
            dst_port: NonZero::new(3053).unwrap(),
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.2").unwrap(),
            53,
            None,
            None,
        )
        .unwrap();
        fwtable.add_entry(Arc::from(entry)).unwrap();

        Arc::new(fwtable)
    }

    #[test]
    fn test_port_forwarding_table_reject_dup_key() {
        let mut fwtable = PortFwTable::new();
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
            dst_port: NonZero::new(3022).unwrap(),
        };
        let entry1 = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
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

        let entry2 = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(4000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.2").unwrap(),
            23,
            None,
            None,
        )
        .unwrap()
        .arced();

        let r = fwtable.add_entry(entry2);
        assert!(r.is_err_and(|e| e == PortFwTableError::DuplicateKey(key)));
    }

    #[test]
    fn test_port_forwarding_entry_reject_distinct_ip_ver() {
        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
            dst_port: NonZero::new(3022).unwrap(),
        };
        let r = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("2002:a:b:c::1").unwrap(),
            22,
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
            dst_port: NonZero::new(3022).unwrap(),
        };
        let r = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            IpAddr::from_str("70.71.72.73").unwrap(),
            22,
            None,
            None,
        );
        assert!(r.is_err_and(|e| matches!(e, PortFwTableError::Unsupported(_))));
    }

    #[test]
    #[traced_test]
    fn test_port_forwarding_table_removals() {
        let fwtable = build_sample_port_forwarding_table(); //
        let mut fwtable = Arc::<PortFwTable>::into_inner(fwtable).unwrap();

        let key = PortFwKey {
            src_vpcd: VpcDiscriminant::VNI(2000.try_into().unwrap()),
            dst_ip: UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            proto: NextHeader::TCP,
            dst_port: NonZero::new(3022).unwrap(),
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
            None,
            None,
        )
        .unwrap();

        // check that entry exists
        assert!(fwtable.contains_rule(&entry));

        // lookup
        let found = fwtable.lookup_rule(&key).unwrap();
        assert_eq!(found.as_ref(), &entry);

        // lookup + weak ref
        let weak = fwtable.lookup_rule_ref(&key).unwrap();
        assert_eq!(weak.upgrade().unwrap().as_ref(), &entry);

        // remove
        fwtable.remove_entry_by_key(&key);
        assert!(!fwtable.contains_rule(&entry));
        assert!(fwtable.lookup_rule(&key).is_none());
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
            dst_port: NonZero::new(3022).unwrap(),
        };
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
            None,
            None,
        )
        .unwrap()
        .arced();

        // add rule and check it exists in table
        fwtable.add_entry(entry.clone()).unwrap();
        assert!(fwtable.contains_rule(&entry));

        // get a weak reference to the rule
        let weak = fwtable.lookup_rule_ref(&key).unwrap();
        assert_eq!(weak.upgrade().unwrap().as_ref(), entry.as_ref());

        // add same rule but with modified timeouts
        let entry = PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            22,
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
