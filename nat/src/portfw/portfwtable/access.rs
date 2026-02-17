// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding table objects for concurrent accesses
//! from datapath and configuration / management

use super::PortFwTableError;
use super::objects::{PortFwEntry, PortFwTable};
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};

#[allow(unused)]
use tracing::{debug, error, warn};

enum PortFwTableChange {
    Update(Vec<PortFwEntry>),
}

impl Absorb<PortFwTableChange> for PortFwTable {
    fn absorb_first(&mut self, operation: &mut PortFwTableChange, _other: &Self) {
        match operation {
            PortFwTableChange::Update(ruleset) => self.update(&ruleset.clone()),
        }
    }
    fn sync_with(&mut self, _first: &Self) {}
}

pub struct PortFwTableWriter(WriteHandle<PortFwTable, PortFwTableChange>);
pub struct PortFwTableReader(ReadHandle<PortFwTable>);

#[allow(clippy::unnecessary_wraps)]
fn validate_ruleset(_ruleset: &[PortFwEntry]) -> Result<(), PortFwTableError> {
    debug!("Validating port-forwarding ruleset...");
    // deferring the implementation of this since it will change
    // when we introduce port ranges
    Ok(())
}

impl PortFwTableWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> PortFwTableWriter {
        let (mut write, _) = left_right::new::<PortFwTable, PortFwTableChange>();
        write.publish();
        PortFwTableWriter(write)
    }
    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, PortFwTable>> {
        self.0.enter()
    }
    #[must_use]
    pub fn reader(&self) -> PortFwTableReader {
        PortFwTableReader(self.0.clone())
    }
    pub fn update_table(&mut self, ruleset: &[PortFwEntry]) -> Result<(), PortFwTableError> {
        validate_ruleset(ruleset)?;
        self.0.append(PortFwTableChange::Update(ruleset.to_vec()));
        self.0.publish();
        self.0.publish(); // intended
        Ok(())
    }
}

#[derive(Debug)]
pub struct PortFwTableReaderFactory(ReadHandleFactory<PortFwTable>);
impl PortFwTableReaderFactory {
    #[must_use]
    pub fn handle(&self) -> PortFwTableReader {
        PortFwTableReader(self.0.handle())
    }
}

impl PortFwTableReader {
    #[must_use]
    pub fn enter(&self) -> Option<ReadGuard<'_, PortFwTable>> {
        self.0.enter()
    }
    #[must_use]
    pub fn factory(&self) -> PortFwTableReaderFactory {
        PortFwTableReaderFactory(self.0.factory())
    }
}

#[cfg(test)]
mod test {
    use crate::portfw::portfwtable::access::PortFwTableWriter;
    use crate::portfw::{PortFwEntry, PortFwKey};
    use net::ip::NextHeader;
    use net::ip::UnicastIpAddr;
    use net::packet::VpcDiscriminant;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use tracing_test::traced_test;

    fn build_sample_port_forwarding_rule(dst_port: u16) -> PortFwEntry {
        let key = PortFwKey::new(
            VpcDiscriminant::VNI(2000.try_into().unwrap()),
            UnicastIpAddr::from_str("70.71.72.73").unwrap(),
            NextHeader::TCP,
        );
        PortFwEntry::new(
            key,
            VpcDiscriminant::VNI(3000.try_into().unwrap()),
            IpAddr::from_str("192.168.1.1").unwrap(),
            (dst_port, dst_port),
            (22, 22),
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    #[traced_test]
    fn test_port_forwarding_access_remove_rules_drops_refs() {
        let mut pfw_table_w = PortFwTableWriter::new();
        let reader = pfw_table_w.reader();
        let rule = build_sample_port_forwarding_rule(22);
        let weak;

        // add a ruleset with one rule
        pfw_table_w
            .update_table(std::slice::from_ref(&rule))
            .unwrap();
        if let Some(pfwtable) = reader.enter() {
            println!("{}", pfwtable.as_ref());
            assert!(pfwtable.contains_rule(&rule));
            weak = pfwtable.lookup_rule_ref(&rule).unwrap();
            assert!(weak.upgrade().is_some());
        } else {
            unreachable!()
        }
        // remove ruleset
        pfw_table_w.update_table(&[]).unwrap();
        if let Some(pfwtable) = reader.enter() {
            println!("{}", pfwtable.as_ref());
            assert!(!pfwtable.contains_rule(&rule));
        }
        // check that ref has been invalidated
        assert!(weak.upgrade().is_none());
    }

    #[test]
    #[traced_test]
    fn test_port_forwarding_access_modify_rules_keeps_refs() {
        let mut pfw_table_w = PortFwTableWriter::new();
        let reader = pfw_table_w.reader();
        let rule = build_sample_port_forwarding_rule(22);

        let weak;

        // add a ruleset with one rule
        pfw_table_w
            .update_table(std::slice::from_ref(&rule))
            .unwrap();
        if let Some(pfwtable) = reader.enter() {
            assert!(pfwtable.contains_rule(&rule));
            weak = pfwtable.lookup_rule_ref(&rule).unwrap();
            assert!(weak.upgrade().is_some());
        } else {
            unreachable!()
        }

        // update the original rule and add it again but with distinct timeouts
        rule.set_init_timeout(Duration::from_secs(10));
        rule.set_estab_timeout(Duration::from_secs(123));

        // check that rule has been changed
        pfw_table_w
            .update_table(std::slice::from_ref(&rule))
            .unwrap();
        if let Some(pfwtable) = reader.enter() {
            assert!(pfwtable.contains_rule(&rule));
            let stored = pfwtable.lookup_rule(&rule).unwrap().as_ref();
            assert_eq!(stored.init_timeout(), rule.init_timeout());
            assert_eq!(stored.estab_timeout(), rule.estab_timeout());
        }
        // reference has not been dropped
        assert!(weak.upgrade().is_some());
    }

    #[test]
    #[traced_test]
    fn test_port_forwarding_access_replace_ruleset() {
        let mut pfwt_w = PortFwTableWriter::new();
        let reader = pfwt_w.reader();

        // build a sample ruleset with 3 rules. The rules map a single port to port 22
        // all of them have the same key and will be stored within the same group.
        let r1 = build_sample_port_forwarding_rule(1);
        let r2 = build_sample_port_forwarding_rule(2);
        let r3 = build_sample_port_forwarding_rule(3);

        let w1;
        let w2;
        let w3;

        // update the table with it
        let ruleset = [r1.clone(), r2.clone(), r3.clone()];
        pfwt_w.update_table(&ruleset).unwrap();
        if let Some(pfwtable) = reader.enter() {
            println!("{}", pfwtable.as_ref());
            assert!(pfwtable.contains_rule(&r1));
            assert!(pfwtable.contains_rule(&r2));
            assert!(pfwtable.contains_rule(&r3));
            w1 = pfwtable.lookup_rule_ref(&r1).unwrap();
            w2 = pfwtable.lookup_rule_ref(&r2).unwrap();
            w3 = pfwtable.lookup_rule_ref(&r3).unwrap();
        } else {
            unreachable!()
        }
        drop(reader);

        // create a fourth rule
        let r4 = build_sample_port_forwarding_rule(4); // FIXME: test key collisions

        // modify rule r2
        let r2mod = r2.clone();
        r2mod.set_init_timeout(Duration::from_mins(10));
        r2mod.set_estab_timeout(Duration::from_hours(2));

        // update the table with [r2mod, r3, r4]
        pfwt_w
            .update_table(&[r2mod.clone(), r3.clone(), r4.clone()])
            .unwrap();

        let reader = pfwt_w.reader();
        if let Some(pfwtable) = reader.enter() {
            println!("{}", pfwtable.as_ref());
            assert!(!pfwtable.contains_rule(&r1), "Should be gone");
            assert!(pfwtable.contains_rule(&r2mod), "Should remain");
            assert!(pfwtable.contains_rule(&r3), "Should remain");
            assert!(pfwtable.contains_rule(&r4), "Should remain");

            assert!(w1.upgrade().is_none());
            assert!(w2.upgrade().is_some());
            assert!(w3.upgrade().is_some());
        }
    }
}
