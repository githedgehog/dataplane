// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Adjacency table left-right

use crate::atable::adjacency::{Adjacency, AdjacencyTable};
use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use net::interface::InterfaceIndex;
use std::net::IpAddr;

enum AtableChange {
    Add(Adjacency),
    Del((IpAddr, InterfaceIndex)),
    Clear,
}

impl Absorb<AtableChange> for AdjacencyTable {
    fn absorb_first(&mut self, change: &mut AtableChange, _: &Self) {
        match change {
            AtableChange::Add(adjacency) => self.add_adjacency(adjacency.clone()),
            AtableChange::Del((address, ifindex)) => self.del_adjacency(*address, *ifindex),
            AtableChange::Clear => self.clear(),
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct AtableWriter(WriteHandle<AdjacencyTable, AtableChange>);
impl AtableWriter {
    #[must_use]
    pub fn new() -> (AtableWriter, AtableReader) {
        let (w, r) =
            left_right::new_from_empty::<AdjacencyTable, AtableChange>(AdjacencyTable::new());
        (AtableWriter(w), AtableReader(r))
    }
    pub fn add_adjacency(&mut self, adjacency: Adjacency, publish: bool) {
        self.0.append(AtableChange::Add(adjacency));
        if publish {
            self.0.publish();
        }
    }
    #[allow(unused)]
    pub fn del_adjacency(&mut self, address: IpAddr, ifindex: InterfaceIndex, publish: bool) {
        self.0.append(AtableChange::Del((address, ifindex)));
        if publish {
            self.0.publish();
        }
    }
    pub fn clear(&mut self, publish: bool) {
        self.0.append(AtableChange::Clear);
        if publish {
            self.0.publish();
        }
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
}

#[derive(Clone, Debug)]
pub struct AtableReader(ReadHandle<AdjacencyTable>);
impl AtableReader {
    pub fn new(rhandle: ReadHandle<AdjacencyTable>) -> Self {
        AtableReader(rhandle)
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, AdjacencyTable>> {
        self.0.enter()
    }
    pub fn factory(&self) -> AtableReaderFactory {
        AtableReaderFactory(self.0.factory())
    }
}

#[derive(Debug)]
pub struct AtableReaderFactory(ReadHandleFactory<AdjacencyTable>);
impl AtableReaderFactory {
    #[must_use]
    pub fn handle(&self) -> AtableReader {
        AtableReader(self.0.handle())
    }
}

#[cfg(test)]
mod atable_properties {
    use super::*;
    use bolero::{Driver, ValueGenerator};
    use net::eth::mac::Mac;
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_IFACES: u8 = 2;
    const NUM_ADDRESSES: u8 = 3;
    const NUM_MACS: u8 = 2;
    const MAX_CHANGES: u8 = 12;

    fn ifindexes() -> Vec<InterfaceIndex> {
        (1..=u32::from(NUM_IFACES))
            .map(|i| InterfaceIndex::try_new(i).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn addresses() -> Vec<IpAddr> {
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            .iter()
            .map(|a| IpAddr::from_str(a).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn macs() -> Vec<Mac> {
        vec![
            Mac::from([0x00, 0xaa, 0x00, 0x00, 0x00, 0x01]),
            Mac::from([0x00, 0xbb, 0x00, 0x00, 0x00, 0x02]),
        ]
    }

    #[derive(Debug, Clone)]
    enum Change {
        Add {
            iface: usize,
            address: usize,
            mac: usize,
            publish: bool,
        },
        Del {
            iface: usize,
            address: usize,
            publish: bool,
        },
        Clear {
            publish: bool,
        },
        Publish,
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct ChangeSequences;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    impl ValueGenerator for ChangeSequences {
        type Output = Vec<Change>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<Change>> {
            let len = driver.gen_u8(Included(&0), Included(&MAX_CHANGES))?;
            let mut out = Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                let change = match driver.gen_u8(Included(&0), Included(&3))? {
                    0 => Change::Add {
                        iface: index(driver, NUM_IFACES)?,
                        address: index(driver, NUM_ADDRESSES)?,
                        mac: index(driver, NUM_MACS)?,
                        publish: driver.produce::<bool>()?,
                    },
                    1 => Change::Del {
                        iface: index(driver, NUM_IFACES)?,
                        address: index(driver, NUM_ADDRESSES)?,
                        publish: driver.produce::<bool>()?,
                    },
                    2 => Change::Clear {
                        publish: driver.produce::<bool>()?,
                    },
                    _ => Change::Publish,
                };
                out.push(change);
            }
            Some(out)
        }
    }

    type Entries = BTreeMap<(usize, usize), usize>;

    #[derive(Debug, Clone, Default)]
    struct Model {
        appended: Entries,
        published: Entries,
    }

    impl Model {
        fn publish(&mut self) {
            self.published = self.appended.clone();
        }

        fn apply(&mut self, change: &Change) {
            match change {
                Change::Add {
                    iface,
                    address,
                    mac,
                    publish,
                } => {
                    self.appended.insert((*iface, *address), *mac);
                    if *publish {
                        self.publish();
                    }
                }
                Change::Del {
                    iface,
                    address,
                    publish,
                } => {
                    self.appended.remove(&(*iface, *address));
                    if *publish {
                        self.publish();
                    }
                }
                Change::Clear { publish } => {
                    self.appended.clear();
                    if *publish {
                        self.publish();
                    }
                }
                Change::Publish => self.publish(),
            }
        }
    }

    fn apply_to_table(writer: &mut AtableWriter, change: &Change) {
        let ifaces = ifindexes();
        let addrs = addresses();
        match change {
            Change::Add {
                iface,
                address,
                mac,
                publish,
            } => writer.add_adjacency(
                Adjacency::new(addrs[*address], ifaces[*iface], macs()[*mac]),
                *publish,
            ),
            Change::Del {
                iface,
                address,
                publish,
            } => writer.del_adjacency(addrs[*address], ifaces[*iface], *publish),
            Change::Clear { publish } => writer.clear(*publish),
            Change::Publish => writer.publish(),
        }
    }

    fn seen(table: &AdjacencyTable) -> Entries {
        let ifaces = ifindexes();
        let addrs = addresses();
        let all = macs();
        let mut out = Entries::new();
        for (iface, ifindex) in ifaces.iter().enumerate() {
            for (address, addr) in addrs.iter().enumerate() {
                if let Some(adjacency) = table.get_adjacency(*addr, *ifindex) {
                    let mac = all
                        .iter()
                        .position(|m| *m == adjacency.get_mac())
                        .unwrap_or_else(|| unreachable!());
                    assert_eq!(adjacency.get_ifindex(), *ifindex, "adjacency ifindex");
                    assert_eq!(adjacency.get_ip(), *addr, "adjacency address");
                    out.insert((iface, address), mac);
                }
            }
        }
        assert_eq!(
            out.len(),
            table.len(),
            "the table holds entries outside the pools"
        );
        out
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(ifindexes().len(), usize::from(NUM_IFACES));
        assert_eq!(addresses().len(), usize::from(NUM_ADDRESSES));
        assert_eq!(macs().len(), usize::from(NUM_MACS));
        assert_ne!(macs()[0], macs()[1]);
    }

    #[test]
    fn a_reader_sees_the_table_as_of_the_last_publish() {
        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let (mut writer, reader) = AtableWriter::new();
                let mut model = Model::default();

                for (step, change) in changes.iter().enumerate() {
                    apply_to_table(&mut writer, change);
                    model.apply(change);
                    let at = format!("at step {step} of {changes:?}");

                    let view = reader.enter().unwrap_or_else(|| unreachable!());
                    assert_eq!(seen(&view), model.published, "reader {at}");
                }

                writer.publish();
                model.publish();
                let view = reader.enter().unwrap_or_else(|| unreachable!());
                assert_eq!(seen(&view), model.appended, "reader after a final publish");
            });
    }

    #[test]
    fn a_clear_and_repopulate_is_invisible_until_published() {
        let (mut writer, reader) = AtableWriter::new();
        let ifindex = ifindexes()[0];
        let (old, new) = (addresses()[0], addresses()[1]);

        writer.add_adjacency(Adjacency::new(old, ifindex, macs()[0]), true);
        assert!(
            reader
                .enter()
                .unwrap_or_else(|| unreachable!())
                .get_adjacency(old, ifindex)
                .is_some()
        );

        writer.clear(false);
        writer.add_adjacency(Adjacency::new(new, ifindex, macs()[1]), false);

        let view = reader.enter().unwrap_or_else(|| unreachable!());
        assert!(
            view.get_adjacency(old, ifindex).is_some(),
            "the table emptied under a reader mid-refresh"
        );
        assert!(
            view.get_adjacency(new, ifindex).is_none(),
            "an unpublished addition was visible"
        );
        drop(view);

        writer.publish();
        let view = reader.enter().unwrap_or_else(|| unreachable!());
        assert!(
            view.get_adjacency(old, ifindex).is_none(),
            "the clear was lost"
        );
        assert!(
            view.get_adjacency(new, ifindex).is_some(),
            "the addition was lost"
        );
    }
}
