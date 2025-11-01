// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Portid-to-interface mappings. This module implements a table to map port identifiers
//! and interface identifiers. Port identifiers are represented by [`PortIndex`] type,
//! while interface identifiers by type [`InterfaceIndex`].

#![allow(unused)]
#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use ahash::RandomState;
use left_right::ReadHandleFactory;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::interface::{InterfaceIndex, InterfaceName};
use net::packet::PortIndex;
use net::vlan::Vid;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

/// Type to describe a port. This definition is temporary
pub type NetworkDeviceDescription = String;

/// A key to look up port mappings [`PortMap`] in a [`PortMapTable`].
/// This type is internal to this module and needs not be exposed.
#[derive(Copy, Clone, Eq, Hash, PartialEq, Debug)]
enum PortMapKey {
    Port(PortIndex),
    Iface(InterfaceIndex),
}
impl PortMapKey {
    const fn from_port(pindex: PortIndex) -> Self {
        PortMapKey::Port(pindex)
    }
    const fn from_iface(ifindex: InterfaceIndex) -> Self {
        PortMapKey::Iface(ifindex)
    }
}

/// A (port+vlan)-to-interface mapping entry.
#[derive(Clone, Debug, PartialEq)]
pub struct PortMap {
    pdesc: NetworkDeviceDescription,
    pindex: PortIndex,
    ifname: InterfaceName,
    ifindex: InterfaceIndex,
}
impl PortMap {
    const fn new(
        pdesc: NetworkDeviceDescription,
        pindex: PortIndex,
        ifname: InterfaceName,
        ifindex: InterfaceIndex,
    ) -> Self {
        Self {
            pdesc,
            pindex,
            ifname,
            ifindex,
        }
    }
    const fn build_keys(&self) -> (PortMapKey, PortMapKey) {
        let one = PortMapKey::from_port(self.pindex);
        let two = PortMapKey::from_iface(self.ifindex);
        (one, two)
    }
}

/// Table to look up [`PortMap`]'s. Every [`PortMap`] is doubly indexed by two keys
/// so that it can be queried from interface or port & vlan.
/// This table is wrapped in left-right and needs not be exposed.
#[derive(Clone, Debug)]
struct PortMapTable(HashMap<PortMapKey, Arc<PortMap>, RandomState>);
impl PortMapTable {
    #[must_use]
    fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
    fn add_replace(&mut self, pmap: PortMap) {
        let pmap = Arc::new(pmap);
        let (pkey, ifkey) = pmap.build_keys();

        self.del(pkey);
        self.del(ifkey);
        self.0.insert(pkey, pmap.clone());
        self.0.insert(ifkey, pmap.clone());

        debug_assert!(self.0.len().is_multiple_of(2));
        debug_assert!(self.get(pkey) == Some(&pmap));
        debug_assert!(self.get(ifkey) == Some(&pmap));
    }
    fn del_by_port(&mut self, portid: PortIndex) {
        if let Some(pmap) = self.0.remove(&PortMapKey::from_port(portid)) {
            self.0.remove(&PortMapKey::from_iface(pmap.ifindex));
        }
        debug_assert!(self.0.len().is_multiple_of(2));
    }
    fn del_by_interface(&mut self, ifindex: InterfaceIndex) {
        if let Some(pmap) = self.0.remove(&PortMapKey::from_iface(ifindex)) {
            self.0.remove(&PortMapKey::from_port(pmap.pindex));
        }
        debug_assert!(self.0.len().is_multiple_of(2));
    }
    fn del(&mut self, key: PortMapKey) {
        match key {
            PortMapKey::Port(pindex) => self.del_by_port(pindex),
            PortMapKey::Iface(ifid) => self.del_by_interface(ifid),
        }
        debug_assert!(self.0.len().is_multiple_of(2));
    }

    #[inline]
    fn get(&self, key: PortMapKey) -> Option<&PortMap> {
        self.0.get(&key).map(std::convert::AsRef::as_ref)
    }
    #[inline]
    pub(crate) fn get_by_port(&self, pindex: PortIndex) -> Option<&PortMap> {
        self.get(PortMapKey::from_port(pindex))
    }
    #[inline]
    pub(crate) fn get_by_iface(&self, ifindex: InterfaceIndex) -> Option<&PortMap> {
        self.get(PortMapKey::from_iface(ifindex))
    }
}

enum PortMapChange {
    AddReplace(PortMap),
    Del(PortMapKey),
}
impl Absorb<PortMapChange> for PortMapTable {
    fn absorb_first(&mut self, change: &mut PortMapChange, _: &Self) {
        match change {
            PortMapChange::AddReplace(pmap) => self.add_replace(pmap.clone()),
            PortMapChange::Del(pmapkey) => self.del(*pmapkey),
        }
    }
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct PortMapWriter(WriteHandle<PortMapTable, PortMapChange>);
impl PortMapWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (writer, _) =
            left_right::new_from_empty::<PortMapTable, PortMapChange>(PortMapTable::new());
        PortMapWriter(writer)
    }
    pub fn add_replace(
        &mut self,
        pdesc: NetworkDeviceDescription,
        ifname: InterfaceName,
        pindex: PortIndex,
        ifindex: InterfaceIndex,
    ) {
        let pmap = PortMap::new(pdesc, pindex, ifname, ifindex);
        self.0.append(PortMapChange::AddReplace(pmap));
        self.0.publish();
    }
    pub fn del_by_interface(&mut self, ifindex: InterfaceIndex) {
        let pmapkey = PortMapKey::from_iface(ifindex);
        self.0.append(PortMapChange::Del(pmapkey));
        self.0.publish();
    }
    pub fn del_by_port(&mut self, pindex: PortIndex) {
        let pmapkey = PortMapKey::from_port(pindex);
        self.0.append(PortMapChange::Del(pmapkey));
        self.0.publish();
    }
    pub fn factory(&self) -> PortMapReaderFactory {
        PortMapReaderFactory(self.0.clone().factory())
    }
    pub fn log_pmap_table(&self) {
        let table = &*self.0.enter().unwrap_or_else(|| unreachable!());
        info!("{table}",);
    }
}

pub struct PortMapReader(ReadHandle<PortMapTable>);
impl PortMapReader {
    #[cfg(test)]
    fn get_by_port(&self, pindex: PortIndex) -> Option<ReadGuard<'_, PortMap>> {
        if let Some(g) = self.0.enter() {
            g.get_by_port(pindex)?; // FIXME
            Some(ReadGuard::map(g, |table| {
                table.get_by_port(pindex).unwrap()
            }))
        } else {
            None
        }
    }
    #[cfg(test)]
    fn get_by_iface(&self, ifindex: InterfaceIndex) -> Option<ReadGuard<'_, PortMap>> {
        if let Some(g) = self.0.enter() {
            g.get_by_iface(ifindex)?; // FIXME
            Some(ReadGuard::map(g, |table| {
                table.get_by_iface(ifindex).unwrap()
            }))
        } else {
            None
        }
    }

    pub fn lookup_iface_by_port(&self, pindex: PortIndex) -> Option<InterfaceIndex> {
        self.0.enter()?.get_by_port(pindex).map(|pmap| pmap.ifindex)
    }
    pub fn lookup_port_by_iface(&self, ifindex: InterfaceIndex) -> Option<PortIndex> {
        self.0
            .enter()?
            .get_by_iface(ifindex)
            .map(|pmap| pmap.pindex)
    }
}

pub struct PortMapReaderFactory(ReadHandleFactory<PortMapTable>);
impl PortMapReaderFactory {
    #[must_use]
    pub fn handle(&self) -> PortMapReader {
        PortMapReader(self.0.handle())
    }
}

use std::fmt::Display;

macro_rules! PORTMAP_FMT {
    () => {
        "   {:<8} {:<20} {:<8} {:<16} {:<8}"
    };
}
fn fmt_portmap_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            PORTMAP_FMT!(),
            "key", "Device", "portid", "interface", "ifindex"
        )
    )
}

impl Display for PortMapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortMapKey::Iface(ifindex) => write!(f, "{ifindex}"),
            PortMapKey::Port(pindex) => write!(f, "{pindex}"),
        }
    }
}

fn fmt_pmap_with_key(
    f: &mut std::fmt::Formatter<'_>,
    pmap: &PortMap,
    key: PortMapKey,
) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            PORTMAP_FMT!(),
            key.to_string(),
            pmap.pdesc.to_string(),
            pmap.pindex.to_string(),
            pmap.ifname.to_string(),
            pmap.ifindex
        )
    )
}

impl Display for PortMapTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━ PortMap table ━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )?;
        fmt_portmap_heading(f)?;
        for (key, pmap) in &self.0 {
            fmt_pmap_with_key(f, pmap, *key)?;
        }
        writeln!(
            f,
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::portmap::{NetworkDeviceDescription, PortMap, PortMapTable, PortMapWriter};
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::packet::PortIndex;
    use tracing_test::traced_test;

    fn build_portmap(pdesc: &str, ifname: &str, pindex: u16, ifindex: u32) -> PortMap {
        let pdesc = pdesc.to_string();
        let ifname = InterfaceName::try_from(ifname).unwrap();
        let pindex = PortIndex::new(pindex);
        let ifindex = InterfaceIndex::try_new(ifindex).unwrap();
        PortMap::new(pdesc, pindex, ifname, ifindex)
    }

    #[test]
    fn test_portmap_table_internal() {
        let mut pmap_t = PortMapTable::new();

        {
            println!("test: insertion");
            let pmap = build_portmap("0000:03:02.1", "eth1", 1, 800);
            pmap_t.add_replace(pmap.clone());

            let lookup1 = pmap_t.get_by_iface(pmap.ifindex).unwrap();
            let lookup2 = pmap_t.get_by_port(pmap.pindex).unwrap();
            assert_eq!(lookup1, &pmap);
            assert_eq!(lookup2, &pmap);
            assert_eq!(pmap_t.0.len(), 2);
        }

        {
            println!("test: idempotence");
            let pmap = build_portmap("0000:03:02.1", "eth1", 1, 800);
            pmap_t.add_replace(pmap.clone());

            let lookup1 = pmap_t.get_by_iface(pmap.ifindex).unwrap();
            let lookup2 = pmap_t.get_by_port(pmap.pindex).unwrap();
            assert_eq!(lookup1, &pmap);
            assert_eq!(lookup2, &pmap);
            assert_eq!(pmap_t.0.len(), 2);
        }

        {
            println!("test: update non key fields");
            let pmap = build_portmap("0000:03:02.7", "ethFoo", 1, 800);
            pmap_t.add_replace(pmap.clone());

            let lookup1 = pmap_t.get_by_iface(pmap.ifindex).unwrap();
            let lookup2 = pmap_t.get_by_port(pmap.pindex).unwrap();
            assert_eq!(lookup1, &pmap);
            assert_eq!(lookup2, &pmap);
            assert_eq!(pmap_t.0.len(), 2);
        }

        {
            println!("test: replacement: change port index");
            let pmap = build_portmap("0000:03:02.1", "eth1", 2, 800);
            pmap_t.add_replace(pmap.clone());

            let lookup1 = pmap_t.get_by_iface(pmap.ifindex).unwrap();
            let lookup2 = pmap_t.get_by_port(pmap.pindex).unwrap();
            assert_eq!(lookup1, &pmap);
            assert_eq!(lookup2, &pmap);
            assert_eq!(pmap_t.0.len(), 2);
        }

        {
            println!("test: replacement: change ifindex");
            let pmap = build_portmap("0000:03:02.1", "eth1", 2, 900);
            pmap_t.add_replace(pmap.clone());

            let lookup1 = pmap_t.get_by_iface(pmap.ifindex).unwrap();
            let lookup2 = pmap_t.get_by_port(pmap.pindex).unwrap();
            assert_eq!(lookup1, &pmap);
            assert_eq!(lookup2, &pmap);
            assert_eq!(pmap_t.0.len(), 2);
        }

        {
            println!("test: deletion by portid");
            let pindex = PortIndex::new(2);
            let ifindex = InterfaceIndex::try_new(900).unwrap();
            pmap_t.del_by_port(pindex);

            assert!(pmap_t.get_by_iface(ifindex).is_none());
            assert!(pmap_t.get_by_port(pindex).is_none());
            assert!(pmap_t.0.is_empty());
        }

        {
            println!("test: restore and deletion by ifindex");
            let pmap = build_portmap("0000:03:02.1", "eth1", 2, 900);
            pmap_t.add_replace(pmap.clone());
            assert_eq!(pmap_t.0.len(), 2);

            pmap_t.del_by_interface(pmap.ifindex);
            assert!(pmap_t.get_by_iface(pmap.ifindex).is_none());
            assert!(pmap_t.get_by_port(pmap.pindex).is_none());
            assert!(pmap_t.0.is_empty());
        }
    }

    #[traced_test]
    #[test]
    fn test_portmap_table() {
        let mut writer = PortMapWriter::new();
        let reader = writer.factory().handle();

        // insert some port map
        let pmap = build_portmap("0000:03:02.1", "eth1", 1, 101);
        writer.add_replace(
            pmap.pdesc.clone(),
            pmap.ifname.clone(),
            pmap.pindex,
            pmap.ifindex,
        );
        writer.log_pmap_table();

        // check reader sees it
        let found = reader.get_by_iface(pmap.ifindex).unwrap();
        assert_eq!(&pmap, found.as_ref());
        drop(found);

        // lookups
        assert_eq!(
            reader.lookup_iface_by_port(pmap.pindex).unwrap(),
            pmap.ifindex
        );
        let pindex = reader.lookup_port_by_iface(pmap.ifindex).unwrap();
        assert_eq!(pindex, pmap.pindex);

        // update a port map: same port, distinct interface and vlan
        let pmap = build_portmap("0000:03:02.1", "eth2", 1, 102);
        writer.add_replace(
            pmap.pdesc.clone(),
            pmap.ifname.clone(),
            pmap.pindex,
            pmap.ifindex,
        );
        let found = reader.get_by_iface(pmap.ifindex).unwrap();
        assert_eq!(&pmap, found.as_ref());
        drop(found);

        // lookups
        assert_eq!(
            reader.lookup_iface_by_port(pmap.pindex).unwrap(),
            pmap.ifindex
        );
        let pindex = reader.lookup_port_by_iface(pmap.ifindex).unwrap();
        assert_eq!(pindex, pmap.pindex);

        // Remove port map
        let pmap = build_portmap("0000:03:02.1", "eth2", 1, 102);
        writer.del_by_port(pmap.pindex);
        assert!(reader.get_by_iface(pmap.ifindex).is_none());
        assert!(reader.get_by_port(pmap.pindex).is_none());

        // lookups
        assert!(reader.lookup_iface_by_port(pmap.pindex).is_none());
        assert!(reader.lookup_port_by_iface(pmap.ifindex).is_none());
    }
}
