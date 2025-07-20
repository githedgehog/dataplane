// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle, new_from_empty};
use std::collections::HashMap;
use tracing::{debug, error, warn};

use lpm::trie::IpPrefixTrie;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryIp};
use net::packet::{DoneReason, Packet};
use net::vxlan::Vni;
use pipeline::NetworkFunction;

pub mod setup;

#[derive(thiserror::Error, Debug, Clone)]
pub enum DstVniLookupError {
    #[error("Error building dst_vni_lookup table: {0}")]
    BuildError(String),
}

#[derive(Debug, Clone)]
pub struct VniTables {
    tables_by_vni: HashMap<Vni, VniTable>,
}

impl VniTables {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tables_by_vni: HashMap::new(),
        }
    }
}

impl Default for VniTables {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum VniTablesChange {
    UpdateVniTables(VniTables),
}

impl Absorb<VniTablesChange> for VniTables {
    fn absorb_first(&mut self, change: &mut VniTablesChange, _: &Self) {
        match change {
            VniTablesChange::UpdateVniTables(vni_tables) => {
                *self = vni_tables.clone();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

#[derive(Debug)]
pub struct VniTablesReader(ReadHandle<VniTables>);
impl VniTablesReader {
    fn enter(&self) -> Option<ReadGuard<'_, VniTables>> {
        self.0.enter()
    }
}

#[derive(Debug)]
pub struct VniTablesWriter(WriteHandle<VniTables, VniTablesChange>);
impl VniTablesWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> VniTablesWriter {
        let (w, _r) = new_from_empty::<VniTables, VniTablesChange>(VniTables::new());
        VniTablesWriter(w)
    }
    #[must_use]
    pub fn get_reader(&self) -> VniTablesReader {
        VniTablesReader(self.0.clone())
    }
    pub fn update_vni_tables(&mut self, vni_tables: VniTables) {
        self.0.append(VniTablesChange::UpdateVniTables(vni_tables));
        self.0.publish();
        debug!("Updated tables for Destination VNI Lookup");
    }
}

#[derive(Debug, Clone)]
struct VniTable {
    dst_vnis: IpPrefixTrie<Vni>,
}

impl VniTable {
    fn new() -> Self {
        Self {
            dst_vnis: IpPrefixTrie::new(),
        }
    }
}

impl Default for VniTable {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DstVniLookup {
    name: String,
    tablesr: VniTablesReader,
}

impl DstVniLookup {
    pub fn new(name: &str, tablesr: VniTablesReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
        }
    }

    fn process_packet<Buf: PacketBufferMut>(
        &self,
        tablesr: &ReadGuard<'_, VniTables>,
        packet: &mut Packet<Buf>,
    ) {
        if packet.meta.dst_vni.is_some() {
            debug!("{}: Packet already has dst_vni, skipping", self.name);
            return;
        }
        let Some(net) = packet.headers().try_ip() else {
            warn!("{}: No Ip headers, so no dst_vni to lookup", self.name);
            return;
        };
        if let Some(src_vni) = packet.meta.src_vni {
            let vni_table = tablesr.tables_by_vni.get(&src_vni);
            if let Some(vni_table) = vni_table {
                let dst_vni = vni_table.dst_vnis.lookup(net.dst_addr());
                if let Some((prefix, dst_vni)) = dst_vni {
                    debug!(
                        "{}: Tagging packet with dst_vni {dst_vni} using {prefix} using table for src_vni {src_vni}",
                        self.name
                    );
                    packet.meta.dst_vni = Some(*dst_vni);
                } else {
                    debug!(
                        "{}: no dst_vni found for {} in src_vni {src_vni}, marking packet as unroutable",
                        self.name,
                        net.dst_addr()
                    );
                    packet.done(DoneReason::Unroutable);
                }
            } else {
                debug!(
                    "{}: no vni table found for src_vni {src_vni} (dst_addr={})",
                    self.name,
                    net.dst_addr()
                );
                packet.done(DoneReason::Unroutable);
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DstVniLookup {
    #[allow(clippy::if_not_else)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if let Some(tablesr) = &self.tablesr.enter() {
                if !packet.is_done() {
                    // FIXME: ideally, we'd `enter` once for the whole batch. However,
                    // this requires boxing the closures, which may be worse than
                    // calling `enter` per packet? ... if not uglier

                    self.process_packet(tablesr, &mut packet);
                }
            } else {
                error!("{}: failed to read vni tables", self.name);
                packet.done(DoneReason::InternalFailure);
            }
            packet.enforce()
        })
    }
}
