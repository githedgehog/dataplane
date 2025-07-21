// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements a packet stats sink.
//! Currently, it only includes `PacketDropStats`, but other type of statistics could
//! be added like protocol breakdowns.

#![allow(unused)]

use net::packet::Packet;
use net::packet::PacketDropStats;
use net::packet::PacketMeta;
use pipeline::NetworkFunction;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use net::packet::DoneReason;
use net::vxlan::Vni;
use std::{collections::HashMap, collections::HashSet, hash::Hash};
use vpcmap::VpcDiscriminant;
use vpcmap::map::VpcMapReader;

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use net::buffer::PacketBufferMut;
#[allow(unused)]
use tracing::{error, trace, warn};

// Statistics about traffic exchanged between 2 vpcs - i.e. over a peering, uni-directionally
// TODO(fredi): clarify what information we require
// TODO(fredi): see if it makes sense to code this as a pair map instead
#[derive(Clone)]
pub struct VpcPeeringStats {
    pub src: VpcDiscriminant,
    pub dst: VpcDiscriminant,
    pub src_vpc: String,
    pub dst_vpc: String,
    pub pkts: u64,  /* packets src -> dst */
    pub bytes: u64, /* bytes src -> dst */
    pub pkts_dropped: u64,
    pub bytes_dropped: u64,
}
impl VpcPeeringStats {
    fn new(src: VpcDiscriminant, dst: VpcDiscriminant, src_vpc: &str, dst_vpc: &str) -> Self {
        Self {
            src,
            dst,
            src_vpc: src_vpc.to_owned(),
            dst_vpc: dst_vpc.to_owned(),
            pkts: 0,
            bytes: 0,
            pkts_dropped: 0,
            bytes_dropped: 0,
        }
    }
}

// TODO(fredi): clarify what information we require
#[derive(Clone)]
pub struct VpcStats {
    pub disc: VpcDiscriminant,
    pub vpc: String,
    pub rx_pkts: u64, /* pkts received by VPC -- pkts gateway sent to it */
    pub rx_bytes: u64,
    pub tx_pkts: u64, /* pkts sent by VPC -- pkts gateway received from it */
    pub tx_bytes: u64,
}
impl VpcStats {
    pub fn new(disc: VpcDiscriminant, vpc: &str) -> Self {
        Self {
            disc,
            vpc: vpc.to_string(),
            rx_pkts: 0,
            rx_bytes: 0,
            tx_pkts: 0,
            tx_bytes: 0,
        }
    }
}

#[derive(Clone)]
pub struct VpcMapName {
    disc: VpcDiscriminant,
    name: String,
}
impl VpcMapName {
    pub fn new(disc: VpcDiscriminant, name: &str) -> Self {
        Self {
            disc,
            name: name.to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct PacketStats {
    pub vpcmatrix: HashMap<(VpcDiscriminant, VpcDiscriminant), VpcPeeringStats>,
    //dropstats: PacketDropStats, // TODO
    pub vpcstats: HashMap<VpcDiscriminant, VpcStats>,
    vpcmap_r: VpcMapReader<VpcMapName>,
    known_vpcs: HashSet<VpcDiscriminant>, // Track known VPCs for cleanup
}
impl PacketStats {
    pub fn new(vpcmap_r: VpcMapReader<VpcMapName>) -> Self {
        Self {
            vpcmatrix: HashMap::new(),
            vpcstats: HashMap::new(),
            vpcmap_r,
            known_vpcs: HashSet::new(),
        }
    }

    /// Synchronize stats with the current VPC map and clean up removed VPCs
    pub fn sync_with_vpc_map(&mut self) {
        let Some(mapper) = self.vpcmap_r.enter() else {
            warn!("Unable to read vpc mapper for cleanup!");
            return;
        };
        
        // Get current VPCs from the map
        let mut current_vpcs = HashSet::new();
        
        // Collect VPCs that still exist in the map from our known VPCs
        for &disc in &self.known_vpcs {
            if mapper.get(disc).is_some() {
                current_vpcs.insert(disc);
            }
        }
        
        // Also add any VPCs we find in current stats that still exist in the map
        for &disc in self.vpcstats.keys() {
            if mapper.get(disc).is_some() {
                current_vpcs.insert(disc);
            }
        }
        
        // Find removed VPCs
        let removed_vpcs: Vec<VpcDiscriminant> = self.known_vpcs
            .difference(&current_vpcs)
            .copied()
            .collect();
        
        if !removed_vpcs.is_empty() {
            trace!("Cleaning up stats for {} removed VPCs", removed_vpcs.len());
            
            // Clean up stats for removed VPCs
            for removed_vpc in &removed_vpcs {
                self.vpcstats.remove(removed_vpc);
                trace!("Removed VPC stats for discriminant {:?}", removed_vpc);
            }
            
            // Remove peering stats involving removed VPCs
            let initial_matrix_size = self.vpcmatrix.len();
            self.vpcmatrix.retain(|(src, dst), _| {
                !removed_vpcs.contains(src) && !removed_vpcs.contains(dst)
            });
            let removed_peering_stats = initial_matrix_size - self.vpcmatrix.len();
            
            if removed_peering_stats > 0 {
                trace!("Removed {} peering stats entries", removed_peering_stats);
            }
        }
        
        self.known_vpcs = current_vpcs;
    }

    /// Get statistics about current state (useful for monitoring)
    pub fn get_cleanup_stats(&self) -> (usize, usize, usize) {
        (
            self.known_vpcs.len(),
            self.vpcstats.len(),
            self.vpcmatrix.len(),
        )
    }

    #[inline]
    fn update_matrix_cell(cell: &mut VpcPeeringStats, bytes: u64, dreason: DoneReason) {
        match dreason {
            DoneReason::Delivered => {
                cell.pkts += 1;
                cell.bytes += bytes;
            }
            // At the moment we don't distinguish drop reasons.
            _ => {
                cell.pkts_dropped += 1;
                cell.bytes_dropped += bytes;
            }
        }
    }

    fn update_vpcmatrix(
        &mut self,
        sdisc: VpcDiscriminant,
        ddisc: VpcDiscriminant,
        bytes: u64,
        dreason: DoneReason,
    ) {
        // Track both VPCs as known
        self.known_vpcs.insert(sdisc);
        self.known_vpcs.insert(ddisc);
        
        if let Some(cell) = self.vpcmatrix.get_mut(&(sdisc, ddisc)) {
            // Update existing cell
            Self::update_matrix_cell(cell, bytes, dreason);
        } else {
            // No cell exists yet
            let Some(mapper) = self.vpcmap_r.enter() else {
                warn!("Unable to read vpc mapper!");
                return;
            };
            let Some(smap) = mapper.get(sdisc) else {
                warn!("Unable to find name for discriminant {sdisc}");
                return;
            };
            let Some(dmap) = mapper.get(ddisc) else {
                warn!("Unable to find name for discriminant {ddisc}");
                return;
            };
            // create a new cell
            let mut cell = VpcPeeringStats::new(sdisc, ddisc, &smap.name, &dmap.name);
            Self::update_matrix_cell(&mut cell, bytes, dreason);
            self.vpcmatrix.insert((sdisc, ddisc), cell);
        }
    }
    
    fn update_vpcstats_rx(&mut self, disc: VpcDiscriminant, bytes: u64) {
        // Track VPC as known
        self.known_vpcs.insert(disc);
        
        if let Some(entry) = self.vpcstats.get_mut(&disc) {
            entry.rx_pkts += 1;
            entry.rx_bytes += bytes;
        } else {
            let Some(mapper) = self.vpcmap_r.enter() else {
                warn!("Unable to read vpc mapper!");
                return;
            };
            let Some(map) = mapper.get(disc) else {
                warn!("Unable to find name for discriminant {disc}");
                return;
            };
            let mut entry = VpcStats::new(disc, &map.name);
            entry.rx_pkts += 1;
            entry.rx_bytes += bytes;
            self.vpcstats.insert(disc, entry);
        }
    }
    
    fn update_vpcstats_tx(&mut self, disc: VpcDiscriminant, bytes: u64) {
        // Track VPC as known
        self.known_vpcs.insert(disc);
        
        if let Some(entry) = self.vpcstats.get_mut(&disc) {
            entry.tx_pkts += 1;
            entry.tx_bytes += bytes;
        } else {
            let Some(mapper) = self.vpcmap_r.enter() else {
                warn!("Unable to read vpc mapper!");
                return;
            };
            let Some(map) = mapper.get(disc) else {
                warn!("Unable to find name for discriminant {disc}");
                return;
            };
            let mut entry = VpcStats::new(disc, &map.name);
            entry.tx_pkts += 1;
            entry.tx_bytes += bytes;
            self.vpcstats.insert(disc, entry);
        }
    }
}

#[allow(clippy::enum_variant_names)]
enum PacketStatsChange {
    VpcIngress((VpcDiscriminant, u64)),
    VpcEgress((VpcDiscriminant, u64)),
    PeeringStats((VpcDiscriminant, VpcDiscriminant, u64, DoneReason)),
    SyncWithVpcMap, // New variant for triggering cleanup
}

pub struct PacketStatsWriter(WriteHandle<PacketStats, PacketStatsChange>);
impl Absorb<PacketStatsChange> for PacketStats {
    fn absorb_first(&mut self, change: &mut PacketStatsChange, _: &Self) {
        match change {
            PacketStatsChange::VpcIngress((disc, bytes)) => {
                self.update_vpcstats_tx(*disc, *bytes);
            }
            PacketStatsChange::VpcEgress((disc, bytes)) => {
                self.update_vpcstats_rx(*disc, *bytes);
            }
            PacketStatsChange::PeeringStats((sdisc, ddisc, bytes, dreason)) => {
                self.update_vpcmatrix(*sdisc, *ddisc, *bytes, *dreason);
            }
            PacketStatsChange::SyncWithVpcMap => {
                self.sync_with_vpc_map();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

impl PacketStatsWriter {
    #[must_use]
    pub fn new(vpcmap_r: VpcMapReader<VpcMapName>) -> (PacketStatsWriter, PacketStatsReader) {
        let (w, r) = left_right::new_from_empty::<PacketStats, PacketStatsChange>(
            PacketStats::new(vpcmap_r),
        );
        (PacketStatsWriter(w), PacketStatsReader(r))
    }
    
    pub fn update_vpcmatrix(
        &mut self,
        sdisc: VpcDiscriminant,
        ddisc: VpcDiscriminant,
        bytes: u64,
        dreason: DoneReason,
    ) {
        self.0.append(PacketStatsChange::PeeringStats((
            sdisc, ddisc, bytes, dreason,
        )));
    }
    
    pub fn update_vpcstats_ingress(&mut self, disc: VpcDiscriminant, bytes: u64) {
        self.0.append(PacketStatsChange::VpcIngress((disc, bytes)));
    }
    
    pub fn update_vpcstats_egress(&mut self, disc: VpcDiscriminant, bytes: u64) {
        self.0.append(PacketStatsChange::VpcEgress((disc, bytes)));
    }
    
    /// Trigger cleanup of stale VPC stats by syncing with the VPC map
    pub fn trigger_cleanup(&mut self) {
        self.0.append(PacketStatsChange::SyncWithVpcMap);
    }
    
    pub fn refresh(&mut self) {
        self.0.publish();
    }
}

#[derive(Clone)]
pub struct PacketStatsReader(ReadHandle<PacketStats>);
impl PacketStatsReader {
    pub fn enter(&self) -> Option<ReadGuard<'_, PacketStats>> {
        self.0.enter()
    }
    
    /// Get cleanup statistics (known VPCs, VPC stats entries, peering stats entries)
    pub fn get_cleanup_stats(&self) -> Option<(usize, usize, usize)> {
        self.enter().map(|guard| guard.get_cleanup_stats())
    }
}

#[allow(unsafe_code)]
unsafe impl Send for PacketStatsReader {}
unsafe impl Sync for PacketStatsReader {}

pub struct PipelineStats {
    name: String,
    stats: PacketStatsWriter,
    refresh: AtomicBool, /* not used */
}

/// Stage to collect packet statistics
impl PipelineStats {
    pub fn new(name: &str, vpcmap_r: VpcMapReader<VpcMapName>) -> Self {
        let (statsw, _statsr) = PacketStatsWriter::new(vpcmap_r);
        Self {
            name: name.to_owned(),
            stats: statsw,
            refresh: AtomicBool::new(false),
        }
    }
    
    pub fn get_reader(&self) -> PacketStatsReader {
        PacketStatsReader(self.stats.0.clone())
    }
    
    /// Trigger cleanup of stale VPC stats
    pub fn trigger_cleanup(&mut self) {
        self.stats.trigger_cleanup();
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for PipelineStats {
    #[allow(clippy::let_and_return)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        let nfi = &self.name;
        trace!("Stage '{nfi}'...");
        let it = input.filter_map(|mut packet| {
            let sdisc = packet.get_meta().src_vni.map(VpcDiscriminant::VNI);
            let ddisc = packet.get_meta().dst_vni.map(VpcDiscriminant::VNI);
            let packet_len = u64::from(packet.total_len());

            if let Some(dreason) = packet.get_done() {
                if let Some(sdisc) = sdisc {
                    self.stats.update_vpcstats_ingress(sdisc, packet_len);
                }
                if let Some(ddisc) = ddisc {
                    self.stats.update_vpcstats_egress(ddisc, packet_len);
                }
                if let (Some(sdisc), Some(ddisc)) = (sdisc, ddisc) {
                    self.stats
                        .update_vpcmatrix(sdisc, ddisc, packet_len, dreason);
                }

                // we have to refresh per packet atm :(
                self.stats.refresh();
            } else {
                warn!("Got packet without status!!");
            }
            packet.get_meta_mut().keep = false; /* no longer disable enforce */
            packet.enforce()
        });
        // we can't do this here, meaning we have to refresh by packet. This is bad.
        // we could do it in closure by knowing the last packet in iter, but that
        // requires size_hint(). Also, we can't just fail to publish because the oplog
        // may become too big. A smarter approach is needed. Rwlock has issues so does
        // ArcSwap.
        // self.stats.refresh();
        it
    }
}