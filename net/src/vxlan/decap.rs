// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::buffer::PacketBufferMut;
use crate::packet::{Packet, VrfId};
use crate::vxlan::Vni;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Configuration for a VXLAN decapsulation.
pub struct VxlanDecap(HashMap<Vni, VrfId>);

impl VxlanDecap {
    /// TODO
    pub fn run<Buf: PacketBufferMut> (&mut self, mut packet: Packet<Buf>) -> Option<Packet<Buf>> {
        match packet.vxlan_decap() {
            None => Some(packet),
            Some(Ok(vxlan)) => {
                match self.0.get(&vxlan.vni) {
                    None => {
                        debug!(
                            "No VRF associated with this VNI (vni {vni})",
                            vni = vxlan.vni
                        );
                    }
                    Some(vrf_id) => {
                        packet.meta.vrf = Some(*vrf_id);
                    }
                }
                Some(packet)
            }
            Some(Err(bad)) => {
                warn!("{}", bad);
                None
            }
        }
    }
}
