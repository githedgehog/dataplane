// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::pipeline::NetworkFunction;
use net::buffer::PacketBufferMut;
use net::headers::Headers;
use net::headers::TryIp;
use net::headers::TryUdp;
use net::headers::TryVxlan;
use net::packet::Packet;
use tracing::{debug, error, trace};

pub struct VxlanDecap;

// TODO: this will need to actually mark the packet with metadata derived from the vxlan header we
// removed.
impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanDecap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            match packet.vxlan_decap() {
                None => {
                    trace!("skipping packet with no vxlan header: {packet:?}");
                }
                Some(Err(invalid)) => {
                    debug!("invalid packet in vxlan: {invalid:?}");
                }
                Some(Ok(vxlan)) => {
                    trace!("decapsulated vxlan packet: {vxlan:?} inner packet: {packet:?}");
                }
            }
            packet
        })
    }
}

pub struct VxlanEncap {
    headers: Headers,
}

/// Errors which may occur when encapsulating a packet with VXLAN headers.
#[derive(Debug, thiserror::Error)]
pub enum VxlanEncapError {
    /// supplied headers have no IP layer
    #[error("supplied headers have no IP layer")]
    Ip,
    /// supplied headers have no UDP layer
    #[error("supplied headers have no UDP layer")]
    Udp,
    /// supplied headers have no VXLAN layer
    #[error("supplied headers have no VXLAN layer")]
    Vxlan,
}

impl VxlanEncap {
    #[allow(missing_docs)] // TODO
    pub fn new(headers: Headers) -> Result<VxlanEncap, VxlanEncapError> {
        match (headers.try_ip(), headers.try_udp(), headers.try_vxlan()) {
            (None, _, _) => Err(VxlanEncapError::Ip),
            (_, None, _) => Err(VxlanEncapError::Udp),
            (_, _, None) => Err(VxlanEncapError::Vxlan),
            (Some(_), Some(_), Some(_)) => Ok(Self { headers }),
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for VxlanEncap {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|packet| packet.encap_vxlan(self.headers.clone()).ok())
    }
}
