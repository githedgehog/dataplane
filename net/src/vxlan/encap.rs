// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::buffer::PacketBufferMut;
use crate::headers::{Headers, TryIp, TryUdp, TryUdpMut, TryVxlan};
use crate::packet::Packet;
use crate::udp::Udp;
use crate::vxlan::Vxlan;
use std::num::NonZero;
use tracing::error;

/// Configuration for [`VxlanEncap`] operation
pub struct VxlanEncap {
    headers: Headers,
}

impl AsRef<Headers> for VxlanEncap {
    fn as_ref(&self) -> &Headers {
        &self.headers
    }
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
    /// Create a new [`VxlanEncap`] configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`VxlanEncapError`] if the supplied [`Headers`] are not a legal VXLAN header.
    pub fn new(headers: Headers) -> Result<VxlanEncap, VxlanEncapError> {
        match (headers.try_ip(), headers.try_udp(), headers.try_vxlan()) {
            (None, _, _) => Err(VxlanEncapError::Ip),
            (_, None, _) => Err(VxlanEncapError::Udp),
            (_, _, None) => Err(VxlanEncapError::Vxlan),
            (Some(_), Some(_), Some(_)) => Ok(Self { headers }),
        }
    }

    /// Get the headers to be used to fill in the VXLAN parameters on encap.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}

impl VxlanEncap {
    /// TODO
    /// # Panics
    ///
    /// May panic (TODO)
    pub fn run<Buf: PacketBufferMut> (&mut self, packet: Packet<Buf>) -> Option<Packet<Buf>> {
        #[allow(clippy::expect_used)] // clearly impossible to fail here
        let mbuf_len = NonZero::new(
            packet.payload_len() + Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get(),
        )
            .expect("programmer error in length logic");
        match packet.vxlan_encap(self) {
            Ok(mut packet) => {
                #[allow(unsafe_code)] // TODO
                unsafe {
                    #[allow(clippy::expect_used)] // udp is always there if we vxlan encap
                    packet
                        .try_udp_mut()
                        .expect("programmer error")
                        .set_length(mbuf_len);
                    }
                Some(packet)
            }
            Err(e) => {
                error!("{e:?}");
                None
            }
        }
    }
}
