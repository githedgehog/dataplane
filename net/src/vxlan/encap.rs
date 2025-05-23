// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::headers::{Headers, TryIp, TryVxlan};
use tracing::error;

/// Configuration for [`VxlanEncap`] operation
///
/// This struct is a safety measure designed to check that the enclosed [`Headers`] really do
/// describe a vxlan packet.
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
        match (headers.try_ip(), headers.try_vxlan()) {
            (None, _) => Err(VxlanEncapError::Ip),
            (_, None) => Err(VxlanEncapError::Vxlan),
            (Some(_), Some(_)) => Ok(Self { headers }),
        }
    }

    /// Get the headers to be used to fill in the VXLAN parameters on encap.
    #[must_use]
    pub fn headers(&self) -> &Headers {
        &self.headers
    }
}
