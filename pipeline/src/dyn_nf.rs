// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use net::buffer::PacketBufferMut;

/// A [`NetworkFunction`] held as a trait object.
pub trait DynNetworkFunction<Buf: PacketBufferMut>: NetworkFunction<Buf> {}

impl<Buf: PacketBufferMut, NF: NetworkFunction<Buf>> DynNetworkFunction<Buf> for NF {}

/// Creates a boxed, dynamic network function.
///
/// This function takes a [`NetworkFunction`] and returns a boxed, dynamic network function.
///
/// # See Also
///
/// * [`DynNetworkFunction`]
/// * [`crate::pipeline::DynPipeline`]
pub fn nf_dyn<'nf, Buf: PacketBufferMut + 'nf, NF: NetworkFunction<Buf> + 'nf>(
    nf: NF,
) -> Box<dyn DynNetworkFunction<Buf> + 'nf> {
    Box::new(nf)
}
