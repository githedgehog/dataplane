// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use net::buffer::PacketBufferMut;
use std::any::Any;

/// A [`NetworkFunction`] trait object supporting downcasts through [`Any`].
pub trait DynNetworkFunction<Buf: PacketBufferMut>: NetworkFunction<Buf> + Any {}

impl<Buf: PacketBufferMut, NF: NetworkFunction<Buf> + Any> DynNetworkFunction<Buf> for NF {}

/// Creates a boxed, dynamic network function.
///
/// This function takes a [`NetworkFunction`] and returns a boxed, dynamic network function.
///
/// # See Also
///
/// * [`DynNetworkFunction`]
/// * [`crate::pipeline::DynPipeline`]
pub fn nf_dyn<Buf: PacketBufferMut + 'static, NF: NetworkFunction<Buf> + 'static>(
    nf: NF,
) -> Box<dyn DynNetworkFunction<Buf>> {
    Box::new(nf)
}
