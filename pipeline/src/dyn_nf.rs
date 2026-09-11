// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use net::buffer::PacketBufferMut;
use std::any::Any;

/// A [`NetworkFunction`] held as a trait object.
///
/// This exists only to name the object type. [`NetworkFunction`] is object safe on its own --
/// `process_burst` takes a `&mut Vec<Packet<Buf>>`, which is a concrete type -- so this trait
/// adds nothing and is blanket implemented for every network function.
///
/// It was not always so. While a stage's signature was generic over its input iterator and
/// returned an opaque `impl Iterator`, neither could appear in a vtable, and a parallel trait
/// with an erased iterator type (`DynIter`) was the only way to build a pipeline at runtime.
/// That erasure also stopped the optimiser at every stage boundary. Passing the burst by
/// reference removed the need for it.
///
/// # See Also
///
/// * [`nf_dyn`]
/// * [`crate::pipeline::DynPipeline`]
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
