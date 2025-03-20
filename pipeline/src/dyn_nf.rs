// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::NetworkFunction;
use dyn_iter::{DynIter, IntoDynIterator};
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use std::any::Any;
use std::marker::PhantomData;

/// Trait for an object that processes a stream of packets.
///
/// Generally, you should not need to implement this trait directly. Instead, use the [`nf_dyn`]
/// function to create a boxed, dynamic network function.
///
/// # See Also
///
/// * [`nf_dyn`]
/// * [`crate::pipeline::DynPipeline`]
pub trait DynNetworkFunction<Buf: PacketBufferMut>: Any {
    /// The `process_dyn` method takes an iterator of [`Packet`] objects,
    /// However, unlike [`NetworkFunction::process`], this method does not require concrete
    /// iterator types.
    ///
    /// To call this method, import the [`IntoDynIterator`] trait and use the
    /// `into_dyn_iter` method to get a [`DynIter`] to use with this method.
    /// Generally, you should not need to call this method directly, instead call
    /// [`DynPipeline::process`][crate::pipeline::DynPipeline::process] with a concrete iterator
    /// type.  However, if you only have a dynamic iterator, you can use this method to process the
    /// packets.
    fn process_dyn<'a>(&'a mut self, input: DynIter<'a, Packet<Buf>>) -> DynIter<'a, Packet<Buf>>;
}

pub(crate) struct DynNetworkFunctionImpl<Buf: PacketBufferMut, NF: NetworkFunction<Buf> + 'static> {
    nf: NF,
    _marker: PhantomData<Buf>,
}

impl<Buf: PacketBufferMut, NF: NetworkFunction<Buf>> DynNetworkFunctionImpl<Buf, NF> {
    pub fn new(nf: NF) -> Self {
        Self {
            nf,
            _marker: PhantomData,
        }
    }

    pub fn get_nf(&self) -> &NF {
        &self.nf
    }
}

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
    Box::new(DynNetworkFunctionImpl::new(nf))
}

impl<Buf: PacketBufferMut, NF: NetworkFunction<Buf>> DynNetworkFunction<Buf>
    for DynNetworkFunctionImpl<Buf, NF>
{
    fn process_dyn<'a>(&'a mut self, input: DynIter<'a, Packet<Buf>>) -> DynIter<'a, Packet<Buf>> {
        self.nf.process(input).into_dyn_iter()
    }
}
