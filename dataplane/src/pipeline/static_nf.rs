// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::buffer::PacketBufferMut;
use net::packet::Packet;
use std::marker::PhantomData;

/// Trait for an object that processes a stream of packets.
pub trait NetworkFunction<Buf: PacketBufferMut> {
    /// The `process` method takes an iterator of [`Packet`] objects,
    /// applies the appropriate transformations (or drops) and returns an iterator of
    /// modified packets.
    ///
    /// Note that a concrete iterator type is required to call this function and
    /// a concrete iterator type must be returned from this function (i.e., `impl Iterator`).
    /// If you don't have a concrete iterator type, use the
    /// [`DynNetworkFunction`][crate::pipeline::DynPipeline] trait instead.
    ///
    /// # See Also
    ///
    /// [`DynNetworkFunction`][crate::pipeline::DynPipeline]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a;
}

struct StaticChainImpl<Buf: PacketBufferMut, NF1: NetworkFunction<Buf>, NF2: NetworkFunction<Buf>> {
    nf1: NF1,
    nf2: NF2,
    _marker: PhantomData<Buf>,
}

impl<Buf: PacketBufferMut, NF1: NetworkFunction<Buf>, NF2: NetworkFunction<Buf>>
    NetworkFunction<Buf> for StaticChainImpl<Buf, NF1, NF2>
{
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        self.nf2.process(self.nf1.process(input))
    }
}

/// Statically chains two [`NetworkFunction`] objects together.
///
/// The `chain` method takes two [`NetworkFunction`] objects and returns a new [`NetworkFunction`]
/// that applies the first function, then the second.
///
/// This trait is automatically implemented for all objects that implement [`NetworkFunction`].
///
/// <div class="warning">
///
/// Do not use long chains of statically chained network functions.
/// This will cause the compiler to generate a large chain of functions that
/// causes the linker to run out of memory and crash.
///
/// </div>
pub trait StaticChain<Buf: PacketBufferMut>: NetworkFunction<Buf> {
    #[allow(unused)]
    fn chain<NF: NetworkFunction<Buf>>(self, nf: NF) -> impl NetworkFunction<Buf>;
}

impl<Buf: PacketBufferMut, Nf: NetworkFunction<Buf>> StaticChain<Buf> for Nf {
    fn chain<NF: NetworkFunction<Buf>>(self, nf: NF) -> impl NetworkFunction<Buf>
    where
        Self: Sized,
    {
        StaticChainImpl {
            nf1: self,
            nf2: nf,
            _marker: PhantomData,
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod test {
    use net::eth::mac::{DestinationMac, Mac};
    use net::headers::{TryEth, TryIpv4};

    use crate::pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders, Passthrough};
    use crate::pipeline::{NetworkFunction, StaticChain};
    use net::packet::test_utils::build_test_ipv4_packet;

    #[test]
    fn static_chain() {
        const MAX_TTL: u8 = u8::MAX;
        const NUM_TTL_DECS: usize = 3;
        let mut chain = InspectHeaders
            .chain(BroadcastMacs)
            .chain(InspectHeaders)
            .chain(Passthrough)
            .chain(DecrementTtl)
            .chain(DecrementTtl)
            .chain(DecrementTtl);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = chain.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let p0_out = &packets_out[0];
        assert_eq!(
            DestinationMac::new(Mac::BROADCAST).unwrap(),
            p0_out.try_eth().unwrap().destination()
        );
        assert_eq!(
            (MAX_TTL as usize) - NUM_TTL_DECS,
            p0_out.try_ipv4().unwrap().ttl() as usize
        );
    }
}
