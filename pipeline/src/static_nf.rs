// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use std::marker::PhantomData;

use crate::PipelineData;

/// Trait for an object that processes a burst of packets.
pub trait NetworkFunction<Buf: PacketBufferMut> {
    /// Apply this function to a burst of packets, in place.
    ///
    /// A stage rewrites the packets it is handed and records its verdict in each packet's
    /// metadata. It does not decide their fate: only the driver knows whether there is a
    /// kernel to punt a finished packet to, so every packet reaches the driver with its
    /// verdict attached rather than being swallowed here.
    ///
    /// Stages are expected to skip packets an earlier stage has already finished with --
    /// that is what [`Packet::is_done`] is for. Shortening the burst is allowed but rare;
    /// [`crate::sample_nfs::DecrementTtl`] is the one example in this crate.
    ///
    /// The burst is borrowed rather than consumed so that a `Packet` is written where it
    /// lies. Handing each stage an iterator and taking one back moved every packet by value
    /// through every stage, which a profile of the DPDK datapath found to be the single
    /// largest cost in the worker (see the `size_budget` note in `net`'s `Headers`).
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>);

    /// Run this function over an iterator's worth of packets, returning the result.
    ///
    /// A convenience for tests, benchmarks and doctests, which think in iterators rather
    /// than in bursts. It allocates; the datapath calls [`NetworkFunction::process_burst`]
    /// against a buffer it owns and reuses.
    fn process<I: IntoIterator<Item = Packet<Buf>>>(
        &mut self,
        input: I,
    ) -> std::vec::IntoIter<Packet<Buf>>
    where
        Self: Sized,
    {
        let mut burst: Vec<Packet<Buf>> = input.into_iter().collect();
        self.process_burst(&mut burst);
        burst.into_iter()
    }

    /// Let NFs access some `PipelineData` if they wish on their creation
    fn set_data(&mut self, _data: Arc<PipelineData>) {}
}

struct StaticChainImpl<Buf: PacketBufferMut, NF1: NetworkFunction<Buf>, NF2: NetworkFunction<Buf>> {
    nf1: NF1,
    nf2: NF2,
    _marker: PhantomData<Buf>,
}

impl<Buf: PacketBufferMut, NF1: NetworkFunction<Buf>, NF2: NetworkFunction<Buf>>
    NetworkFunction<Buf> for StaticChainImpl<Buf, NF1, NF2>
{
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        self.nf1.process_burst(burst);
        self.nf2.process_burst(burst);
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
    /// Chain a network function (self) with another, producing a third
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

#[cfg(test)]
mod test {
    use net::eth::mac::{DestinationMac, Mac};
    use net::headers::{TryEth, TryIpv4};

    use crate::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders, Passthrough};
    use crate::{NetworkFunction, StaticChain};
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

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()];
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
