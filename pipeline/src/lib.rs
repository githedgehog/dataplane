// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(rustdoc::private_doc_tests)]
#![deny(
    unsafe_code,
    missing_docs,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! # Pipeline Building Blocks
//!
//! This crate provides the building blocks for constructing pipelines of network functions.
//! There are two main methods provided for linking network functions together in sequence:
//!
//! - `StaticChain`: A trait for statically chaining network functions together.
//! - `DynPipeline`: A pipeline that can be dynamically constructed at runtime.
//!
//! ## Network Functions
//!
//! A network function is anything that implements the [`NetworkFunction`] trait.
//! You can look at the [`sample_nfs`] module for some examples of simple network functions.
//!
//! ## Static Chaining
//!
//! You can statically chain together a series of network functions using the [`StaticChain::chain`]
//! method. [`StaticChain`] is implemented for all types that implement [`NetworkFunction`].
//!
//! ```rust
//! use dataplane_pipeline::{NetworkFunction, StaticChain};
//! use dataplane_pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders};
//! use net::buffer::PacketBufferMut;
//! use net::packet::Packet;
//! use net::buffer::TestBuffer;
//!
//! /// This creates a chain of functions that first does a `debug!` on the packet contents then
//! /// sets the destination mac to the broadcast mac address then decrements the TTL value of the
//! /// IP packet.
//! let mut pipeline = InspectHeaders.chain(BroadcastMacs).chain(DecrementTtl);
//! let pkts: Vec<Packet<TestBuffer>> = vec![];
//! pipeline.process(pkts);
//! ```
//! Note that `pipeline` implements the [`NetworkFunction`] trait and can be used anywhere a
//! network function is expected.
//!
//! <div class="warning">
//!
//! Keep statically linked chains short, ideally less than 8 stages.
//!
//! The [`StaticChain::chain`] triggers compiler/linker limitations, long chains cause long
//! compile times and eventually cause the linker to run out of memory.
//!
//! </div>
//!
//! ## Dynamic Pipeline
//!
//! You can also use [`DynPipeline`] to construct a pipeline at runtime or to dynamically chain
//! together a series of network functions.
//!
//! ```rust
//! use dataplane_pipeline::DynPipeline;
//! use dataplane_pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders};
//! use net::buffer::TestBuffer;
//!
//! let mut pipeline = DynPipeline::<'static, TestBuffer>::new();
//! pipeline = pipeline.add_stage(InspectHeaders);
//! pipeline = pipeline.add_stage(BroadcastMacs);
//! pipeline = pipeline.add_stage(DecrementTtl);
//! ```
//! Here the pipeline has exactly the same functionality as the statically chained pipeline in the
//! previous example, but the stages are boxed as [`DynNetworkFunction`], which allows for dynamic
//! chaining, including at runtime.
//!
//! Note again that `pipeline` is of type [`NetworkFunction`] and can be used anywhere a network
//! function is expected.
//!
//! ## Dynamic Pipeline with Static Chaining
//!
//! You can also combine dynamic chaining with static chaining.
//!
//! ```rust
//! use dataplane_pipeline::{DynPipeline, NetworkFunction, StaticChain};
//! use dataplane_pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders};
//! use net::buffer::TestBuffer;
//!
//! let mut pipeline: DynPipeline<'static, TestBuffer> = DynPipeline::new();
//! // Add a dynamic stage that is the static chain of `InspectHeaders` and `BroadcastMacs`
//! pipeline = pipeline.add_stage(InspectHeaders.chain(BroadcastMacs));
//! pipeline = pipeline.add_stage(DecrementTtl);
//! ```
//! Here the first stage is a static chain of [`sample_nfs::InspectHeaders`] and
//! [`sample_nfs::BroadcastMacs`] and the second stage is just [`sample_nfs::DecrementTtl`].
//! The overall functionality is the same as the previous examples.
//!
//! ## Performance Considerations
//!
//! Static chaining still compiles to a direct call per stage and a dynamic one to a virtual call,
//! so a static chain of a few small functions remains the cheaper arrangement, and statically
//! chained stages can be added to a dynamic pipeline as shown above.
//!
//! The gap used to be much wider. A stage took an iterator and returned an opaque one, so a
//! dynamic pipeline had to erase the iterator type at every boundary, and that erasure stopped
//! the optimiser dead -- each stage moved every packet by value across it. Stages now borrow the
//! burst, so the only thing a stage boundary costs is the call itself.
//!

mod dyn_nf;
mod pipeline;
/// Sample network functions
pub mod sample_nfs;
mod static_nf;

#[cfg(test)]
pub(crate) mod test_utils;

#[allow(unused)]
pub use dyn_nf::{DynNetworkFunction, nf_dyn};
#[allow(unused)]
pub use pipeline::{DynPipeline, PipelineData, StageId};
#[allow(unused)]
pub use static_nf::{NetworkFunction, StaticChain};

#[cfg(test)]
mod test {
    use net::eth::mac::{DestinationMac, Mac};
    use net::headers::{TryEth, TryIpv4};

    use crate::sample_nfs::{BroadcastMacs, DecrementTtl, Passthrough};
    use crate::{DynPipeline, NetworkFunction, StaticChain};
    use net::packet::test_utils::build_test_ipv4_packet;

    #[test]
    fn mixed_dyn_static_pipeline() {
        const MAX_TTL: u8 = u8::MAX;

        let mut pipeline = DynPipeline::new();
        let num_stages = 50;

        let num_ttl_decs = 3 * num_stages;
        for _ in 0..num_stages {
            pipeline = pipeline.add_stage(
                DecrementTtl
                    .chain(Passthrough)
                    .chain(DecrementTtl)
                    .chain(BroadcastMacs)
                    .chain(DecrementTtl),
            );
        }

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = pipeline.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let p0_out = &packets_out[0];
        assert_eq!(
            p0_out.try_eth().unwrap().destination(),
            DestinationMac::new(Mac::BROADCAST).unwrap()
        );
        assert_eq!(
            (MAX_TTL as usize) - num_ttl_decs,
            p0_out.try_ipv4().unwrap().ttl() as usize
        );
    }
}
