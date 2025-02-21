// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pipeline Building Blocks

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod dyn_nf;
#[allow(clippy::module_inception)]
mod pipeline;
pub mod sample_nfs;
mod static_nf;

#[cfg(test)]
pub(crate) mod test_utils;

#[allow(unused)]
pub use dyn_nf::{DynNetworkFunction, nf_dyn};
#[allow(unused)]
pub use pipeline::DynPipeline;
#[allow(unused)]
pub use static_nf::{NetworkFunction, StaticChain};

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod test {
    use net::eth::mac::{DestinationMac, Mac};
    use net::headers::{TryEth, TryIpv4};

    use crate::pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, Passthrough};
    use crate::pipeline::test_utils::build_test_ipv4_packet;
    use crate::pipeline::{DynPipeline, NetworkFunction, StaticChain};

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
