// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::pipeline::sample_nfs::{BroadcastMacs, DecrementTtl, InspectHeaders, Passthrough};
use crate::pipeline::{DynNetworkFunction, nf_dyn};
use net::buffer::TestBuffer;

/// Generates an infinite sequence of network functions.
///
/// The sequence is a repeating pattern of:
/// - [`InspectHeaders`]
/// - [`BroadcastMacs`]
/// - [`InspectHeaders`]
/// - [`DecrementTtl`]
///
/// To avoid decrementing the TTL below 0, once there are 255 [`DecrementTtl`] stages, the pattern
/// becomes:
/// - [`InspectHeaders`]
/// - [`BroadcastMacs`]
/// - [`InspectHeaders`]
/// - [`Passthrough`]
pub struct DynStageGenerator {
    i: usize,
}

impl DynStageGenerator {
    pub fn new() -> Self {
        Self { i: 0 }
    }

    pub fn num_ttl_decs(count: usize) -> usize {
        let num = count / 4;
        if num > u8::MAX as usize {
            u8::MAX as usize
        } else {
            num
        }
    }
}

impl Iterator for DynStageGenerator {
    #![allow(clippy::match_same_arms)]

    type Item = Box<dyn DynNetworkFunction<TestBuffer>>;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = match self.i % 4 {
            0 => Some(nf_dyn(InspectHeaders)),
            1 => Some(nf_dyn(BroadcastMacs)),
            2 => Some(nf_dyn(InspectHeaders)),
            3 => {
                if Self::num_ttl_decs(self.i) == u8::MAX as usize {
                    Some(nf_dyn(Passthrough))
                } else {
                    Some(nf_dyn(DecrementTtl))
                }
            }
            _ => unreachable!(),
        };
        self.i += 1;
        ret
    }
}
