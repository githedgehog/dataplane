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
//! Static chains use direct calls; dynamic chains use virtual calls.
//! Both pass the burst by reference between stages.
//!

use concurrency::sync::atomic::{AtomicU64, Ordering};
use concurrency::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

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

/// An object to inform that a pipeline should be run before some specified time
/// even if no packets arrive. Each pipeline owns an instance of this type and
/// hands shared clones to its NFs.Since there is a single value shared by all NFs,
/// the following protocol between the NFs, the pipeline and its owner governs its usage:
///    * NFs can set the value to some time `t` if they require an action to be
///      executed by `t`.
///    * The pipeline owner (e.g. a worker), if idle, must check the value and run the
///      pipeline if the deadline is reached. On each run, whether there are packets or
///      not, the value is cleared. Therefore, NFs requiring a deadline must keep on
///      requesting it on each run.
///    * Since a value may already be set, a NF request to set the value only changes it
///      if the requested time is earlier than the one set.
#[derive(Clone, Debug, Default)]
pub struct SchedRun(Arc<Deadline>);

#[derive(Debug)]
/// Deadlines need to be shared. Since we use atomics, we need to encode them.
/// This type is used to encode the time when a scheduled run should happen.
/// The deadline represents time since some reference time `epoch` encoded as follows:
///    * zero value means immediately
///    * no deadline is encoded as `u64::MAX`
///    * a given instant is encoded as 1 + nanoseconds since the `epoch`
///
/// The `epoch` is the time when the first deadline is set
struct Deadline {
    deadline: AtomicU64,
    epoch: OnceLock<Instant>,
}

impl Default for Deadline {
    fn default() -> Self {
        Self {
            deadline: AtomicU64::new(SchedRun::NONE),
            epoch: OnceLock::new(),
        }
    }
}

impl SchedRun {
    const ASAP: u64 = 0; // immediately
    const NONE: u64 = u64::MAX; // no deadline - never

    fn encode(&self, at: Instant) -> u64 {
        // get the epoch or init it
        let epoch = *self.0.epoch.get_or_init(clock::now);

        // offset of instant since the epoch
        let nanos = at.saturating_duration_since(epoch).as_nanos();

        // offset by 1 from `ASAP`; a deadline past `u64` (some 584 years) is kept short of `NONE`
        u64::try_from(nanos)
            .map_or(Self::NONE - 1, |nanos| nanos.saturating_add(1))
            .min(Self::NONE - 1)
    }

    /// Lower the deadline to `at`, unless it is earlier already.
    pub fn set_deadline(&self, at: Instant) {
        self.0.deadline.fetch_min(self.encode(at), Ordering::AcqRel);
    }

    /// Lower the deadline as far as it goes: the pipeline is to run as soon as its owner can.
    pub fn asap(&self) {
        self.0.deadline.fetch_min(Self::ASAP, Ordering::AcqRel);
    }

    /// Whether a deadline is set, reached or not.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.deadline.load(Ordering::Acquire) != Self::NONE
    }

    /// Tell if the pipeline should be run. This should be called by pipeline owners
    #[must_use]
    pub fn must_run(&self) -> bool {
        match self.0.deadline.load(Ordering::Acquire) {
            Self::NONE => false,
            Self::ASAP => true,
            nanos => self
                .0
                .epoch
                .get()
                .is_none_or(|epoch| *epoch + Duration::from_nanos(nanos - 1) <= clock::now()),
        }
    }

    /// Clear the deadline and tell whether one was set. Each time a pipeline runs it call this method
    pub(crate) fn take(&self) -> bool {
        self.0.deadline.load(Ordering::Acquire) != Self::NONE
            && self.0.deadline.swap(Self::NONE, Ordering::AcqRel) != Self::NONE
    }
}

#[cfg(test)]
mod sched_run_encoding {
    use crate::SchedRun;
    use clock::virtual_time::{Paused, advance};
    use std::time::Duration;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn no_deadline_is_set_at_first() {
        let sched = SchedRun::default();
        assert!(!sched.is_set());
        assert!(!sched.must_run());
    }

    #[test]
    fn a_deadline_is_reached_from_then_on() {
        Paused::new().block_on(async {
            let sched = SchedRun::default();
            sched.set_deadline(clock::now() + ms(1));
            assert!(sched.is_set());
            assert!(!sched.must_run());
            advance(ms(1)).await;
            assert!(sched.must_run());
            advance(ms(1)).await;
            assert!(sched.must_run());
        });
    }

    #[test]
    fn a_deadline_is_reached_exactly() {
        Paused::new().block_on(async {
            let sched = SchedRun::default();
            // fix the epoch, then clear the deadline
            sched.set_deadline(clock::now());
            assert!(sched.take());
            sched.set_deadline(clock::now() + ms(10) + Duration::from_nanos(300));
            advance(ms(10) + Duration::from_nanos(299)).await;
            assert!(!sched.must_run(), "a deadline is reached early");
            advance(Duration::from_nanos(1)).await;
            assert!(sched.must_run(), "a deadline is reached late");
        });
    }

    #[test]
    fn a_deadline_can_only_be_lowered() {
        Paused::new().block_on(async {
            let sched = SchedRun::default();
            let now = clock::now();
            let (early, late) = (now + ms(100), now + ms(200));
            sched.set_deadline(late);
            sched.set_deadline(early);
            sched.set_deadline(late);
            advance(ms(99)).await;
            assert!(!sched.must_run());
            advance(ms(1)).await;
            assert!(sched.must_run());
            assert!(sched.take());
            sched.asap();
            sched.set_deadline(late);
            assert!(sched.must_run(), "a later deadline raised an immediate run");
        });
    }

    #[test]
    fn a_deadline_before_the_first_is_kept() {
        Paused::new().block_on(async {
            let sched = SchedRun::default();
            let now = clock::now();
            sched.set_deadline(now + ms(1200));
            sched.set_deadline(now + ms(100));
            advance(ms(99)).await;
            assert!(!sched.must_run());
            advance(ms(1)).await;
            assert!(sched.must_run());
        });
    }

    #[test]
    fn taking_clears_the_deadline() {
        let sched = SchedRun::default();
        assert!(!sched.take());
        sched.asap();
        assert!(sched.take());
        assert!(!sched.is_set());
    }
}

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
