// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! Offload gateway policy to NIC hardware, with software fallback.
//!
//! - [`program`] compiles typed ingress, ACL and rate-limit rules into a backend-neutral program.
//! - [`mlx5`] lowers and installs the program on supported hardware.
//! - [`model`] predicts NIC outcomes for comparison with software.
//!
//! Drivers use [`probe_args`], [`port_resources`] and [`mlx5::run`] to configure and follow policy.
//! Offload defaults on; `gateway.alpha.githedgehog.com/attempt-offloads: "false"` disables it.
//! Failed offload probes fall back to software. Currently supports mlx5 only.

pub mod mlx5;
pub mod model;
pub mod program;

#[cfg(test)]
mod differential;
#[cfg(test)]
mod meters;
#[cfg(test)]
mod qualify;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use acl_filter::AclFilterContextReader;
use concurrency::sync::Arc;
use dpdk::dev::DevInfo;
use dpdk::flow::template::TemplateConfig;
use hardware::pci::address::PciAddress;
use net::vxlan::Vni;
use rate_limit::{IngressRules, PeeringRules, RateLimitReader};

/// The PCI vendor id of NVIDIA/Mellanox.
const MELLANOX: &str = "0x15b3";

/// Driver arguments a device needs at probe for this crate to program it later.
#[must_use]
pub fn probe_args(address: PciAddress) -> Vec<String> {
    let vendor = std::fs::read_to_string(format!("/sys/bus/pci/devices/{address}/vendor"));
    if !vendor.is_ok_and(|v| v.trim() == MELLANOX) {
        return Vec::new();
    }
    let mut args = vec!["dv_flow_en=2".to_string()];
    // mlx5 pins its counter thread to `service_core`, which defaults to the main lcore's *id* used
    // as a CPU number (`mlx5.c`, `rte_get_main_lcore`). A process confined to other CPUs then
    // fails to configure the port, so name a CPU it may run on.
    if let Some(cpu) = first_allowed_cpu() {
        args.push(format!("service_core={cpu}"));
    }
    args
}

/// The lowest CPU the calling thread may run on.
fn first_allowed_cpu() -> Option<usize> {
    let set = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).ok()?;
    (0..nix::sched::CpuSet::count()).find(|&cpu| set.is_set(cpu).unwrap_or(false))
}

/// What a configured port must reserve before start for this crate to program it, if anything.
#[must_use]
pub fn port_resources(info: &DevInfo<'_>) -> Option<TemplateConfig> {
    info.driver_name()
        .starts_with("mlx5")
        .then_some(mlx5::RESOURCES)
}

/// The published policy offload follows, as the pipeline's stages do.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The ACL filter's rules.
    pub acls: AclFilterContextReader,
    /// Where the flow filter sends each source VPC's traffic.
    pub routing: flow_filter::FlowFilterContextReader,
    /// The rate limiter's rules, and whether offload is turned off.
    pub rate_limits: RateLimitReader<PeeringRules>,
    /// The gateway's ingress policy.
    pub ingress: RateLimitReader<IngressRules>,
    /// The VTEP each VPC's VXLAN is addressed to.
    pub vteps: Arc<dyn Vteps>,
    /// Whether the NIC decapsulates the VXLAN of every VPC with a VTEP, delivering the inner frame
    /// with the VNI in META. Fixed for the life of a port: the switch is never rebuilt.
    pub decap: bool,
    /// With decapsulation, the stamp the trap rule writes, as the configuration publisher wants
    /// it; `None`: stamped with generation 1 for good (no publisher flips).
    pub stamping: Option<Arc<Stamping>>,
    /// Where software resumes what a VPC's generation delivers decapsulated, past its ingress
    /// policy (its arrived meter): `None` for the root, where software runs that policy again
    /// (the NIC's ingress stage a prefilter). Legal only where the NIC's ingress stage is
    /// complete: one offloading port (each port's meters are its own), and software honouring
    /// the node (`mlx5::Plan::trapping_decapped_at`).
    pub decapped_trap: Option<std::num::NonZero<u8>>,
}

/// One configuration generation's policy, as offload compiles it: the ACLs, where the flow filter
/// sends each source VPC's traffic, the peering rate limits and the ingress policy.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// The ACL filter's rules.
    pub acls: Arc<acl_filter::AclFilterContext>,
    /// The flow filter's tables.
    pub routing: Arc<flow_filter::FlowFilterContext>,
    /// The peering rate limits.
    pub rate_limits: Arc<rate_limit::RateLimits<PeeringRules>>,
    /// The ingress policy.
    pub ingress: Arc<rate_limit::RateLimits<IngressRules>>,
}

impl Inputs {
    /// What `policy`'s readers publish now.
    #[must_use]
    pub fn load(policy: &Policy) -> Inputs {
        Inputs {
            acls: policy.acls.load(),
            routing: policy.routing.load(),
            rate_limits: policy.rate_limits.load(),
            ingress: policy.ingress.load(),
        }
    }

    /// Whether `other` is the same publication of every part.
    #[must_use]
    pub fn same(&self, other: &Inputs) -> bool {
        Arc::ptr_eq(&self.acls, &other.acls)
            && Arc::ptr_eq(&self.routing, &other.routing)
            && Arc::ptr_eq(&self.rate_limits, &other.rate_limits)
            && Arc::ptr_eq(&self.ingress, &other.ingress)
    }
}

/// The generation every port's NIC is to classify under: its stamp, and its policy, which the
/// port compiles into the stamp's bank before turning its selector to it (the train track,
/// `notes/match-action-dag/GENERATIONS.md` §3). The configuration publisher asks for it at each
/// flip ([`Stamping::request`]), and each port confirms it once its NIC classifies under it: the
/// flip is done only then. Before, an idle worker could acknowledge it and the previous generation
/// retire while a port still classified packets under it.
#[derive(Debug)]
pub struct Stamping {
    wanted: concurrency::sync::Mutex<(net::packet::Stamp, Inputs)>,
    ports: concurrency::sync::Mutex<Vec<Arc<concurrency::sync::atomic::AtomicU8>>>,
}

impl Stamping {
    /// Classifying under `stamp`, with `inputs`, no port yet.
    #[must_use]
    pub fn new(stamp: net::packet::Stamp, inputs: Inputs) -> Self {
        Stamping {
            wanted: concurrency::sync::Mutex::new((stamp, inputs)),
            ports: concurrency::sync::Mutex::new(Vec::new()),
        }
    }

    /// Have every port classify under `stamp`, with `inputs`; whether every port does now. Call
    /// again until it does: ports confirm from their own threads.
    pub fn request(&self, stamp: net::packet::Stamp, inputs: Inputs) -> bool {
        use concurrency::sync::atomic::Ordering;
        *self.wanted.lock() = (stamp, inputs);
        self.ports
            .lock()
            .iter()
            .all(|applied| applied.load(Ordering::Acquire) == stamp.to_bits())
    }

    /// What ports should classify under now, and its policy.
    #[must_use]
    pub fn wanted(&self) -> (net::packet::Stamp, Inputs) {
        self.wanted.lock().clone()
    }

    /// A port's confirmation: it stores each stamp once its NIC classifies under it (or once
    /// nothing it holds is reachable). Starts at nothing, which no stamp encodes to: a port has
    /// confirmed nothing until it has installed its first generation.
    pub(crate) fn register(&self) -> Arc<concurrency::sync::atomic::AtomicU8> {
        let applied = Arc::new(concurrency::sync::atomic::AtomicU8::new(0));
        self.ports.lock().push(Arc::clone(&applied));
        applied
    }
}

/// Where software takes in each VPC's VXLAN: it decapsulates only VXLAN addressed to the VTEP of
/// the VNI's FIB, and routes the rest in the underlay untouched.
pub trait Vteps: std::fmt::Debug + Send + Sync {
    /// The IPv4 addresses of the VTEPs of `vnis`, for those that have one. Offload polls this:
    /// one call reads them all.
    fn vteps(&self, vnis: &BTreeSet<Vni>) -> BTreeMap<Vni, Ipv4Addr>;
}
