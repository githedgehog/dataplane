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
}

/// Where software takes in each VPC's VXLAN: it decapsulates only VXLAN addressed to the VTEP of
/// the VNI's FIB, and routes the rest in the underlay untouched.
pub trait Vteps: std::fmt::Debug + Send + Sync {
    /// The IPv4 addresses of the VTEPs of `vnis`, for those that have one. Offload polls this:
    /// one call reads them all.
    fn vteps(&self, vnis: &BTreeSet<Vni>) -> BTreeMap<Vni, Ipv4Addr>;
}
