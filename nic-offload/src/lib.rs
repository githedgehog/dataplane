// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! Policy lowered into NIC hardware, per port and per NIC species, with software as the fallback.
//!
//! - [`program`] compiles published policy (today: rate limits) into what a NIC may do, from the
//!   typed match-action rules software uses, and refuses what it may not. It knows no NIC.
//! - One module per NIC species lowers a program onto that NIC: [`mlx5`].
//! - [`model`] says what a lowered plan may do with a frame, without the NIC, so tests can hold
//!   the lowering to the software it stands in front of.
//! - The driver asks this crate three questions and nothing else: what a device needs at probe
//!   ([`probe_args`]), what a port reserves before start ([`port_resources`]), and, per started
//!   port, to follow the policy ([`mlx5::run`]).
//!
//! Prototype: enabled by `DATAPLANE_NIC_OFFLOAD=1`; mlx5 only.

pub mod mlx5;
pub mod model;
pub mod program;

#[cfg(test)]
mod differential;
#[cfg(test)]
mod tests;

use dpdk::dev::DevInfo;
use dpdk::flow::template::TemplateConfig;
use hardware::pci::address::PciAddress;

/// The PCI vendor id of NVIDIA/Mellanox.
const MELLANOX: &str = "0x15b3";

/// Whether NIC offload is requested.
#[must_use]
pub fn enabled() -> bool {
    std::env::var("DATAPLANE_NIC_OFFLOAD").is_ok_and(|v| v == "1")
}

/// Driver arguments a device needs at probe for this crate to program it later.
#[must_use]
pub fn probe_args(address: PciAddress) -> Vec<String> {
    if !enabled() {
        return Vec::new();
    }
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
    (enabled() && info.driver_name().starts_with("mlx5")).then_some(mlx5::RESOURCES)
}
