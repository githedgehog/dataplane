// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Concrete [`Backend`] implementations.
//!
//! Each submodule provides a backend that materializes a
//! [`PipelineIR`] into a runtime form usable by the data path.
//! The first entry, [`dpdk`], targets the DPDK ACL classifier
//! (`rte_acl_*`).
//!
//! [`Backend`]: crate::manager::Backend
//! [`PipelineIR`]: crate::ir::PipelineIR

pub mod dpdk;
