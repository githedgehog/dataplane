// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! FRR drivers: the logic to drive FRR.
//! Currently only one driver exists, leveraging frr-reload.py.

pub(crate) mod frrmi;
pub mod renderer;
