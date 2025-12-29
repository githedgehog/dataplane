// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration processor.
//! This module implements the core logic to determine and build internal configurations.

pub(crate) mod confbuild;
mod display;
pub(crate) mod gwconfigdb;
pub(crate) mod k8s_client;
pub(crate) mod k8s_less_client;
pub(crate) mod launch;
pub(crate) mod mgmt_client;
pub(crate) mod proc;
