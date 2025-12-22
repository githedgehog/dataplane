// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Support for k8s-less mode where CRDs are learnt from a file

mod local;

pub use local::kubeless_watch_gateway_agent_crd;
