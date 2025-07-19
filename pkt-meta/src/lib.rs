// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]

mod dst_vni_lookup;

pub use dst_vni_lookup::{DstVniLookup, VniTablesWriter};
