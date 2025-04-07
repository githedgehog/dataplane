// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::vxlan::Vni;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VtepProperties {
    #[multi_index(hashed_unique)]
    pub vni: Option<Vni>,
    #[builder(default)]
    pub local: Option<Ipv4Addr>,
    #[builder(default = Some(0))]
    pub ttl: Option<u8>,
}
