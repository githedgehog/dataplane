// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: frr

use std::fmt::Display;

#[derive(Clone, Debug, Default)]
pub enum FrrProfile {
    #[default]
    Datacenter,
    Traditional,
}

#[derive(Clone, Debug, Default)]
pub struct Frr {
    pub profile: FrrProfile,
    pub hostname: String,
}
#[allow(dead_code)]
impl Frr {
    #[must_use]
    pub fn new(profile: FrrProfile, hostname: &str) -> Self {
        Self {
            profile,
            hostname: hostname.to_owned(),
        }
    }
}
