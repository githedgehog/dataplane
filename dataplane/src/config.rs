// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::HashMap;

pub struct Vpc {
    #[allow(dead_code)]
    pub vni: u32,
}

pub struct Config {
    // Add appropriate configuration fields here
    #[allow(dead_code)]
    pub vni_to_vpc_id: HashMap<u32, Vpc>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            vni_to_vpc_id: HashMap::new(),
        }
    }
}
