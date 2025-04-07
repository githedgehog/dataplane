// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: vpc

#![allow(unused)]

#[derive(Debug)]
pub struct Vpc {
    pub id: u64,
    pub name: String,
    pub vrf: String,
}
