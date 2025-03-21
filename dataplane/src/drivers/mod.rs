// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]

pub mod dpdk;
pub mod kernel;

use crate::CmdArgs;
use net::buffer::PacketBufferMut;
use pipeline::DynPipeline;

/// Minimalistic trait that packet drivers should implement
pub trait Driver<Buf: PacketBufferMut> {
    type InitEnv;
    type Devices;

    /// the name of the driver
    fn name(&self) -> &'static str;

    /// fetches arguments from main arguments object and returns a vector
    /// with the ones that apply
    fn get_args(&self, args: &CmdArgs) -> Vec<String>;

    /// initializes driver: e.g. EAL if DPDK
    fn init_driver(&self, args: impl IntoIterator<Item = impl AsRef<str>>) -> Self::InitEnv;

    /// initializes devices
    fn init_devs(&self, env: &Self::InitEnv) -> Vec<Self::Devices>;

    /// starts the driver
    fn start(&self, devices: &[Self::Devices], pipeline: DynPipeline<Buf>);
}
