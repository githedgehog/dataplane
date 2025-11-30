// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::HashMap;

use interface_manager::interface::TapDevice;
use net::{
    buffer::{BufferPool, PacketBufferMut}, interface::InterfaceIndex, packet::Packet
};
use pipeline::DynPipeline;

/// Send packets to a [`Trap`] point in order to "trap" them to the kernel dataplane.
/// They won't go through any further pipeline processing and will be delivered to the kernel at the packet's currently
/// set iif (input interface index) if it matches a trap (tap) index.
pub struct Trap<Buf: PacketBufferMut> {
    to_trap_handler: tokio::sync::mpsc::Sender<Box<Packet<Buf>>>,
}

/// You can receive an packet injection from the kernel into the pipeline
/// at any stage which is "registered" to accept an injection.
pub struct InjectHandler<Buf: PacketBufferMut> {
    from_taps: tokio::sync::mpsc::Receiver<Box<Packet<Buf>>>,
    pipeline: DynPipeline<Buf>,
}
