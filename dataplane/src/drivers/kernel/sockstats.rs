// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Statistics that the kernel keeps for a packet socket.

use std::os::unix::io::AsFd;

use nix::libc;
use nix::sys::socket::getsockopt;
use nix::{getsockopt_impl, sockopt_impl};

sockopt_impl!(
    PacketStatistics,
    GetOnly,
    libc::SOL_PACKET,
    libc::PACKET_STATISTICS,
    libc::tpacket_stats
);

/// Get the number of frames the kernel dropped on the socket, typically because we
/// did not read them fast enough. The kernel resets its counters when we read them,
/// so this returns the number of drops since the previous call.
pub fn get_kernel_drops<Fd: AsFd>(fd: Fd) -> Result<u64, nix::Error> {
    getsockopt(&fd, PacketStatistics).map(|stats| u64::from(stats.tp_drops))
}
