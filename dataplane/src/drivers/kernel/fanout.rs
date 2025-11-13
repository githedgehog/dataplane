// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::os::unix::io::AsFd;

use nix::libc;
use nix::sys::socket::setsockopt;
use nix::{setsockopt_impl, sockopt_impl};

sockopt_impl!(
    PacketFanout,
    SetOnly,
    libc::SOL_PACKET,
    libc::PACKET_FANOUT,
    u32
);

#[allow(unused)]
const PACKET_FANOUT_HASH: u16 = 0;
#[allow(unused)]
const PACKET_FANOUT_LB: u16 = 1;
#[allow(unused)]
const PACKET_FANOUT_CPU: u16 = 2;
#[allow(unused)]
const PACKET_FANOUT_ROLLOVER: u16 = 3;
#[allow(unused)]
const PACKET_FANOUT_RND: u16 = 4;
#[allow(unused)]
const PACKET_FANOUT_QM: u16 = 5;

const DP_PACKET_FANOUT_ID: u16 = 0xbeef;

pub fn set_packet_fanout<Fd>(fd: Fd) -> Result<(), nix::Error>
where
    Fd: AsFd,
{
    let value = (u32::from(PACKET_FANOUT_HASH) << 16) | u32::from(DP_PACKET_FANOUT_ID);
    setsockopt(&fd, PacketFanout, &value)
}
