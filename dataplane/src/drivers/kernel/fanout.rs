// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fmt::Display;
use std::os::unix::io::AsFd;

use net::interface::InterfaceIndex;
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

pub enum PacketFanoutType {
    Qm,
    Hash,
    Cpu,
}

impl Display for PacketFanoutType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketFanoutType::Qm => write!(f, "PACKET_FANOUT_QM"),
            PacketFanoutType::Hash => write!(f, "PACKET_FANOUT_HASH"),
            PacketFanoutType::Cpu => write!(f, "PACKET_FANOUT_CPU"),
        }
    }
}

pub fn set_packet_fanout<Fd>(
    if_index: InterfaceIndex,
    fd: Fd,
) -> Result<PacketFanoutType, nix::Error>
where
    Fd: AsFd,
{
    #[allow(clippy::expect_used)]
    let raw_fanout_id = u16::try_from(u32::from(if_index) & 0xffff).unwrap_or_else(|_| unreachable!(
        "Could not convert interface index to u16 when computing fanout id for if_index={if_index}",
    ));
    let packet_fanout_id = u32::from(raw_fanout_id);

    let value = (u32::from(PACKET_FANOUT_QM) << 16) | packet_fanout_id;
    if setsockopt(&fd, PacketFanout, &value).is_ok() {
        return Ok(PacketFanoutType::Qm);
    }

    let value = (u32::from(PACKET_FANOUT_HASH) << 16) | packet_fanout_id;
    if setsockopt(&fd, PacketFanout, &value).is_ok() {
        return Ok(PacketFanoutType::Hash);
    }

    // FIXME(manishv) for these cases, we should probably install an eBPF filter and use
    // PACKET_FANOUT_EBPF
    let value = (u32::from(PACKET_FANOUT_CPU) << 16) | packet_fanout_id;
    if setsockopt(&fd, PacketFanout, &value).is_ok() {
        return Ok(PacketFanoutType::Cpu);
    }

    Err(nix::Error::ENOTSUP)
}
