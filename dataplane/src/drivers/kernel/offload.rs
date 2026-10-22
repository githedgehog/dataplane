// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Disable generic receive offload (GRO) through the ethtool ioctl.
//!
//! The `ethtool` netlink crate can read features but not set them.

use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::libc;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};

/// `ETHTOOL_GGRO` from `linux/ethtool.h`.
#[cfg(test)]
const ETHTOOL_GGRO: u32 = 0x2b;
/// `ETHTOOL_SGRO` from `linux/ethtool.h`.
const ETHTOOL_SGRO: u32 = 0x2c;

/// `struct ethtool_value` from `linux/ethtool.h`.
#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

/// Run an ethtool command on `if_name` in the calling thread's network namespace.
#[allow(unsafe_code)]
fn ethtool(if_name: &str, value: &mut EthtoolValue) -> nix::Result<()> {
    let name = if_name.as_bytes();
    // Reserve a terminating NUL and reject embedded NULs.
    if name.len() >= libc::IFNAMSIZ || name.contains(&0) {
        return Err(Errno::EINVAL);
    }
    let socket = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    // SAFETY: all zeroes is a valid `ifreq`: an empty name and a null data pointer.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, &byte) in request.ifr_name.iter_mut().zip(name) {
        *slot = libc::c_char::from_ne_bytes([byte]);
    }
    request.ifr_ifru.ifru_data = std::ptr::from_mut(value).cast();
    // SAFETY: the name is NUL-terminated; `ifru_data` points to a live, exclusively borrowed
    // `ethtool_value`. The request, value, and socket remain valid throughout the call.
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCETHTOOL as _,
            std::ptr::from_mut(&mut request),
        )
    };
    Errno::result(result).map(drop)
}

/// Read GRO state in the calling thread's network namespace.
#[cfg(test)]
pub(super) fn gro(if_name: &str) -> nix::Result<bool> {
    let mut value = EthtoolValue {
        cmd: ETHTOOL_GGRO,
        data: 0,
    };
    ethtool(if_name, &mut value)?;
    Ok(value.data != 0)
}

/// Disable GRO in the calling thread's network namespace.
///
/// GRO can deliver frames larger than the MTU to `AF_PACKET`; the datapath cannot segment them.
pub(super) fn disable_gro(if_name: &str) -> nix::Result<()> {
    ethtool(
        if_name,
        &mut EthtoolValue {
            cmd: ETHTOOL_SGRO,
            data: 0,
        },
    )
}
