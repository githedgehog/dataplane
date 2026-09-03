// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Getting received packets from an interface to the sockets bound to it.
//!
//! An `AF_XDP` socket only ever sees the packets an XDP program redirects to
//! it, and redirecting is final: the network stack never sees that packet
//! again. So the program decides, for every packet, whether the dataplane gets
//! it or the host does, and [`Redirect`] is that program -- loaded, attached,
//! and told which sockets and which addresses to send things to.
//!
//! libxdp will load a redirect program of its own when a socket is bound, and
//! that is what happens if we do not inhibit it. We do: its program redirects
//! everything, which leaves the host receiving nothing on its own interfaces,
//! and it does not handle packets that span more than one buffer, which the
//! fabric's MTU guarantees.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;

use aya::Ebpf;
use aya::maps::{HashMap as BpfHashMap, XskMap};
use aya::programs::{Xdp, XdpMode};
use concurrency::sync::Mutex;
use tracing::{debug, info};

/// Most RX queues a redirect can serve on one interface.
///
/// The socket map of the program has this many entries, so a socket bound to a
/// queue above it could never be redirected to. `xdp-ebpf` declares the same
/// number; it is a `no_std` crate for another target and cannot share this.
pub const MAX_QUEUES: u32 = 64;

/// The compiled eBPF object, placed in `OUT_DIR` by our build script.
static PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dataplane-xdp-ebpf"));

/// Name of the XDP function within the object.
const PROGRAM_NAME: &str = "xdp_redirect";

/// Name of the socket map within the object.
const SOCKET_MAP_NAME: &str = "XSKMAP";

/// Names of the maps holding the host's own addresses.
const LOCAL_IPV4_MAP_NAME: &str = "LOCAL_IPV4";
const LOCAL_IPV6_MAP_NAME: &str = "LOCAL_IPV6";

/// The XDP program that decides where each packet goes, attached to every
/// interface the driver serves.
///
/// Dropping this detaches it, so it must be held for as long as packets are
/// expected.
pub struct Redirect {
    /// One loaded and attached program per interface. Behind a lock because
    /// workers register their sockets from their own threads.
    programs: Mutex<HashMap<String, Ebpf>>,
}

impl Redirect {
    /// Load the program and attach it to each of `interfaces`.
    ///
    /// # Errors
    ///
    /// Returns an error if the program cannot be loaded or attached.
    pub fn attach<'a>(interfaces: impl IntoIterator<Item = &'a str>) -> io::Result<Self> {
        let mut programs = HashMap::new();
        for if_name in interfaces {
            if programs.contains_key(if_name) {
                continue;
            }
            programs.insert(if_name.to_owned(), attach_to(if_name)?);
        }
        Ok(Self {
            programs: Mutex::new(programs),
        })
    }

    /// Tell the program where to send the packets of `if_name`, queue
    /// `queue_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel refuses the map entry.
    pub fn register(&self, if_name: &str, queue_id: u32, socket: &impl AsRawFd) -> io::Result<()> {
        let mut programs = self.programs.lock();
        let ebpf = programs
            .get_mut(if_name)
            .ok_or_else(|| io::Error::other(format!("no XDP program attached to {if_name}")))?;

        let map = ebpf.map_mut(SOCKET_MAP_NAME).ok_or_else(|| {
            io::Error::other(format!("no map named '{SOCKET_MAP_NAME}' in the object"))
        })?;
        let mut sockets = XskMap::try_from(map)
            .map_err(|e| io::Error::other(format!("'{SOCKET_MAP_NAME}' is not an XskMap: {e}")))?;

        sockets.set(queue_id, socket.as_raw_fd(), 0).map_err(|e| {
            io::Error::other(format!(
                "could not register the socket for {if_name}:q{queue_id}: {e}"
            ))
        })?;

        debug!("Registered the socket for {if_name}:q{queue_id}");
        Ok(())
    }

    /// Tell the program which addresses are the host's own, so that traffic to
    /// them is left for the kernel instead of being redirected to a socket.
    ///
    /// Replaces whatever was there. Call it again whenever the set changes: an
    /// address the program does not know about is an address whose traffic the
    /// host stops receiving.
    ///
    /// # Errors
    ///
    /// Returns an error if the maps cannot be updated.
    pub fn set_local_addresses(&self, addresses: &[IpAddr]) -> io::Result<()> {
        let mut programs = self.programs.lock();
        // The same set goes to every interface: an address is the host's
        // wherever the packet carrying it arrived.
        for (if_name, ebpf) in programs.iter_mut() {
            replace_addresses(ebpf, addresses)
                .map_err(|e| io::Error::other(format!("on {if_name}: {e}")))?;
        }
        Ok(())
    }
}

/// Put `addresses`, and only those, in one program's address maps.
fn replace_addresses(ebpf: &mut Ebpf, addresses: &[IpAddr]) -> io::Result<()> {
    sync_family(
        ebpf,
        LOCAL_IPV4_MAP_NAME,
        |address| match address {
            // Stored as the address appears in the header, which is what the
            // program reads out of the packet.
            IpAddr::V4(v4) => Some(u32::from_ne_bytes(v4.octets())),
            IpAddr::V6(_) => None,
        },
        addresses,
    )?;
    sync_family(
        ebpf,
        LOCAL_IPV6_MAP_NAME,
        |address| match address {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => Some(v6.octets()),
        },
        addresses,
    )
}

/// Make the named map hold exactly the addresses `key_of` accepts.
///
/// Updated in place rather than cleared and refilled, so that an address
/// that is not changing is never briefly absent -- traffic to it would be
/// redirected away from the host for as long as the gap lasted.
fn sync_family<K: aya::Pod + Eq + Hash>(
    ebpf: &mut Ebpf,
    name: &str,
    key_of: impl Fn(&IpAddr) -> Option<K>,
    addresses: &[IpAddr],
) -> io::Result<()> {
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| io::Error::other(format!("no map named '{name}' in the object")))?;
    let mut map: BpfHashMap<_, K, u8> = BpfHashMap::try_from(map)
        .map_err(|e| io::Error::other(format!("'{name}' is not a hash map: {e}")))?;

    let wanted: HashSet<K> = addresses.iter().filter_map(key_of).collect();
    let present: HashSet<K> = map
        .keys()
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::other(format!("could not read the addresses already set: {e}")))?;

    for key in wanted.difference(&present) {
        map.insert(key, 1, 0)
            .map_err(|e| io::Error::other(format!("could not add an address: {e}")))?;
    }
    for key in present.difference(&wanted) {
        map.remove(key)
            .map_err(|e| io::Error::other(format!("could not drop an address: {e}")))?;
    }
    Ok(())
}

/// Load the redirect program and attach it to `if_name`.
///
/// Native XDP is tried first, and generic XDP -- which every interface
/// supports, at the cost of running after the kernel has built an `skb` --
/// second.
fn attach_to(if_name: &str) -> io::Result<Ebpf> {
    let mut ebpf = Ebpf::load(PROGRAM)
        .map_err(|e| io::Error::other(format!("could not load the XDP program: {e}")))?;

    let program: &mut Xdp = ebpf
        .program_mut(PROGRAM_NAME)
        .ok_or_else(|| {
            io::Error::other(format!("no function named '{PROGRAM_NAME}' in the object"))
        })?
        .try_into()
        .map_err(|e| io::Error::other(format!("'{PROGRAM_NAME}' is not an XDP program: {e}")))?;

    program
        .load()
        .map_err(|e| io::Error::other(format!("the kernel rejected the XDP program: {e}")))?;

    match program.attach(if_name, XdpMode::Driver) {
        Ok(_) => info!("XDP program attached to {if_name} in native mode"),
        Err(native) => {
            debug!("Native XDP attach to {if_name} failed ({native}); trying generic XDP");
            program.attach(if_name, XdpMode::Skb).map_err(|generic| {
                io::Error::other(format!(
                    "could not attach the XDP program to {if_name}: \
                     native mode said '{native}', generic mode said '{generic}'"
                ))
            })?;
            info!("XDP program attached to {if_name} in generic mode");
        }
    }

    Ok(ebpf)
}

#[cfg(test)]
mod test {
    /// The XDP program has to recognise VXLAN to keep it away from the kernel,
    /// and it carries its own copy of the port because it is built for another
    /// target and cannot use `net`. Nothing links the two but this.
    #[test]
    fn the_program_agrees_with_net_on_the_vxlan_port() {
        assert_eq!(
            u16::from(net::vxlan::Vxlan::PORT),
            4789,
            "xdp-ebpf/src/main.rs hardcodes this as VXLAN_PORT"
        );
    }
}
