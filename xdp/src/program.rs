// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Getting received packets from an interface to the sockets bound to it.
//!
//! An `AF_XDP` socket only ever sees the packets an XDP program redirects to
//! it, and redirecting is final: the network stack never sees that packet
//! again. So the program decides, for every packet, where it goes, and
//! [`Redirect`] is that program -- loaded, attached, and told which sockets to
//! send things to.
//!
//! libxdp will load a redirect program of its own when a socket is bound, and
//! that is what happens if we do not inhibit it. We do: we want the decision
//! to be ours.

use std::collections::HashMap;
use std::io;
use std::os::unix::io::AsRawFd;

use aya::Ebpf;
use aya::maps::XskMap;
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

