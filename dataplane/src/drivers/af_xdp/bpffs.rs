// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The BPF filesystem libxdp keeps its programs in.
//!
//! libxdp pins the dispatcher program it loads, and the count of sockets using
//! it, under `/sys/fs/bpf`. That is how it knows, when a socket goes away,
//! whether it was the last one on that interface and the program can be
//! detached. Without the filesystem it says so and carries on with a program
//! it cannot later detach, which leaves one attached to every interface the
//! dataplane ran on -- and the next run then has to displace it.
//!
//! Most systems have it mounted already. A container often does not, and the
//! dataplane runs in one, so mount it rather than asking whoever launches us
//! to.

use std::path::Path;

use nix::mount::{MsFlags, mount};
use nix::sys::statfs::{BPF_FS_MAGIC, statfs};
use tracing::{debug, info, warn};

/// Where the BPF filesystem is mounted, by convention and by what libxdp looks
/// for.
const MOUNT_POINT: &str = "/sys/fs/bpf";

/// Mount the BPF filesystem if it is not mounted already.
///
/// Does not fail: a dataplane that cannot mount it still runs, so this reports
/// what it could not do and leaves the decision to carry on to the caller.
pub(super) fn ensure_mounted() {
    let path = Path::new(MOUNT_POINT);

    match statfs(path) {
        Ok(stats) if stats.filesystem_type() == BPF_FS_MAGIC => {
            debug!("BPF filesystem already mounted at {MOUNT_POINT}");
            return;
        }
        Ok(_) => debug!("{MOUNT_POINT} exists but is not a BPF filesystem; mounting one"),
        Err(e) => {
            // No mount point at all. Creating one only works where /sys is
            // writable, which is the same condition as the mount itself, so
            // let the mount report the failure rather than pre-empting it.
            debug!("Cannot stat {MOUNT_POINT} ({e}); trying to create and mount it");
            if let Err(e) = std::fs::create_dir_all(path) {
                warn!("Could not create {MOUNT_POINT}: {e}");
            }
        }
    }

    match mount(
        Some("bpf"),
        path,
        Some("bpf"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        Ok(()) => info!("Mounted the BPF filesystem at {MOUNT_POINT}"),
        Err(e) => warn!(
            "Could not mount the BPF filesystem at {MOUNT_POINT}: {e}. \
             XDP programs will be left attached to the interfaces on exit, \
             and the next run will have to displace them."
        ),
    }
}
