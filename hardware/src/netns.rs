// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network namespaces, held by descriptor rather than by name.
//!
//! The dataplane spans two network namespaces, and neither of them is the host's. `dataplane-init`
//! creates a **datapath** namespace, moves the NICs into it, and then puts itself -- and so, across
//! `exec`, the whole dataplane -- into a **control** namespace where FRR lives and where the taps
//! that stand in for those NICs are created. The dataplane enters the datapath namespace on one
//! thread and drives DPDK from there; every other thread stays on the control side.
//!
//! The host's namespace still has tenants (Kubernetes, the metrics endpoint), but nothing in the
//! dataplane process is in it. Giving those their own runtime is a later split.
//!
//! # Why a descriptor and not `/run/netns/<name>`
//!
//! `ip netns add` keeps a namespace alive by bind-mounting it under `/run/netns`. That works, but
//! it leaves a mount behind that outlives the process, so a dataplane that dies leaves a namespace
//! for the next one to trip over, and cleaning it up becomes somebody's job.
//!
//! A namespace lives as long as *anything* references it, and an open file descriptor is such a
//! reference. So holding the descriptor holds the namespace, and closing it -- which the kernel
//! does on exit, however the process dies -- releases it. Nothing is left behind and there is
//! nothing to clean up. Measured: a namespace whose creating process was `kill -9`ed still had its
//! interfaces, reachable through the descriptor alone.
//!
//! It also travels. [`OwnedFd`] survives `exec` once its close-on-exec flag is cleared, which is
//! how `dataplane-init` hands the namespace to the dataplane along with its configuration, and
//! `DEVLINK_ATTR_NETNS_FD` accepts a raw descriptor, which is how the devices get moved into it
//! without the namespace ever having a name.
//!
//! The cost is that a nameless namespace does not appear in `ip netns list`. `lsns -t net` still
//! finds it, since a thread is in it.
//!
//! # Entering one takes two steps, not one
//!
//! [`NetworkNamespace::enter`] is not enough to reach an mlx5 device, and the way it falls short is
//! silent. Two independent things gate the device, and `setns` addresses only the first:
//!
//! 1. **Access** is gated on the network namespace. Under `rdma system show` = `netns exclusive`
//!    the kernel checks the caller's namespace when `/dev/infiniband/uverbs*` is opened.
//! 2. **Enumeration** is gated on the *mount* namespace. `libibverbs` finds devices by reading
//!    `/sys/class/infiniband`, and sysfs is tagged with the network namespace it was *mounted* in.
//!    A `setns` does not retag an existing mount, so an inherited `/sys` keeps showing wherever it
//!    came from -- listing devices that cannot be used, or listing none when they are right there.
//!
//! [`NetworkNamespace::enter_with_sysfs`] does both. Measured on a BlueField-3 whose ports had been
//! moved into a namespace: `setns` alone probed 0 ports, and `setns` plus a fresh sysfs probed the
//! port and forwarded traffic through it. See `hardware/tests/dpdk_in_netns.rs`.
//!
//! Both failure modes present as an empty device list, which is also what absent hardware looks
//! like, which is why this does both steps together rather than offering the halves separately.
//!
//! # These are per-thread
//!
//! `setns` and `unshare` affect the calling thread alone, and threads inherit both namespaces from
//! whichever thread created them. That is what makes the design work: one thread jumps, spawns the
//! DPDK workers, and they land in the right place, while every other thread in the process carries
//! on in the control namespace serving the control plane.
//!
//! It is also what makes `TUNSETIFF` placement matter. A tap is created in the namespace of the
//! thread which opens it and no later `setns` moves it, so the control-plane bridge has to build
//! its taps before the datapath thread jumps.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use tracing::debug;

/// Anything that can go wrong creating or entering a network namespace.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetnsError {
    /// The namespace could not be created.
    #[error("failed to create a network namespace: {0} (CAP_SYS_ADMIN is required)")]
    Create(#[source] io::Error),
    /// The namespace's descriptor could not be opened.
    #[error("failed to open {path}: {source}")]
    Open {
        /// The path that could not be opened.
        path: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// `setns` failed.
    #[error("failed to enter the network namespace: {0} (CAP_SYS_ADMIN is required)")]
    Enter(#[source] io::Error),
    /// The mount namespace could not be unshared, so sysfs could not be replaced safely.
    #[error("failed to unshare the mount namespace: {0} (CAP_SYS_ADMIN is required)")]
    UnshareMounts(#[source] io::Error),
    /// The mount tree could not be made private, so mounting would have escaped this process.
    #[error("failed to make the mount tree private: {0}")]
    MakePrivate(#[source] io::Error),
    /// A sysfs reflecting this namespace could not be mounted.
    #[error("failed to mount a sysfs for this network namespace: {0}")]
    MountSysfs(#[source] io::Error),
}

/// A network namespace, kept alive by an open descriptor.
///
/// Dropping this releases the reference. If it was the last one the kernel destroys the namespace,
/// which returns any device inside it to the host -- see [`NetworkNamespace::create`] for what that
/// costs.
#[derive(Debug)]
pub struct NetworkNamespace {
    fd: OwnedFd,
}

impl NetworkNamespace {
    /// Where a thread's own network namespace appears in procfs.
    ///
    /// `thread-self`, not `self`: `/proc/self/ns/net` is the *process's* namespace, meaning the
    /// main thread's, and reading it from a thread that has just unshared would hand back the
    /// namespace that thread just left.
    const THREAD_NETNS: &'static str = "/proc/thread-self/ns/net";

    /// Create a new, empty network namespace and return a handle that keeps it alive.
    ///
    /// The namespace is made on a short-lived thread, which unshares, opens its own namespace, and
    /// exits. Unsharing on a scratch thread rather than the caller's is the point: `unshare` is
    /// per-thread and cannot be undone, so doing it in place would strand the caller -- typically
    /// the process's main thread -- outside the host's namespace for good.
    ///
    /// Once that thread exits the returned descriptor is the only reference, which is exactly the
    /// intended lifetime: the namespace exists for as long as this handle does.
    ///
    /// # A destroyed namespace is not free
    ///
    /// Devices inside it do not simply move back. Measured on a BlueField-3: the driver is torn
    /// down and re-probed from scratch, taking about **seven seconds** for two ports, with a link
    /// retrain, a **new ifindex**, and the netdev reappearing as `eth0` before udev renames it.
    /// Nothing may cache an ifindex across that, and anything holding the device's name -- a tap,
    /// say -- will collide with udev's rename and leave the device misnamed. That collision is the
    /// reason the dataplane's taps live in a control namespace of their own rather than the host's:
    /// there is nothing there for the returning device to collide with.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Create`] if the namespace cannot be made, which without
    /// `CAP_SYS_ADMIN` it cannot, and [`NetnsError::Open`] if its descriptor cannot be opened.
    pub fn create() -> Result<Self, NetnsError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    nix::sched::unshare(CloneFlags::CLONE_NEWNET)
                        .map_err(|e| NetnsError::Create(e.into()))?;
                    Self::open(Self::THREAD_NETNS)
                })
                .join()
                // The closure above returns a `Result`; a panic is this module's own bug, and the
                // guide is explicit that programmer error is not recoverable.
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
        })
    }

    /// Take ownership of a descriptor that already refers to a network namespace.
    ///
    /// This is how the dataplane picks up the namespace `dataplane-init` created for it: the
    /// descriptor arrives across `exec`, and nothing about it needs re-deriving.
    #[must_use]
    pub const fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    /// Open a namespace by path, such as `/proc/<pid>/ns/net` or `/run/netns/<name>`.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Open`] if the path cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NetnsError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| NetnsError::Open {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            fd: OwnedFd::from(file),
        })
    }

    /// Borrow the descriptor, for handing to `exec` or to `DEVLINK_ATTR_NETNS_FD`.
    #[must_use]
    pub fn as_raw(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Give up ownership of the descriptor without releasing the namespace.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// Move **the calling thread** into this network namespace.
    ///
    /// This is the first of the two steps a DPDK datapath needs; on its own it will not reach an
    /// mlx5 device, because enumeration still reads the sysfs this thread inherited. Prefer
    /// [`enter_with_sysfs`](Self::enter_with_sysfs) unless the caller has already arranged a sysfs
    /// that reflects this namespace.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Enter`] if `setns` fails, which without `CAP_SYS_ADMIN` it will.
    pub fn enter(&self) -> Result<(), NetnsError> {
        nix::sched::setns(&self.fd, CloneFlags::CLONE_NEWNET)
            .map_err(|e| NetnsError::Enter(e.into()))?;
        debug!("thread entered network namespace {:?}", self.fd);
        Ok(())
    }

    /// Move **the calling thread** into this namespace and give it a sysfs that reflects it.
    ///
    /// This is what a thread about to initialize DPDK wants. After it returns,
    /// `/sys/class/infiniband` lists the namespace's RDMA devices rather than the ones this thread
    /// inherited, and `/dev/infiniband/uverbs*` can be opened, which are the two things the mlx5
    /// PMD needs and which fail independently of each other.
    ///
    /// It is also what a thread joining the **control** namespace wants, for an unrelated reason
    /// with the same cause. `netdev` reads an interface's type from `/sys/class/net/<name>/type`
    /// and reports `Unknown` when it cannot; the configuration builder rejects an interface whose
    /// type it does not recognise. Under an inherited sysfs that path does not exist for any
    /// interface in the joined namespace, so every config apply fails. Measured on a tap: `type`
    /// reads `1` (`ARPHRD_ETHER`) under a fresh sysfs and is absent under an inherited one, while
    /// netlink reports the interface correctly either way -- so nothing about the symptom points
    /// at the mount.
    ///
    /// The mount namespace is unshared first, and its tree made private, before anything is
    /// mounted. Both matter: unsharing keeps `/sys` unchanged for every other thread in this
    /// process, and making the tree private keeps the new mount from propagating back out through
    /// the shared propagation a typical host uses -- which would replace the host's own `/sys`.
    ///
    /// Like [`enter`](Self::enter), this affects only the calling thread, and threads spawned
    /// afterwards inherit both namespaces from it.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError`] if entering the namespace, unsharing the mount namespace, making the
    /// tree private, or mounting sysfs fails. All of them need `CAP_SYS_ADMIN`.
    pub fn enter_with_sysfs(&self) -> Result<(), NetnsError> {
        self.enter()?;

        nix::sched::unshare(CloneFlags::CLONE_NEWNS)
            .map_err(|e| NetnsError::UnshareMounts(e.into()))?;

        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .map_err(|e| NetnsError::MakePrivate(e.into()))?;

        nix::mount::mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| NetnsError::MountSysfs(e.into()))?;

        debug!("thread has a sysfs reflecting its network namespace");
        Ok(())
    }
}

/// Identify the calling thread's network namespace, for logging.
///
/// Returns the `net:[...]` form the kernel uses, so a log line can be matched against `lsns -t net`
/// and `readlink /proc/<pid>/ns/net`. Best effort: this exists to make a log message useful, so a
/// failure to read it is reported inline rather than raised.
#[must_use]
pub fn current() -> String {
    match std::fs::read_link(NetworkNamespace::THREAD_NETNS) {
        Ok(path) => path.display().to_string(),
        Err(e) => format!("unknown ({e})"),
    }
}

#[cfg(test)]
mod test {
    use super::NetworkNamespace;
    use caps::Capability;
    use fixin::wrap;
    use std::collections::BTreeSet;
    use test_utils::with_caps;

    /// What `/sys/class/net` lists to the calling thread.
    fn sysfs_interfaces() -> BTreeSet<String> {
        std::fs::read_dir("/sys/class/net")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// `setns` alone leaves the thread reading the *old* namespace's sysfs.
    ///
    /// This is the trap the module documentation describes, pinned down as a test because both of
    /// its failure modes are silent and neither points at the mount. It has now cost two separate
    /// bugs: the DPDK datapath enumerating no RDMA devices, and -- later, and far less obviously --
    /// every configured interface coming back as `InterfaceType::Unknown` in the control namespace,
    /// because `netdev` reads an interface's type from `/sys/class/net/<name>/type`. Every config
    /// apply then failed with "Unsupported type of interface", the routing table never learned the
    /// interface, and the datapath dropped every frame arriving on it as `InterfaceUnknown`.
    ///
    /// Netlink is namespace-aware and gets it right either way, which is what makes this so hard to
    /// see: the interface is *there*, with the right name, index and MAC. Only its type is missing.
    ///
    /// The namespaces are entered on scratch threads because `setns` and `unshare` are per-thread
    /// and irreversible; doing either on the test thread would strand the rest of the run.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn setns_alone_leaves_the_old_namespaces_sysfs_behind() {
        let netns = NetworkNamespace::create().expect("could not create a namespace");

        let here = sysfs_interfaces();
        assert!(
            here.len() > 1,
            "this test needs the starting namespace to have interfaces beyond `lo` for the \
             comparison below to mean anything; it listed {here:?}"
        );

        // `enter` alone. The thread is in a namespace whose only interface is `lo`, but sysfs was
        // mounted elsewhere and `setns` does not retag an existing mount.
        let inherited = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    netns.enter().expect("could not enter");
                    sysfs_interfaces()
                })
                .join()
                .expect("scratch thread panicked")
        });
        assert_eq!(
            inherited, here,
            "sysfs unexpectedly reflected the joined namespace after `enter` alone. If this ever \
             starts passing, the kernel's sysfs tagging has changed -- but until then, dropping \
             `enter_with_sysfs` breaks both the datapath and the control plane."
        );

        // `enter_with_sysfs`. A fresh sysfs is tagged with this namespace, so it lists exactly what
        // the namespace holds: a new namespace has only loopback.
        let fresh = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    netns
                        .enter_with_sysfs()
                        .expect("could not enter with a fresh sysfs");
                    let listed = sysfs_interfaces();
                    // Readable, not merely listed: this is the file `netdev` needs, and 772 is
                    // ARPHRD_LOOPBACK.
                    let ty = std::fs::read_to_string("/sys/class/net/lo/type").ok();
                    (listed, ty)
                })
                .join()
                .expect("scratch thread panicked")
        });
        let (listed, lo_type) = fresh;
        assert_eq!(
            listed,
            BTreeSet::from(["lo".to_string()]),
            "a fresh sysfs must list exactly the joined namespace's interfaces"
        );
        assert_eq!(
            lo_type.as_deref().map(str::trim),
            Some("772"),
            "with a fresh sysfs an interface's type must be readable; without it `netdev` reports \
             `Unknown` and every config apply fails"
        );
    }
}
