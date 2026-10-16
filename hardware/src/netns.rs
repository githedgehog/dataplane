// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Descriptor-owned network namespaces for the datapath.
//!
//! Init holds namespaces by descriptor and passes them across process startup. A descriptor keeps
//! its namespace alive without a bind mount under `/run/netns`; the kernel destroys it after the
//! last reference is released, which returns physical devices to the host and may reload their
//! drivers.
//!
//! The datapath owns the physical NICs; the control namespace holds their TAP interfaces and FRR.
//! [`NetworkNamespace::enter_with_sysfs`] also mounts a private sysfs for device enumeration.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
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
    /// The descriptor could not be inspected as a namespace.
    #[error("failed to identify namespace descriptor: {0}")]
    Inspect(#[source] io::Error),
    /// The descriptor refers to another kind of namespace.
    #[error("expected a network namespace, found namespace type {0:#x}")]
    WrongType(i32),
    /// The descriptor could not be marked close-on-exec.
    #[error("failed to mark namespace descriptor close-on-exec: {0}")]
    CloseOnExec(#[source] io::Error),
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
    // `/proc/self/ns/net` identifies the main thread's namespace, even after this thread moves.
    const THREAD_NETNS: &'static str = "/proc/thread-self/ns/net";

    /// Create an empty namespace on a temporary thread, leaving the caller's namespace unchanged.
    ///
    /// Destroying the namespace may reload physical NIC drivers, change ifindices, and retrain
    /// links. Do not cache ifindices across destruction or reuse device names before udev finishes.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Create`] if creation fails (requires `CAP_SYS_ADMIN`), or
    /// [`NetnsError::Open`] if the namespace descriptor cannot be opened.
    pub fn create() -> Result<Self, NetnsError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    nix::sched::unshare(CloneFlags::CLONE_NEWNET)
                        .map_err(|e| NetnsError::Create(e.into()))?;
                    Self::open(Self::THREAD_NETNS)
                })
                .join()
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
        })
    }

    /// Validate and own a network namespace descriptor, marking it close-on-exec.
    ///
    /// # Errors
    ///
    /// Rejects ordinary files and other namespace types, or reports a descriptor operation error.
    pub fn from_fd(fd: OwnedFd) -> Result<Self, NetnsError> {
        // SAFETY: NS_GET_NSTYPE takes no pointer argument, and `fd` stays open during the call.
        let kind = unsafe { nix::libc::ioctl(fd.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
        if kind == -1 {
            return Err(NetnsError::Inspect(io::Error::last_os_error()));
        }
        if kind != nix::libc::CLONE_NEWNET {
            return Err(NetnsError::WrongType(kind));
        }
        nix::fcntl::fcntl(
            &fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(|e| NetnsError::CloseOnExec(e.into()))?;
        Ok(Self { fd })
    }

    /// Open a namespace by path, such as `/proc/<pid>/ns/net` or `/run/netns/<name>`.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Open`] if opening fails, or a validation error from [`Self::from_fd`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NetnsError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| NetnsError::Open {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_fd(OwnedFd::from(file))
    }

    /// Open the calling thread's network namespace.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Open`] if the namespace descriptor cannot be opened.
    pub fn current() -> Result<Self, NetnsError> {
        Self::open(Self::THREAD_NETNS)
    }

    /// Whether the calling thread is already in this namespace.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Inspect`] if either namespace cannot be identified.
    pub fn is_current(&self) -> Result<bool, NetnsError> {
        // Namespace identity is the (device, inode) pair of its nsfs file.
        let this = nix::sys::stat::fstat(&self.fd).map_err(|e| NetnsError::Inspect(e.into()))?;
        let current =
            nix::sys::stat::stat(Self::THREAD_NETNS).map_err(|e| NetnsError::Inspect(e.into()))?;
        Ok((this.st_dev, this.st_ino) == (current.st_dev, current.st_ino))
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

    /// Move the calling thread into this network namespace.
    ///
    /// This leaves its sysfs mount unchanged. Use [`enter_with_sysfs`](Self::enter_with_sysfs)
    /// before probing mlx5 devices unless sysfs already reflects the destination namespace.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError::Enter`] if `setns` fails; requires `CAP_SYS_ADMIN`.
    pub fn enter(&self) -> Result<(), NetnsError> {
        nix::sched::setns(&self.fd, CloneFlags::CLONE_NEWNET)
            .map_err(|e| NetnsError::Enter(e.into()))?;
        debug!("thread entered network namespace {:?}", self.fd);
        Ok(())
    }

    /// Enter this namespace and mount a sysfs that exposes its RDMA devices to libibverbs.
    ///
    /// The mount namespace is unshared and made private to prevent replacing other threads' or
    /// the host's `/sys`. Threads subsequently spawned by the caller inherit both namespaces.
    /// A fresh sysfs also lets netdev inspect interfaces in the control namespace.
    ///
    /// # Errors
    ///
    /// Returns [`NetnsError`] if a namespace or mount operation fails; requires `CAP_SYS_ADMIN`.
    /// Failure can leave the caller in the destination network namespace.
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

/// Return the calling thread's `net:[...]` identifier, or an inline error for logging.
#[must_use]
pub fn current() -> String {
    match std::fs::read_link(NetworkNamespace::THREAD_NETNS) {
        Ok(path) => path.display().to_string(),
        Err(e) => format!("unknown ({e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};

    #[test]
    fn accepts_network_namespace_and_sets_cloexec() {
        let fd = OwnedFd::from(File::open("/proc/thread-self/ns/net").expect("network namespace"));
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::empty())).expect("simulate inherited FD");
        let netns = NetworkNamespace::from_fd(fd).expect("valid network namespace");
        let flags = fcntl(netns.as_raw(), FcntlArg::F_GETFD).expect("descriptor flags");
        assert_ne!(flags & FdFlag::FD_CLOEXEC.bits(), 0);
    }

    #[test]
    fn recognizes_the_current_namespace() {
        assert!(NetworkNamespace::current().unwrap().is_current().unwrap());
    }

    #[test]
    fn rejects_other_namespace_types() {
        for (name, kind) in [
            ("mnt", nix::libc::CLONE_NEWNS),
            ("user", nix::libc::CLONE_NEWUSER),
        ] {
            let result = NetworkNamespace::open(format!("/proc/thread-self/ns/{name}"));
            assert!(matches!(result, Err(NetnsError::WrongType(actual)) if actual == kind));
        }
    }

    #[test]
    fn rejects_non_namespace_descriptors() {
        for path in ["/dev/null", "/proc/self/status"] {
            assert!(matches!(
                NetworkNamespace::open(path),
                Err(NetnsError::Inspect(_))
            ));
        }
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        assert!(matches!(
            NetworkNamespace::from_fd(socket.into()),
            Err(NetnsError::Inspect(_))
        ));
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
