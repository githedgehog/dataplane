// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Descriptor-owned network namespaces for the DPDK datapath.
//!
//! Init creates the namespace and passes its descriptor across `exec`. The descriptor keeps it
//! alive without a bind mount under `/run/netns`; the kernel destroys it after the last reference
//! is released. Destruction returns physical devices to the host and may reload their drivers.
//!
//! The datapath thread enters the namespace before creating EAL and its workers. Management
//! threads stay in the host namespace. For mlx5, [`NetworkNamespace::enter_with_sysfs`] also mounts
//! a private sysfs so libibverbs enumerates devices in the destination namespace.

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

    /// Take ownership of a descriptor that already refers to a network namespace.
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
