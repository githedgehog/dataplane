//! Filesystem mount and unmount operations for the VM init process.

use std::path::Path;

use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount};
use nix::unistd::sync;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{MountError, UnmountError};

/// A single entry in the essential-filesystems mount table.
struct MountEntry {
    /// Filesystem source (e.g. `"proc"`, `"tmpfs"`, `"hugetlbfs"`).
    source: &'static str,
    /// Mount point path.
    target: &'static str,
    /// Filesystem type.
    fstype: &'static str,
    /// Optional comma-separated mount data (e.g. `"mode=0600,size=5%"`).
    data: Option<&'static str>,
    /// Whether to create the target directory before mounting.
    create_target: bool,
    /// Whether mount failure should be logged and ignored.
    optional: bool,
}

/// The filesystems that must be mounted before the test process can run.
const ESSENTIAL_MOUNTS: &[MountEntry] = &[
    MountEntry {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        data: None,
        create_target: false,
        optional: false,
    },
    MountEntry {
        source: "sysfs",
        target: "/sys",
        fstype: "sysfs",
        data: None,
        create_target: false,
        optional: false,
    },
    MountEntry {
        source: "tmpfs",
        target: "/tmp",
        fstype: "tmpfs",
        data: Some("mode=0600,size=5%"),
        create_target: false,
        optional: false,
    },
    MountEntry {
        source: "tmpfs",
        target: "/run",
        fstype: "tmpfs",
        data: Some("mode=0600,size=5%"),
        create_target: false,
        optional: false,
    },
    // Hugetlbfs page sizes are optional because guest CPU support varies.
    MountEntry {
        source: "hugetlbfs",
        target: "/run/huge/2MiB",
        fstype: "hugetlbfs",
        data: Some("pagesize=2M"),
        create_target: true,
        optional: true,
    },
    MountEntry {
        source: "hugetlbfs",
        target: "/run/huge/1GiB",
        fstype: "hugetlbfs",
        data: Some("pagesize=1G"),
        create_target: true,
        optional: true,
    },
    MountEntry {
        source: "cgroup2",
        target: "/sys/fs/cgroup",
        fstype: "cgroup2",
        data: Some("nsdelegate,memory_recursiveprot"),
        create_target: false,
        optional: false,
    },
];

/// Maximum number of `EBUSY` retries per mount point before giving up.
const UMOUNT_MAX_EBUSY_RETRIES: u32 = 1_000;

/// Mounts the essential virtual filesystems required by the guest OS.
///
/// # Errors
///
/// Returns a [`MountError`] if any **non-optional** mount syscall (or
/// preparatory `mkdir`) fails.
pub fn mount_essential_filesystems() -> Result<(), MountError> {
    for entry in ESSENTIAL_MOUNTS {
        match secure_mount(entry) {
            Ok(()) => {}
            Err(e) if entry.optional => {
                warn!("optional mount {} failed ({}); skipping", entry.target, e,);
            }
            Err(e) => return Err(e),
        }
    }
    debug!("all essential filesystems mounted successfully");
    Ok(())
}

/// Performs a single mount with security flags, optionally creating the
/// target directory first.
fn secure_mount(entry: &MountEntry) -> Result<(), MountError> {
    let MountEntry {
        source,
        target,
        fstype,
        data,
        create_target,
        optional: _,
    } = entry;
    let target_path: &'static Path = Path::new(*target);

    if *create_target {
        debug!("creating mount point {}", target_path.display());
        std::fs::create_dir_all(*target).map_err(|e| {
            let errno = e
                .raw_os_error()
                .map_or(Errno::UnknownErrno, Errno::from_raw);
            MountError::Failed {
                target: target_path,
                source: errno,
            }
        })?;
    }

    debug!("mounting {}", target_path.display());
    mount(
        Some(*source),
        *target,
        Some(*fstype),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        *data,
    )
    .map_err(|e| match e {
        Errno::UnknownErrno => MountError::Unknown {
            target: target_path,
        },
        Errno::EPERM => MountError::PermissionDenied {
            target: target_path,
        },
        other => MountError::Failed {
            target: target_path,
            source: other,
        },
    })
}

/// Unmounts all [`ESSENTIAL_MOUNTS`] in reverse order.
///
/// # Errors
///
/// Returns an [`UnmountError`] on `EINVAL`, unexpected errors, or if
/// retries are exhausted for a busy mount point.
#[tracing::instrument(level = "info")]
pub fn unmount_filesystems() -> Result<(), UnmountError> {
    debug!("syncing filesystems");
    sync();
    debug!("umounting filesystems");
    for entry in ESSENTIAL_MOUNTS.iter().rev() {
        let mount_point = Path::new(entry.target);
        match unmount_one(mount_point) {
            Ok(()) => {}
            Err(UnmountError::NotMounted { .. }) if entry.optional => {
                debug!(
                    "optional mount {} was not mounted; skipping unmount",
                    mount_point.display(),
                );
            }
            Err(e) => return Err(e),
        }
    }
    debug!("filesystem umounting completed");
    debug!("final sync");
    sync();
    Ok(())
}

/// Unmounts a single mount point, retrying on `EBUSY`.
fn unmount_one(mount_point: &'static Path) -> Result<(), UnmountError> {
    debug!("umounting {}", mount_point.display());
    sync();
    let mut attempts: u32 = 0;
    loop {
        match nix::mount::umount2(
            mount_point,
            MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW,
        ) {
            Ok(()) => {
                debug!("successfully unmounted {}", mount_point.display());
                sync();
                return Ok(());
            }
            Err(Errno::EBUSY) => {
                attempts += 1;
                if attempts >= UMOUNT_MAX_EBUSY_RETRIES {
                    return Err(UnmountError::BusyExhausted {
                        target: mount_point,
                        attempts,
                    });
                }
                if attempts.is_multiple_of(100) {
                    warn!(
                        "{} still busy after {attempts} retries",
                        mount_point.display(),
                    );
                }
                sync();
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(Errno::EINVAL) => {
                return Err(UnmountError::NotMounted {
                    target: mount_point,
                });
            }
            Err(e) => {
                return Err(UnmountError::Failed {
                    target: mount_point,
                    source: e,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_targets_are_all_absolute_paths() {
        for entry in ESSENTIAL_MOUNTS {
            assert!(
                entry.target.starts_with('/'),
                "mount target should be absolute: {:?}",
                entry.target,
            );
        }
    }

    #[test]
    fn mount_targets_have_no_duplicates() {
        let mut targets: Vec<&str> = ESSENTIAL_MOUNTS.iter().map(|e| e.target).collect();
        let original_len = targets.len();
        targets.sort();
        targets.dedup();
        assert_eq!(
            targets.len(),
            original_len,
            "ESSENTIAL_MOUNTS contains duplicate targets",
        );
    }

    #[test]
    fn child_mount_points_appear_after_their_parents() {
        for (i, entry) in ESSENTIAL_MOUNTS.iter().enumerate() {
            let target = entry.target;
            for (j, other) in ESSENTIAL_MOUNTS.iter().enumerate() {
                if i == j {
                    continue;
                }
                let is_child = target.starts_with(other.target)
                    && target != other.target
                    && target.as_bytes().get(other.target.len()) == Some(&b'/');
                if is_child {
                    assert!(
                        j < i,
                        "mount target {target:?} is a child of {:?}, \
                         but the parent appears at index {j} (after child at index {i})",
                        other.target,
                    );
                }
            }
        }
    }

    #[test]
    fn hugetlbfs_entries_are_optional() {
        for entry in ESSENTIAL_MOUNTS.iter().filter(|e| e.fstype == "hugetlbfs") {
            assert!(
                entry.optional,
                "hugetlbfs mount at {:?} should be optional",
                entry.target,
            );
        }
    }

    #[test]
    fn hugetlbfs_entries_require_create_target() {
        for entry in ESSENTIAL_MOUNTS.iter().filter(|e| e.fstype == "hugetlbfs") {
            assert!(
                entry.create_target,
                "hugetlbfs mount at {:?} should have create_target = true",
                entry.target,
            );
        }
    }

    #[test]
    fn create_target_entries_are_children_of_writable_mounts() {
        let writable_targets: Vec<&str> = ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "tmpfs")
            .map(|e| e.target)
            .collect();

        for entry in ESSENTIAL_MOUNTS.iter().filter(|e| e.create_target) {
            let has_writable_parent = writable_targets.iter().any(|parent| {
                entry.target.starts_with(parent)
                    && entry.target != *parent
                    && entry.target.as_bytes().get(parent.len()) == Some(&b'/')
            });
            assert!(
                has_writable_parent,
                "mount {:?} has create_target = true but is not a child \
                 of any tmpfs mount; the directory cannot be created at runtime",
                entry.target,
            );
        }
    }

    #[test]
    fn hugetlbfs_mounts_cover_both_page_sizes() {
        let hugetlb: Vec<&str> = ESSENTIAL_MOUNTS
            .iter()
            .filter(|e| e.fstype == "hugetlbfs")
            .map(|e| e.target)
            .collect();
        assert!(
            hugetlb.contains(&"/run/huge/2MiB"),
            "missing 2 MiB hugetlbfs mount; got: {hugetlb:?}",
        );
        assert!(
            hugetlb.contains(&"/run/huge/1GiB"),
            "missing 1 GiB hugetlbfs mount; got: {hugetlb:?}",
        );
    }

    #[test]
    fn hugetlbfs_pagesize_matches_mount_point() {
        for entry in ESSENTIAL_MOUNTS.iter().filter(|e| e.fstype == "hugetlbfs") {
            let data = entry
                .data
                .unwrap_or_else(|| panic!("hugetlbfs mount {:?} has no data", entry.target));
            if entry.target.contains("2MiB") {
                assert!(
                    data.contains("pagesize=2M"),
                    "2MiB hugetlbfs mount should have pagesize=2M, got: {data}",
                );
            } else if entry.target.contains("1GiB") {
                assert!(
                    data.contains("pagesize=1G"),
                    "1GiB hugetlbfs mount should have pagesize=1G, got: {data}",
                );
            }
        }
    }
}
