// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Character device nodes a container's `/dev` lacks, made from the device numbers sysfs gives.
//!
//! A container's `/dev` is a copy of the host's taken when the container was created. A node the
//! kernel creates later (vfio-pci binding a group, a devlink reload registering a verbs channel)
//! is in the host's `/dev` and not here, and a node whose device the kernel has since numbered
//! anew still names the old number.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::sys::stat::{Mode, SFlag, makedev, mknod};

/// A character device's number, as sysfs gives it in a device's `dev` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceNumber {
    /// The major number.
    pub major: u64,
    /// The minor number.
    pub minor: u64,
}

impl DeviceNumber {
    /// Read the number from a sysfs `dev` file (`major:minor`).
    ///
    /// # Errors
    ///
    /// [`DeviceNumberError::Unreadable`] if the file cannot be read, or
    /// [`DeviceNumberError::Malformed`] if it does not hold `major:minor`.
    pub fn read(path: &Path) -> Result<DeviceNumber, DeviceNumberError> {
        let contents =
            fs::read_to_string(path).map_err(|source| DeviceNumberError::Unreadable {
                path: path.to_path_buf(),
                source,
            })?;
        let malformed = || DeviceNumberError::Malformed {
            path: path.to_path_buf(),
            contents: contents.clone(),
        };
        let (major, minor) = contents.trim().split_once(':').ok_or_else(malformed)?;
        Ok(DeviceNumber {
            major: major.parse().map_err(|_| malformed())?,
            minor: minor.parse().map_err(|_| malformed())?,
        })
    }

    fn dev(self) -> nix::libc::dev_t {
        makedev(self.major, self.minor)
    }
}

impl fmt::Display for DeviceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// A device number sysfs would not give.
#[derive(Debug, thiserror::Error)]
pub enum DeviceNumberError {
    /// The `dev` file could not be read.
    #[error("cannot read a device number from {path}: {source}")]
    Unreadable {
        /// The sysfs file.
        path: PathBuf,
        /// Why reading failed.
        source: io::Error,
    },
    /// The `dev` file held something other than `major:minor`.
    #[error("{path} holds {contents:?}, not a major:minor device number")]
    Malformed {
        /// The sysfs file.
        path: PathBuf,
        /// What it held.
        contents: String,
    },
}

/// A node that could not be made.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The directory for the node could not be made.
    #[error("cannot create {path}: {source}")]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// Whatever had the node's name could not be removed.
    #[error("cannot remove {path}, which is not device {number}: {source}")]
    Remove {
        /// The node.
        path: PathBuf,
        /// The device it should have been.
        number: DeviceNumber,
        /// Why.
        source: io::Error,
    },
    /// The node could not be made.
    #[error("cannot create {path}: {source}")]
    Create {
        /// The node.
        path: PathBuf,
        /// Why.
        source: nix::Error,
    },
    /// The node was made, but its permissions could not be set.
    #[error("cannot set the permissions of {path}: {source}")]
    Permissions {
        /// The node.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// Something else took the node's name while it was being made.
    #[error("{path} appeared while it was being made, and is not device {number}")]
    Raced {
        /// The node.
        path: PathBuf,
        /// The device it should have been.
        number: DeviceNumber,
    },
}

/// What [`create`] and [`replace`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The node was already there (for [`replace`]: already the device asked for).
    Present,
    /// The node was made.
    Made,
}

/// Whether `path` is the character device `number` (following links, as an open would).
#[must_use]
pub fn is_char_device(path: &Path, number: DeviceNumber) -> bool {
    fs::metadata(path).is_ok_and(|m| m.file_type().is_char_device() && m.rdev() == number.dev())
}

/// Make `path` the character device `number` with exactly `permissions` (the umask does not
/// apply), unless something already has the name; that is left as it is.
///
/// # Errors
///
/// A [`NodeError`] if the node or its directory cannot be made.
pub fn create(path: &Path, number: DeviceNumber, permissions: u32) -> Result<Outcome, NodeError> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(Outcome::Present);
    }
    make(path, number, permissions, |_| Ok(Outcome::Present))
}

/// Make `path` the character device `number` with exactly `permissions` (the umask does not
/// apply), replacing whatever has the name unless it is already that device.
///
/// # Errors
///
/// A [`NodeError`] if the node or its directory cannot be made, what has the name cannot be
/// removed, or another device takes the name while this makes it.
pub fn replace(path: &Path, number: DeviceNumber, permissions: u32) -> Result<Outcome, NodeError> {
    if is_char_device(path, number) {
        return Ok(Outcome::Present);
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(NodeError::Remove {
                path: path.to_path_buf(),
                number,
                source,
            });
        }
    }
    // udev (on a shared `/dev`) may have made the node since it was removed.
    make(path, number, permissions, |path| {
        if is_char_device(path, number) {
            Ok(Outcome::Present)
        } else {
            Err(NodeError::Raced {
                path: path.to_path_buf(),
                number,
            })
        }
    })
}

/// Make the node; `exists` decides what a name taken in the meantime means.
fn make(
    path: &Path,
    number: DeviceNumber,
    permissions: u32,
    exists: impl FnOnce(&Path) -> Result<Outcome, NodeError>,
) -> Result<Outcome, NodeError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|source| NodeError::CreateDir {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    match mknod(
        path,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(permissions),
        number.dev(),
    ) {
        Ok(()) => {}
        Err(nix::Error::EEXIST) => return exists(path),
        Err(source) => {
            return Err(NodeError::Create {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(permissions)).map_err(|source| {
        NodeError::Permissions {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(Outcome::Made)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            let root = std::env::temp_dir().join(format!("devnode-{}", id::Id::<Dir>::new()));
            fs::create_dir(&root).unwrap();
            Dir(root)
        }
    }

    impl Dir {
        /// A fresh tmpfs, standing in for a container's `/dev`: device nodes open there, which
        /// they do not on the VM's root filesystem.
        fn tmpfs() -> Dir {
            let dir = Dir::new();
            nix::mount::mount(
                Some("tmpfs"),
                &dir.0,
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                None::<&str>,
            )
            .unwrap();
            dir
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_device_number_is_read_from_sysfs() {
        let dir = Dir::new();
        let dev = dir.0.join("dev");
        fs::write(&dev, "231:193\n").unwrap();
        assert_eq!(
            DeviceNumber::read(&dev).unwrap(),
            DeviceNumber {
                major: 231,
                minor: 193
            }
        );
    }

    #[test]
    fn a_malformed_device_number_is_an_error() {
        let dir = Dir::new();
        for contents in ["", "231\n", "231:x\n", "a:1\n"] {
            let dev = dir.0.join("dev");
            fs::write(&dev, contents).unwrap();
            assert!(
                matches!(
                    DeviceNumber::read(&dev),
                    Err(DeviceNumberError::Malformed { .. })
                ),
                "{contents:?}"
            );
        }
    }

    #[test]
    fn a_missing_device_number_is_unreadable() {
        let dir = Dir::new();
        assert!(matches!(
            DeviceNumber::read(&dir.0.join("dev")),
            Err(DeviceNumberError::Unreadable { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));
    }

    const NULL: DeviceNumber = DeviceNumber { major: 1, minor: 3 };

    #[test]
    fn a_link_to_the_device_is_the_device() {
        let dir = Dir::new();
        let node = dir.0.join("null");
        std::os::unix::fs::symlink("/dev/null", &node).unwrap();
        assert!(is_char_device(&node, NULL));
        assert!(!is_char_device(&node, DeviceNumber { major: 1, minor: 5 }));
        assert!(!is_char_device(&dir.0.join("missing"), NULL));
    }

    #[test]
    fn the_right_node_is_left_alone() {
        let dir = Dir::new();
        let node = dir.0.join("null");
        std::os::unix::fs::symlink("/dev/null", &node).unwrap();
        assert_eq!(replace(&node, NULL, 0o666).unwrap(), Outcome::Present);
        assert_eq!(create(&node, NULL, 0o600).unwrap(), Outcome::Present);
    }

    #[test]
    fn create_leaves_whatever_has_the_name() {
        let dir = Dir::new();
        let node = dir.0.join("taken");
        fs::write(&node, b"").unwrap();
        assert_eq!(create(&node, NULL, 0o600).unwrap(), Outcome::Present);
        assert!(node.is_file());
    }

    /// Without `CAP_MKNOD`, making the node fails, and the stale node is gone.
    #[test]
    fn a_stale_node_without_cap_mknod_is_an_error() {
        if caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_MKNOD).unwrap_or(true)
        {
            return;
        }
        let dir = Dir::new();
        let node = dir.0.join("stale");
        fs::write(&node, b"").unwrap();
        assert!(matches!(
            replace(&node, NULL, 0o666),
            Err(NodeError::Create {
                source: nix::Error::EPERM,
                ..
            })
        ));
        assert!(fs::symlink_metadata(&node).is_err());
    }

    /// A stale node is replaced by the device, with the permissions asked for whatever the
    /// umask, and opens.
    #[n_vm::test]
    fn a_stale_node_is_replaced_by_the_device() {
        nix::sys::stat::umask(Mode::from_bits_truncate(0o022));
        let dir = Dir::tmpfs();
        let node = dir.0.join("infiniband/uverbs0");
        fs::create_dir_all(node.parent().unwrap()).unwrap();
        // A node of the name that is another device.
        mknod(
            &node,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o600),
            makedev(1, 5),
        )
        .unwrap();
        assert_eq!(replace(&node, NULL, 0o666).unwrap(), Outcome::Made);
        assert!(is_char_device(&node, NULL));
        let mode = fs::symlink_metadata(&node).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o666);
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&node)
            .unwrap();
        assert_eq!(replace(&node, NULL, 0o666).unwrap(), Outcome::Present);
    }

    /// A missing node is made in a directory that is not there yet; one already there is left.
    #[n_vm::test]
    fn create_makes_a_missing_node() {
        nix::sys::stat::umask(Mode::from_bits_truncate(0o077));
        let dir = Dir::tmpfs();
        let node = dir.0.join("vfio/vfio");
        assert_eq!(create(&node, NULL, 0o600).unwrap(), Outcome::Made);
        assert!(is_char_device(&node, NULL));
        let mode = fs::symlink_metadata(&node).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(create(&node, NULL, 0o600).unwrap(), Outcome::Present);
    }
}
