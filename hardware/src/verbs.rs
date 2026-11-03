// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Locate and check the libibverbs command channel for a bifurcated mlx5 function.
//!
//! libibverbs finds the RDMA device in `class/infiniband`, its channel in `infiniband_verbs/uverbsN`,
//! and opens `/dev/infiniband/uverbsN`.
//! Exclusive RDMA mode (`ib_core.netns_mode=0`) exposes only the sysfs mount's network namespace.
//! Use [`enter_with_sysfs`](crate::netns::NetworkNamespace::enter_with_sysfs) for the datapath view.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::devnode::{self, DeviceNumber, DeviceNumberError};
use crate::pci::address::PciAddress;

/// Where libibverbs looks: sysfs for devices, `/dev` for their command channels' nodes.
#[derive(Debug, Clone)]
pub struct Roots {
    /// sysfs.
    pub sys: PathBuf,
    /// `/dev`.
    pub dev: PathBuf,
}

impl Roots {
    /// The calling thread's `/sys` and `/dev`.
    #[must_use]
    pub fn current() -> Roots {
        Roots {
            sys: PathBuf::from("/sys"),
            dev: PathBuf::from("/dev"),
        }
    }
}

/// A function's verbs command channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    /// Where libibverbs opens the channel.
    pub node: PathBuf,
    /// The channel's device number, from sysfs.
    pub number: DeviceNumber,
}

/// Why libibverbs cannot reach a function (yet).
#[derive(Debug, thiserror::Error)]
pub enum Unreachable {
    /// No RDMA device for the function is in this namespace.
    #[error("{address} has no RDMA device in this network namespace")]
    NoDevice {
        /// The function.
        address: PciAddress,
    },
    /// The RDMA devices could not be listed.
    #[error("cannot list RDMA devices in {path}: {source}")]
    ListDevices {
        /// The sysfs directory.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// The function's RDMA device has no verbs command channel.
    #[error("RDMA device {device:?} of {address} has no verbs command channel")]
    NoChannel {
        /// The function.
        address: PciAddress,
        /// Its RDMA device.
        device: OsString,
    },
    /// The RDMA device's command channels could not be listed.
    #[error("cannot list the verbs command channels in {path}: {source}")]
    ListChannels {
        /// The sysfs directory.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// The command channel's device number could not be read.
    #[error(transparent)]
    Number(DeviceNumberError),
    /// The channel's node is missing, or is another device.
    #[error("{} is missing or is not device {}", .channel.node.display(), .channel.number)]
    NoNode {
        /// The channel.
        channel: Channel,
    },
    /// The channel's node is the channel, but does not open.
    #[error("{} does not open: {source}", .node.display())]
    Unopenable {
        /// The node.
        node: PathBuf,
        /// Why.
        source: io::Error,
    },
}

impl Unreachable {
    /// Whether the kernel may yet fix this by itself: an RDMA device a devlink reload has not
    /// registered yet, in part or at all. A missing node is not one; nothing makes it in a
    /// container's `/dev` (see [`devnode`]).
    #[must_use]
    pub fn is_pending(&self) -> bool {
        match self {
            Unreachable::NoDevice { .. } | Unreachable::NoChannel { .. } => true,
            // Removed between listing the channel and reading its number.
            Unreachable::Number(DeviceNumberError::Unreadable { source, .. })
            | Unreachable::ListChannels { source, .. } => source.kind() == io::ErrorKind::NotFound,
            Unreachable::ListDevices { .. }
            | Unreachable::Number(DeviceNumberError::Malformed { .. })
            | Unreachable::NoNode { .. }
            | Unreachable::Unopenable { .. } => false,
        }
    }
}

/// The verbs command channel of `address`'s RDMA device, as sysfs under `roots` gives it.
///
/// # Errors
///
/// An [`Unreachable`] saying what of the device or channel sysfs lacks.
pub fn channel(roots: &Roots, address: PciAddress) -> Result<Channel, Unreachable> {
    let device = rdma_device(&roots.sys, address)?;
    let channels = roots
        .sys
        .join("class/infiniband")
        .join(&device)
        .join("device/infiniband_verbs");
    let entries = match fs::read_dir(&channels) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Unreachable::NoChannel { address, device });
        }
        Err(source) => {
            return Err(Unreachable::ListChannels {
                path: channels,
                source,
            });
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| Unreachable::ListChannels {
            path: channels.clone(),
            source,
        })?;
        names.push(entry.file_name());
    }
    // A device has one; take the first by name so the answer does not depend on listing order.
    names.sort();
    let Some(name) = names.into_iter().next() else {
        return Err(Unreachable::NoChannel { address, device });
    };
    let number =
        DeviceNumber::read(&channels.join(&name).join("dev")).map_err(Unreachable::Number)?;
    Ok(Channel {
        node: roots.dev.join("infiniband").join(name),
        number,
    })
}

/// Whether libibverbs can open `address`'s command channel from `roots`.
///
/// # Errors
///
/// An [`Unreachable`] saying how far it gets.
pub fn reachable(roots: &Roots, address: PciAddress) -> Result<Channel, Unreachable> {
    let channel = channel(roots, address)?;
    open(channel)
}

/// Whether `channel`'s node is the channel, and opens.
///
/// # Errors
///
/// [`Unreachable::NoNode`] or [`Unreachable::Unopenable`].
pub fn open(channel: Channel) -> Result<Channel, Unreachable> {
    if !devnode::is_char_device(&channel.node, channel.number) {
        return Err(Unreachable::NoNode { channel });
    }
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open(&channel.node)
    {
        Ok(_) => Ok(channel),
        Err(source) => Err(Unreachable::Unopenable {
            node: channel.node,
            source,
        }),
    }
}

/// The RDMA device under `sys` whose parent is `address`.
fn rdma_device(sys: &Path, address: PciAddress) -> Result<OsString, Unreachable> {
    let devices = sys.join("class/infiniband");
    let entries = match fs::read_dir(&devices) {
        Ok(entries) => entries,
        // ib_core is not loaded, or has registered nothing yet.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Unreachable::NoDevice { address });
        }
        Err(source) => {
            return Err(Unreachable::ListDevices {
                path: devices,
                source,
            });
        }
    };
    let wanted = address.to_string();
    for entry in entries {
        let entry = entry.map_err(|source| Unreachable::ListDevices {
            path: devices.clone(),
            source,
        })?;
        // A device being unregistered as this looks has no parent link left; it is not ours.
        let parent = fs::read_link(entry.path().join("device")).ok();
        if parent.as_deref().and_then(Path::file_name) == Some(wanted.as_ref()) {
            return Ok(entry.file_name());
        }
    }
    Err(Unreachable::NoDevice { address })
}

/// A sysfs and `/dev` with one function at [`fake::FUNCTION`], and its RDMA device and command
/// channel as asked for; for tests of this module's callers too.
#[cfg(any(test, feature = "test_fakes"))]
#[allow(clippy::unwrap_used)] // A fake that cannot be built fails the test using it.
pub mod fake {
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::Roots;
    use crate::pci::address::PciAddress;

    /// The function's address.
    pub const FUNCTION: &str = "0000:02:00.0";

    /// See the [module](self).
    pub struct Fake {
        /// The directory holding `sys` and `dev`.
        pub root: PathBuf,
    }

    impl Fake {
        /// A function with no RDMA device.
        ///
        /// # Panics
        ///
        /// If the directories cannot be made.
        #[must_use]
        pub fn new() -> Fake {
            let root = std::env::temp_dir().join(format!("verbs-{}", id::Id::<Fake>::new()));
            let function = root.join("sys/devices/pci0000:00").join(FUNCTION);
            std::fs::create_dir_all(&function).unwrap();
            std::fs::create_dir_all(root.join("sys/bus/pci/devices")).unwrap();
            std::fs::create_dir_all(root.join("sys/class/infiniband")).unwrap();
            std::fs::create_dir_all(root.join("dev/infiniband")).unwrap();
            symlink(&function, root.join("sys/bus/pci/devices").join(FUNCTION)).unwrap();
            Fake { root }
        }

        /// The function's address.
        ///
        /// # Panics
        ///
        /// Never; [`FUNCTION`] is an address.
        #[must_use]
        pub fn address() -> PciAddress {
            PciAddress::try_from(FUNCTION).unwrap()
        }

        fn function(&self) -> PathBuf {
            self.root.join("sys/devices/pci0000:00").join(FUNCTION)
        }

        /// Bind the function to the driver `name`.
        ///
        /// # Panics
        ///
        /// If the files cannot be made.
        #[must_use]
        pub fn driver(self, name: &str) -> Fake {
            let driver = self.root.join("sys/bus/pci/drivers").join(name);
            std::fs::create_dir_all(&driver).unwrap();
            symlink(driver, self.function().join("driver")).unwrap();
            self
        }

        /// Register the function's RDMA device, `mlx5_0`.
        ///
        /// # Panics
        ///
        /// If the files cannot be made.
        #[must_use]
        pub fn rdma_device(self) -> Fake {
            let device = self.function().join("infiniband/mlx5_0");
            std::fs::create_dir_all(&device).unwrap();
            symlink(self.function(), device.join("device")).unwrap();
            symlink(&device, self.root.join("sys/class/infiniband/mlx5_0")).unwrap();
            self
        }

        /// Give the device the command channel `uverbs0`, numbered `number` (`major:minor`).
        /// `/dev/null`'s number, 1:3, is one a test can open.
        ///
        /// # Panics
        ///
        /// If the files cannot be made.
        #[must_use]
        pub fn channel(self, number: &str) -> Fake {
            let channel = self.function().join("infiniband_verbs/uverbs0");
            std::fs::create_dir_all(&channel).unwrap();
            std::fs::write(channel.join("dev"), format!("{number}\n")).unwrap();
            self
        }

        /// Make the channel's node `/dev/null`, through a link.
        ///
        /// # Panics
        ///
        /// If the link cannot be made.
        #[must_use]
        pub fn node(self) -> Fake {
            let node = self.root.join("dev/infiniband/uverbs0");
            let _ = std::fs::remove_file(&node);
            symlink("/dev/null", node).unwrap();
            self
        }

        /// Give the channel's node's name to a plain file.
        ///
        /// # Panics
        ///
        /// If the file cannot be made.
        #[must_use]
        pub fn stale_node(self) -> Fake {
            std::fs::write(self.root.join("dev/infiniband/uverbs0"), b"").unwrap();
            self
        }

        /// Where the fake's sysfs and `/dev` are.
        #[must_use]
        pub fn roots(&self) -> Roots {
            Roots {
                sys: self.root.join("sys"),
                dev: self.root.join("dev"),
            }
        }
    }

    impl Default for Fake {
        fn default() -> Self {
            Fake::new()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;

    const NULL: DeviceNumber = DeviceNumber { major: 1, minor: 3 };

    #[test]
    fn a_function_without_an_rdma_device_is_pending() {
        let fake = Fake::new();
        let e = reachable(&fake.roots(), Fake::address()).unwrap_err();
        assert!(matches!(e, Unreachable::NoDevice { .. }), "{e}");
        assert!(e.is_pending());
    }

    #[test]
    fn no_infiniband_class_is_no_device() {
        let fake = Fake::new();
        std::fs::remove_dir(fake.root.join("sys/class/infiniband")).unwrap();
        let e = reachable(&fake.roots(), Fake::address()).unwrap_err();
        assert!(matches!(e, Unreachable::NoDevice { .. }), "{e}");
    }

    #[test]
    fn an_rdma_device_of_another_function_does_not_count() {
        let fake = Fake::new();
        let other = fake.root.join("sys/devices/pci0000:00/0000:02:00.1");
        let device = other.join("infiniband/mlx5_1");
        std::fs::create_dir_all(&device).unwrap();
        std::os::unix::fs::symlink(&other, device.join("device")).unwrap();
        std::os::unix::fs::symlink(&device, fake.root.join("sys/class/infiniband/mlx5_1")).unwrap();
        let e = reachable(&fake.roots(), Fake::address()).unwrap_err();
        assert!(matches!(e, Unreachable::NoDevice { .. }), "{e}");
    }

    #[test]
    fn an_rdma_device_without_a_channel_is_pending() {
        let fake = Fake::new().rdma_device();
        let e = reachable(&fake.roots(), Fake::address()).unwrap_err();
        assert!(matches!(e, Unreachable::NoChannel { .. }), "{e}");
        assert!(e.is_pending());
    }

    /// A malformed number will not get better by waiting.
    #[test]
    fn a_malformed_channel_number_is_not_pending() {
        let fake = Fake::new().rdma_device().channel("garbage");
        let e = reachable(&fake.roots(), Fake::address()).unwrap_err();
        assert!(
            matches!(e, Unreachable::Number(DeviceNumberError::Malformed { .. })),
            "{e}"
        );
        assert!(!e.is_pending());
    }

    /// The container's `/dev` may lack the channel's node, or have its name on another device:
    /// either way the node is to be made, with the number sysfs gives.
    #[test]
    fn a_missing_or_stale_node_is_named_with_its_number() {
        let other = DeviceNumber {
            major: 231,
            minor: 193,
        };
        for (fake, number) in [
            (Fake::new().rdma_device().channel("1:3"), NULL),
            (Fake::new().rdma_device().channel("1:3").stale_node(), NULL),
            // The node is /dev/null, but the channel now has another number.
            (Fake::new().rdma_device().channel("231:193").node(), other),
        ] {
            let e = reachable(&fake.roots(), Fake::address()).unwrap_err();
            let Unreachable::NoNode { channel } = &e else {
                panic!("{e}");
            };
            assert_eq!(
                *channel,
                Channel {
                    node: fake.root.join("dev/infiniband/uverbs0"),
                    number,
                }
            );
            assert!(!e.is_pending());
        }
    }

    #[test]
    fn a_device_with_an_open_channel_is_reachable() {
        let fake = Fake::new().rdma_device().channel("1:3").node();
        let channel = reachable(&fake.roots(), Fake::address()).unwrap();
        assert_eq!(channel.number, NULL);
    }
}
