// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Validate VFIO IOMMU groups before changing driver bindings, and give this process the VFIO
//! device nodes the bindings create.
//! Failed binds can leave devices unbound.

use std::fs;
use std::path::{Path, PathBuf};

use nix::sys::stat::{Mode, SFlag, makedev, mknod};

use hardware::pci::address::PciAddress;

/// Non-VFIO drivers with `driver_managed_dma`.
const GROUP_SAFE_DRIVERS: [&str; 2] = ["pci-stub", "pcieport"];

/// Kernel name for synthetic VFIO no-IOMMU groups.
const NOIOMMU_GROUP_NAME: &str = "vfio-noiommu";

/// An IOMMU condition that prevents VFIO use.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VfioBlocker {
    /// The device has no IOMMU group.
    #[error(
        "{address} is in no IOMMU group, so vfio-pci cannot bind it: the machine has no IOMMU, \
         or it is off (intel_iommu=on or amd_iommu=on), or this is a VM without a virtual IOMMU"
    )]
    NoIommu {
        /// The device.
        address: PciAddress,
    },
    /// No-IOMMU mode is enabled but incompatible with IOVA as VA.
    #[error(
        "{address} is in no IOMMU group. vfio's no-IOMMU mode is on, but the dataplane runs DPDK \
         with IOVA as VA, which needs a real IOMMU: enable it (intel_iommu=on or amd_iommu=on, \
         or give the VM a virtual IOMMU)"
    )]
    NoIommuIovaVa {
        /// The device.
        address: PciAddress,
    },
    /// A synthetic no-IOMMU group cannot support IOVA as VA.
    #[error(
        "{address} is already bound to vfio-pci in no-IOMMU mode (its IOMMU group {group} is \
         vfio's stand-in, with no IOMMU behind it), but the dataplane runs DPDK with IOVA as VA, \
         which needs a real IOMMU: unbind it, and enable the IOMMU (intel_iommu=on or \
         amd_iommu=on, or give the VM a virtual IOMMU)"
    )]
    NoIommuGroup {
        /// The device.
        address: PciAddress,
        /// Its synthetic IOMMU group.
        group: String,
    },
    /// A group member has an incompatible driver.
    #[error(
        "{address} shares IOMMU group {group} with {member}, which is bound to {driver}; \
         vfio-pci only hands over a whole group, so {member} must be unbound or moved to its own \
         group (on a VM, its own PCIe slot rather than behind a shared PCI bridge)"
    )]
    SharedGroup {
        /// The device.
        address: PciAddress,
        /// Its IOMMU group.
        group: String,
        /// The other device in the group, as sysfs names it.
        member: String,
        /// The driver `member` is bound to.
        driver: String,
    },
    /// The group's members could not be listed.
    #[error("cannot list the devices in {address}'s IOMMU group {group}: {source}")]
    Unreadable {
        /// The device.
        address: PciAddress,
        /// Its IOMMU group.
        group: String,
        /// Why listing failed.
        source: std::io::Error,
    },
}

/// Check IOMMU groups under `sys`.
/// Include all devices to be bound; they may share a group.
pub(crate) fn blockers(sys: &Path, devices: &[PciAddress]) -> Vec<VfioBlocker> {
    let mut problems = Vec::new();
    for &address in devices {
        let link = sys
            .join("bus/pci/devices")
            .join(address.to_string())
            .join("iommu_group");
        let Ok(target) = fs::read_link(&link) else {
            problems.push(no_group(sys, address));
            continue;
        };
        let group = file_name(&target);
        // A synthetic group does not provide DMA translation.
        if fs::read_to_string(link.join("name")).is_ok_and(|n| n.trim() == NOIOMMU_GROUP_NAME) {
            problems.push(VfioBlocker::NoIommuGroup { address, group });
            continue;
        }
        let members = match fs::read_dir(link.join("devices")) {
            Ok(members) => members,
            Err(source) => {
                problems.push(VfioBlocker::Unreadable {
                    address,
                    group,
                    source,
                });
                continue;
            }
        };
        for member in members.flatten() {
            let name = member.file_name().to_string_lossy().into_owned();
            if PciAddress::try_from(name.as_str()).is_ok_and(|m| devices.contains(&m)) {
                continue;
            }
            // No driver link: unbound, which vfio accepts.
            let Ok(driver) = fs::read_link(member.path().join("driver")) else {
                continue;
            };
            let driver = file_name(&driver);
            if !group_safe(&driver) {
                problems.push(VfioBlocker::SharedGroup {
                    address,
                    group: group.clone(),
                    member: name,
                    driver,
                });
            }
        }
    }
    problems
}

/// Drivers compatible with VFIO group assignment, including VFIO PCI variants.
fn group_safe(driver: &str) -> bool {
    driver == "vfio-pci" || driver.ends_with("_vfio_pci") || GROUP_SAFE_DRIVERS.contains(&driver)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
}

/// A VFIO character device the kernel has, and the `/dev` this process sees does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MissingNode {
    /// Where the node belongs.
    pub(crate) path: PathBuf,
    /// The device number sysfs gives for it.
    pub(crate) major: u64,
    /// The device number sysfs gives for it.
    pub(crate) minor: u64,
}

/// A VFIO device node that could not be found or made.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DeviceNodeError {
    /// The device is bound to vfio-pci but has no IOMMU group.
    #[error("{address} is bound to vfio-pci but is in no IOMMU group")]
    NoGroup {
        /// The device.
        address: PciAddress,
    },
    /// sysfs does not say which device number the node has.
    #[error("cannot read the device number of {node} from {path}: {source}")]
    Unreadable {
        /// The node.
        node: PathBuf,
        /// Where sysfs keeps its number.
        path: PathBuf,
        /// Why reading failed.
        source: std::io::Error,
    },
    /// sysfs gave something other than `major:minor`.
    #[error("{path} holds {contents:?}, not a major:minor device number")]
    Malformed {
        /// The sysfs file.
        path: PathBuf,
        /// What it held.
        contents: String,
    },
    /// The node could not be made.
    #[error("cannot create {path}: {source}")]
    Create {
        /// The node.
        path: PathBuf,
        /// Why.
        source: nix::Error,
    },
    /// The directory for the node could not be made.
    #[error("cannot create {path}: {source}")]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
}

/// The VFIO nodes that DPDK needs to open `devices`, once they are bound to vfio-pci, and that
/// are missing from `dev`.
///
/// A container's `/dev` is filled in when the container starts, and later device nodes do not
/// appear in it. vfio-pci creates a group's node when it binds the group's first device, which
/// this process does from inside the container, so on the first start after boot the node is in
/// the host's `/dev` and not here: DPDK fails to open the group and skips the device as not
/// managed by vfio. The container node, `vfio/vfio`, is included in case vfio itself loaded late.
pub(crate) fn missing_nodes(
    sys: &Path,
    dev: &Path,
    devices: &[PciAddress],
) -> Result<Vec<MissingNode>, DeviceNodeError> {
    let mut wanted = vec![(dev.join("vfio/vfio"), sys.join("class/misc/vfio/dev"))];
    for &address in devices {
        let link = sys
            .join("bus/pci/devices")
            .join(address.to_string())
            .join("iommu_group");
        let group = fs::read_link(&link).map_err(|_| DeviceNodeError::NoGroup { address })?;
        let group = file_name(&group);
        let node = dev.join("vfio").join(&group);
        if !wanted.iter().any(|(path, _)| *path == node) {
            wanted.push((node, sys.join("class/vfio").join(&group).join("dev")));
        }
    }
    let mut missing = Vec::new();
    for (path, number) in wanted {
        if fs::symlink_metadata(&path).is_ok() {
            continue;
        }
        let contents =
            fs::read_to_string(&number).map_err(|source| DeviceNodeError::Unreadable {
                node: path.clone(),
                path: number.clone(),
                source,
            })?;
        let malformed = || DeviceNodeError::Malformed {
            path: number.clone(),
            contents: contents.clone(),
        };
        let (major, minor) = contents.trim().split_once(':').ok_or_else(malformed)?;
        missing.push(MissingNode {
            path,
            major: major.parse().map_err(|_| malformed())?,
            minor: minor.parse().map_err(|_| malformed())?,
        });
    }
    Ok(missing)
}

/// Make `nodes`, readable and writable by root only, as the kernel makes them.
///
/// A node that has appeared since it was found missing is left as it is.
pub(crate) fn create_nodes(nodes: &[MissingNode]) -> Result<(), DeviceNodeError> {
    for node in nodes {
        if let Some(dir) = node.path.parent() {
            fs::create_dir_all(dir).map_err(|source| DeviceNodeError::CreateDir {
                path: dir.to_path_buf(),
                source,
            })?;
        }
        match mknod(
            &node.path,
            SFlag::S_IFCHR,
            Mode::S_IRUSR | Mode::S_IWUSR,
            makedev(node.major, node.minor),
        ) {
            Ok(()) | Err(nix::Error::EEXIST) => {}
            Err(source) => {
                return Err(DeviceNodeError::Create {
                    path: node.path.clone(),
                    source,
                });
            }
        }
    }
    Ok(())
}

/// Diagnose a missing IOMMU group.
fn no_group(sys: &Path, address: PciAddress) -> VfioBlocker {
    let noiommu = fs::read_to_string(sys.join("module/vfio/parameters/enable_unsafe_noiommu_mode"))
        .is_ok_and(|v| v.trim() == "Y");
    if noiommu {
        VfioBlocker::NoIommuIovaVa { address }
    } else {
        VfioBlocker::NoIommu { address }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::*;

    struct Sysfs(PathBuf);

    impl Sysfs {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("init-vfio-{}", id::Id::<Sysfs>::new()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn device(&self, address: &str) -> PathBuf {
            let path = self.0.join("bus/pci/devices").join(address);
            fs::create_dir_all(&path).unwrap();
            path
        }

        /// Reproduce sysfs links between a group and its devices.
        fn group(&self, group: u32, members: &[&str]) {
            let dir = self.0.join("kernel/iommu_groups").join(group.to_string());
            fs::create_dir_all(dir.join("devices")).unwrap();
            for member in members {
                let device = self.device(member);
                symlink(&dir, device.join("iommu_group")).unwrap();
                symlink(&device, dir.join("devices").join(member)).unwrap();
            }
        }

        fn name_group(&self, group: u32, name: &str) {
            let dir = self.0.join("kernel/iommu_groups").join(group.to_string());
            fs::write(dir.join("name"), format!("{name}\n")).unwrap();
        }

        fn bind(&self, address: &str, driver: &str) {
            let dir = self.0.join("bus/pci/drivers").join(driver);
            fs::create_dir_all(&dir).unwrap();
            symlink(dir, self.device(address).join("driver")).unwrap();
        }

        /// The device number sysfs gives `group`'s VFIO node.
        fn vfio_group_dev(&self, group: u32, number: &str) {
            let dir = self.0.join("class/vfio").join(group.to_string());
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("dev"), format!("{number}\n")).unwrap();
        }

        /// The device number sysfs gives the VFIO container node.
        fn vfio_container_dev(&self, number: &str) {
            let dir = self.0.join("class/misc/vfio");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("dev"), format!("{number}\n")).unwrap();
        }

        fn noiommu(&self, on: bool) {
            let dir = self.0.join("module/vfio/parameters");
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("enable_unsafe_noiommu_mode"),
                if on { "Y\n" } else { "N\n" },
            )
            .unwrap();
        }
    }

    impl Drop for Sysfs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pci(address: &str) -> PciAddress {
        PciAddress::try_from(address).unwrap()
    }

    #[test]
    fn devices_in_their_own_groups_can_be_bound() {
        let sys = Sysfs::new();
        sys.group(6, &["0000:00:11.0"]);
        sys.group(7, &["0000:00:12.0"]);
        sys.bind("0000:00:11.0", "e1000");
        assert!(blockers(&sys.0, &[pci("0000:00:11.0"), pci("0000:00:12.0")]).is_empty());
    }

    #[test]
    fn a_device_without_a_group_is_refused() {
        let sys = Sysfs::new();
        sys.device("0000:02:01.0");
        let problems = blockers(&sys.0, &[pci("0000:02:01.0")]);
        assert!(
            matches!(problems.as_slice(), [VfioBlocker::NoIommu { .. }]),
            "{problems:?}"
        );
    }

    #[test]
    fn noiommu_mode_does_not_help_iova_as_va() {
        let sys = Sysfs::new();
        sys.device("0000:02:01.0");
        sys.noiommu(true);
        let problems = blockers(&sys.0, &[pci("0000:02:01.0")]);
        assert!(
            matches!(problems.as_slice(), [VfioBlocker::NoIommuIovaVa { .. }]),
            "{problems:?}"
        );

        sys.noiommu(false);
        let problems = blockers(&sys.0, &[pci("0000:02:01.0")]);
        assert!(
            matches!(problems.as_slice(), [VfioBlocker::NoIommu { .. }]),
            "{problems:?}"
        );
    }

    /// Management and dataplane NICs share a PCI bridge and IOMMU group.
    #[test]
    fn a_group_shared_with_a_bound_device_is_refused() {
        let sys = Sysfs::new();
        let group = [
            "0000:00:04.0",
            "0000:01:00.0",
            "0000:02:00.0",
            "0000:02:01.0",
            "0000:02:02.0",
        ];
        sys.group(4, &group);
        for nic in &group[2..] {
            sys.bind(nic, "e1000");
        }
        let problems = blockers(&sys.0, &[pci("0000:02:01.0"), pci("0000:02:02.0")]);
        assert_eq!(problems.len(), 2, "{problems:?}");
        for problem in &problems {
            assert!(
                matches!(
                    problem,
                    VfioBlocker::SharedGroup { group, member, driver, .. }
                        if group == "4" && member == "0000:02:00.0" && driver == "e1000"
                ),
                "{problem:?}"
            );
        }
    }

    #[test]
    fn group_members_vfio_accepts_do_not_block() {
        let sys = Sysfs::new();
        sys.group(
            4,
            &[
                "0000:00:1c.0",
                "0000:01:00.0",
                "0000:01:00.1",
                "0000:01:00.2",
            ],
        );
        sys.bind("0000:00:1c.0", "pcieport");
        sys.bind("0000:01:00.1", "vfio-pci");
        sys.bind("0000:01:00.2", "pci-stub");
        assert!(blockers(&sys.0, &[pci("0000:01:00.0")]).is_empty());
    }

    #[test]
    fn group_members_on_vfio_pci_variants_do_not_block() {
        let sys = Sysfs::new();
        sys.group(4, &["0000:01:00.0", "0000:01:00.1", "0000:01:00.2"]);
        sys.bind("0000:01:00.1", "mlx5_vfio_pci");
        sys.bind("0000:01:00.2", "virtio_vfio_pci");
        assert!(blockers(&sys.0, &[pci("0000:01:00.0")]).is_empty());
    }

    #[test]
    fn a_driver_named_like_vfio_still_blocks() {
        let sys = Sysfs::new();
        sys.group(4, &["0000:01:00.0", "0000:01:00.1"]);
        sys.bind("0000:01:00.1", "vfio_pci_helper");
        let problems = blockers(&sys.0, &[pci("0000:01:00.0")]);
        assert!(
            matches!(problems.as_slice(), [VfioBlocker::SharedGroup { driver, .. }] if driver == "vfio_pci_helper"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_device_already_bound_without_an_iommu_is_refused() {
        let sys = Sysfs::new();
        sys.group(0, &["0000:02:01.0"]);
        sys.name_group(0, "vfio-noiommu");
        sys.bind("0000:02:01.0", "vfio-pci");
        sys.noiommu(true);
        let problems = blockers(&sys.0, &[pci("0000:02:01.0")]);
        assert!(
            matches!(problems.as_slice(), [VfioBlocker::NoIommuGroup { group, .. }] if group == "0"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_named_group_with_an_iommu_can_be_bound() {
        let sys = Sysfs::new();
        sys.group(6, &["0000:00:11.0"]);
        sys.name_group(6, "some-platform-group");
        assert!(blockers(&sys.0, &[pci("0000:00:11.0")]).is_empty());
    }

    fn node(path: PathBuf, major: u64, minor: u64) -> MissingNode {
        MissingNode { path, major, minor }
    }

    #[test]
    fn nodes_missing_from_dev_are_found_with_their_numbers() {
        let sys = Sysfs::new();
        let dev = Sysfs::new();
        sys.group(9, &["0000:05:00.0"]);
        sys.vfio_group_dev(9, "246:0");
        sys.vfio_container_dev("10:196");
        assert_eq!(
            missing_nodes(&sys.0, &dev.0, &[pci("0000:05:00.0")]).unwrap(),
            vec![
                node(dev.0.join("vfio/vfio"), 10, 196),
                node(dev.0.join("vfio/9"), 246, 0),
            ]
        );
    }

    #[test]
    fn nodes_already_in_dev_are_left_alone() {
        let sys = Sysfs::new();
        let dev = Sysfs::new();
        sys.group(9, &["0000:05:00.0"]);
        sys.group(10, &["0000:06:00.0"]);
        sys.vfio_group_dev(9, "246:0");
        sys.vfio_group_dev(10, "246:1");
        sys.vfio_container_dev("10:196");
        fs::create_dir(dev.0.join("vfio")).unwrap();
        fs::write(dev.0.join("vfio/vfio"), "").unwrap();
        fs::write(dev.0.join("vfio/9"), "").unwrap();
        assert_eq!(
            missing_nodes(&sys.0, &dev.0, &[pci("0000:05:00.0"), pci("0000:06:00.0")]).unwrap(),
            vec![node(dev.0.join("vfio/10"), 246, 1)]
        );
    }

    #[test]
    fn devices_sharing_a_group_need_its_node_once() {
        let sys = Sysfs::new();
        let dev = Sysfs::new();
        sys.group(4, &["0000:01:00.0", "0000:01:00.1"]);
        sys.vfio_group_dev(4, "246:2");
        sys.vfio_container_dev("10:196");
        let missing =
            missing_nodes(&sys.0, &dev.0, &[pci("0000:01:00.0"), pci("0000:01:00.1")]).unwrap();
        assert_eq!(missing.len(), 2, "{missing:?}");
    }

    #[test]
    fn a_bound_device_without_a_group_is_an_error() {
        let sys = Sysfs::new();
        let dev = Sysfs::new();
        sys.device("0000:05:00.0");
        sys.vfio_container_dev("10:196");
        assert!(matches!(
            missing_nodes(&sys.0, &dev.0, &[pci("0000:05:00.0")]),
            Err(DeviceNodeError::NoGroup { .. })
        ));
    }

    #[test]
    fn a_device_number_that_is_not_major_minor_is_an_error() {
        let sys = Sysfs::new();
        let dev = Sysfs::new();
        sys.group(9, &["0000:05:00.0"]);
        sys.vfio_group_dev(9, "246");
        sys.vfio_container_dev("10:196");
        assert!(matches!(
            missing_nodes(&sys.0, &dev.0, &[pci("0000:05:00.0")]),
            Err(DeviceNodeError::Malformed { contents, .. }) if contents.trim() == "246"
        ));
    }

    /// `VFIO_GET_API_VERSION`: `_IO(VFIO_TYPE, VFIO_BASE)`.
    const VFIO_GET_API_VERSION: libc::Ioctl = (b';' as libc::Ioctl) << 8 | 0x64;

    /// A node made into a `/dev` that lacks it is the kernel's VFIO container.
    #[n_vm::test]
    fn a_made_node_is_the_device_sysfs_names() {
        let dev = std::env::temp_dir().join(format!("init-vfio-dev-{}", id::Id::<Sysfs>::new()));
        fs::create_dir(&dev).unwrap();
        // A fresh tmpfs stands in for a container's /dev, filled in before vfio loaded.
        nix::mount::mount(
            Some("tmpfs"),
            &dev,
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            None::<&str>,
        )
        .unwrap();

        let missing = missing_nodes(Path::new("/sys"), &dev, &[]).unwrap();
        assert_eq!(
            missing.iter().map(|n| &n.path).collect::<Vec<_>>(),
            [&dev.join("vfio/vfio")]
        );
        create_nodes(&missing).unwrap();
        assert_eq!(missing_nodes(Path::new("/sys"), &dev, &[]).unwrap(), []);

        let container = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dev.join("vfio/vfio"))
            .unwrap();
        // SAFETY: the ioctl takes no argument and the descriptor is open.
        let version = unsafe {
            libc::ioctl(
                std::os::fd::AsRawFd::as_raw_fd(&container),
                VFIO_GET_API_VERSION,
            )
        };
        assert_eq!(version, 0, "VFIO_API_VERSION");
    }
}
