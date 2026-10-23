// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Validate VFIO IOMMU groups before changing driver bindings.
//! Failed binds can leave devices unbound.

use std::fs;
use std::path::Path;

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
}
