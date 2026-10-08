// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read the process's hugepage allowance without allocating or changing cgroup limits.

use std::fs;
use std::path::{Component, Path, PathBuf};

use procfs::ProcessCGroups;
use procfs::process::{MountInfo, Process};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Version {
    V1,
    V2,
}

pub(super) struct HugetlbCgroup {
    version: Version,
    root: PathBuf,
    current: PathBuf,
}

impl HugetlbCgroup {
    pub(super) fn discover() -> Result<Self, String> {
        let process = Process::myself().map_err(|e| format!("could not open /proc/self: {e}"))?;
        let groups = process
            .cgroups()
            .map_err(|e| format!("could not read cgroup membership: {e}"))?;
        let mounts = process
            .mountinfo()
            .map_err(|e| format!("could not read cgroup mounts: {e}"))?;
        Self::resolve(&groups, &mounts.0)
    }

    fn resolve(groups: &ProcessCGroups, mounts: &[MountInfo]) -> Result<Self, String> {
        // In hybrid setups the hugetlb controller may still belong to v1.
        let (group, version) = groups
            .0
            .iter()
            .find(|group| group.controllers.iter().any(|name| name == "hugetlb"))
            .map(|group| (group, Version::V1))
            .or_else(|| {
                groups
                    .0
                    .iter()
                    .find(|group| group.hierarchy == 0)
                    .map(|group| (group, Version::V2))
            })
            .ok_or("no hugepage cgroup hierarchy is visible")?;
        let path = Path::new(&group.pathname);
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return Err(format!(
                "cgroup {} is outside the visible hierarchy",
                path.display()
            ));
        }
        let mount = mounts
            .iter()
            .filter(|mount| match version {
                Version::V1 => {
                    mount.fs_type == "cgroup" && mount.super_options.contains_key("hugetlb")
                }
                Version::V2 => mount.fs_type == "cgroup2",
            })
            .filter(|mount| path.starts_with(&mount.root))
            .min_by_key(|mount| Path::new(&mount.root).components().count())
            .ok_or_else(|| {
                format!(
                    "no visible hugetlb mount contains cgroup {}",
                    path.display()
                )
            })?;
        let relative = path.strip_prefix(&mount.root).map_err(|e| e.to_string())?;
        Ok(Self {
            version,
            root: mount.mount_point.clone(),
            current: mount.mount_point.join(relative),
        })
    }

    /// Minimum remaining allowance across the visible ancestors. `None` means unlimited.
    pub(super) fn remaining_bytes(&self, page_size_kb: u64) -> Result<Option<u64>, String> {
        let size = match page_size_kb {
            super::ONE_GIB_KB => "1GB",
            super::TWO_MIB_KB => "2MB",
            _ => return Err(format!("unsupported hugepage size {page_size_kb} kB")),
        };
        let (limit, usage, reserved_limit, reserved_usage) = match self.version {
            Version::V1 => (
                "limit_in_bytes",
                "usage_in_bytes",
                "rsvd.limit_in_bytes",
                "rsvd.usage_in_bytes",
            ),
            Version::V2 => ("max", "current", "rsvd.max", "rsvd.current"),
        };
        let mut remaining = None;
        for directory in self.current.ancestors() {
            let path = directory.join(format!("hugetlb.{size}.{limit}"));
            if let Some(raw) = optional_read(&path)? {
                let available = self.allowance(directory, size, &raw, usage)?;
                remaining = minimum(remaining, available);
            } else if directory == self.current {
                // The real v2 root has no limit files. A missing leaf limit is not permission
                // to consume the host pool: require a readable controller configuration.
                let controllers = optional_read(&directory.join("cgroup.controllers"))?;
                let unlimited_root = self.version == Version::V2
                    && self.current == self.root
                    && controllers.is_some_and(|s| s.split_whitespace().any(|c| c == "hugetlb"));
                if !unlimited_root {
                    return Err(format!(
                        "cannot determine hugepage allowance: {} is missing",
                        path.display()
                    ));
                }
            }
            let path = directory.join(format!("hugetlb.{size}.{reserved_limit}"));
            if let Some(raw) = optional_read(&path)? {
                remaining = minimum(
                    remaining,
                    self.allowance(directory, size, &raw, reserved_usage)?,
                );
            }
            if directory == self.root {
                break;
            }
        }
        Ok(remaining)
    }

    fn allowance(
        &self,
        directory: &Path,
        size: &str,
        raw: &str,
        usage: &str,
    ) -> Result<Option<u64>, String> {
        if self.version == Version::V2 && raw.trim() == "max" {
            return Ok(None);
        }
        let limit = raw.trim().parse::<u64>().map_err(|e| {
            format!(
                "invalid {size} hugepage limit in {}: {e}",
                directory.display()
            )
        })?;
        let path = directory.join(format!("hugetlb.{size}.{usage}"));
        let used = fs::read_to_string(&path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("invalid hugepage usage in {}: {e}", path.display()))?;
        Ok(Some(limit.saturating_sub(used)))
    }
}

fn minimum(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn optional_read(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{TWO_MIB_KB, tests::Fixture};
    use super::*;
    use procfs::FromBufRead;

    fn controller(files: &Fixture, version: Version) -> HugetlbCgroup {
        HugetlbCgroup {
            version,
            root: files.0.clone(),
            current: files.0.join("parent/leaf"),
        }
    }

    #[test]
    fn resolves_process_membership_and_hybrid_hierarchies() {
        let groups = ProcessCGroups::from_buf_read(
            "0::/system.slice/dataplane\n4:hugetlb:/gateway/child\n".as_bytes(),
        )
        .unwrap();
        let v2 = MountInfo::from_line("1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw").unwrap();
        let v1 = MountInfo::from_line(
            "2 0 0:2 /gateway /sys/fs/cgroup/hugetlb rw - cgroup cgroup rw,hugetlb",
        )
        .unwrap();
        let group = HugetlbCgroup::resolve(&groups, &[v2.clone(), v1]).unwrap();
        assert_eq!(group.version, Version::V1);
        assert_eq!(group.current, Path::new("/sys/fs/cgroup/hugetlb/child"));
        let groups =
            ProcessCGroups::from_buf_read("0::/system.slice/dataplane\n".as_bytes()).unwrap();
        let group = HugetlbCgroup::resolve(&groups, std::slice::from_ref(&v2)).unwrap();
        assert_eq!(
            group.current,
            Path::new("/sys/fs/cgroup/system.slice/dataplane")
        );
        let groups = ProcessCGroups::from_buf_read("0::/\n".as_bytes()).unwrap();
        assert_eq!(
            HugetlbCgroup::resolve(&groups, &[v2]).unwrap().current,
            Path::new("/sys/fs/cgroup")
        );
    }

    #[test]
    fn ancestor_usage_and_reservation_limits_constrain_the_leaf() {
        let files = Fixture::new();
        files.write("parent/leaf/hugetlb.2MB.max", "8388608");
        files.write("parent/leaf/hugetlb.2MB.current", "2097152");
        files.write("parent/hugetlb.2MB.max", "6291456");
        files.write("parent/hugetlb.2MB.current", "2097152");
        let group = controller(&files, Version::V2);
        assert_eq!(group.remaining_bytes(TWO_MIB_KB).unwrap(), Some(4_194_304));
        files.write("parent/leaf/hugetlb.2MB.rsvd.max", "4194304");
        files.write("parent/leaf/hugetlb.2MB.rsvd.current", "2097152");
        assert_eq!(group.remaining_bytes(TWO_MIB_KB).unwrap(), Some(2_097_152));
        files.write("parent/hugetlb.2MB.current", "8388608");
        assert_eq!(group.remaining_bytes(TWO_MIB_KB).unwrap(), Some(0));
    }

    #[test]
    fn unlimited_leaf_does_not_override_a_parent_limit() {
        let files = Fixture::new();
        files.write("parent/leaf/hugetlb.2MB.max", "max");
        let group = controller(&files, Version::V2);
        assert_eq!(group.remaining_bytes(TWO_MIB_KB).unwrap(), None);
        files.write("parent/hugetlb.2MB.max", "0");
        files.write("parent/hugetlb.2MB.current", "0");
        assert_eq!(group.remaining_bytes(TWO_MIB_KB).unwrap(), Some(0));
    }

    #[test]
    fn legacy_cgroups_check_usage_and_reservations() {
        let files = Fixture::new();
        files.write("parent/leaf/hugetlb.2MB.limit_in_bytes", "8388608");
        files.write("parent/leaf/hugetlb.2MB.usage_in_bytes", "2097152");
        files.write("parent/leaf/hugetlb.2MB.rsvd.limit_in_bytes", "4194304");
        files.write("parent/leaf/hugetlb.2MB.rsvd.usage_in_bytes", "0");
        assert_eq!(
            controller(&files, Version::V1)
                .remaining_bytes(TWO_MIB_KB)
                .unwrap(),
            Some(4_194_304)
        );
    }

    #[test]
    fn missing_malformed_or_unreadable_controls_are_not_unlimited() {
        let files = Fixture::new();
        let group = controller(&files, Version::V2);
        assert!(group.remaining_bytes(TWO_MIB_KB).is_err());
        files.write("parent/leaf/hugetlb.2MB.max", "bad");
        assert!(group.remaining_bytes(TWO_MIB_KB).is_err());
        files.write("parent/leaf/hugetlb.2MB.max", "4096");
        assert!(group.remaining_bytes(TWO_MIB_KB).is_err());
        files.write("parent/leaf/hugetlb.2MB.current", "bad");
        assert!(group.remaining_bytes(TWO_MIB_KB).is_err());
        fs::remove_file(files.0.join("parent/leaf/hugetlb.2MB.max")).unwrap();
        fs::create_dir(files.0.join("parent/leaf/hugetlb.2MB.max")).unwrap();
        assert!(group.remaining_bytes(TWO_MIB_KB).is_err());
    }

    #[test]
    fn the_v2_root_has_no_limit_files() {
        let files = Fixture::new();
        files.write("cgroup.controllers", "cpu memory hugetlb");
        let group = HugetlbCgroup {
            version: Version::V2,
            root: files.0.clone(),
            current: files.0.clone(),
        };
        assert_eq!(group.remaining_bytes(TWO_MIB_KB).unwrap(), None);
    }
}
