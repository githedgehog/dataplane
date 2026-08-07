// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The kernel manifest: nix's declaration of which guest kernels exist.
//!
//! # Why a manifest at all
//!
//! `cargo` must never invoke `nix`.  Nix does not handle that recursion
//! well, so the build is strictly staged:
//!
//! 1. nix builds or fetches every artifact that is not a test -- kernels,
//!    module trees, virtiofsd, the guest rootfs -- and materializes them
//!    (`just setup-roots` writes the `testroot` symlink);
//! 2. cargo builds the tests;
//! 3. the tests *read* those artifacts, and never build them.
//!
//! That staging means the set of available kernels is a fact about the nix
//! build, discovered at run time rather than hardcoded in Rust.  Hardcoding
//! it -- as `Arch::kernel_image_path` used to, with `/bzImage` and `/Image`
//! -- works only while there is exactly one kernel per architecture, which
//! stops being true as soon as we want to run the same test against both a
//! kernel built from our own config fragments and a distro's production
//! kernel.
//!
//! # Contract
//!
//! nix writes the manifest into `testroot`; every first-level `testroot`
//! entry is bind-mounted at the container root, so the container tier reads
//! it from [`KERNEL_MANIFEST_PATH`].  Paths inside it are
//! container-absolute, because the container tier is what consumes them.
//!
//! A missing or malformed manifest is a hard error naming the fix, never a
//! silent fallback: a wrong kernel path fails much later and far less
//! legibly than a missing one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use n_vm_protocol::KERNEL_MANIFEST_PATH;

use crate::config::Arch;

/// How a profile's kernel reaches its root filesystem.
///
/// A kernel with `CONFIG_VIRTIO_FS=y` can mount the workspace itself and
/// needs no initramfs.  A kernel that has virtiofs as a *module* cannot:
/// the module lives in the module tree, which is reached over virtiofs.
/// Breaking that deadlock needs an initramfs carrying the boot-critical
/// modules, which is the only channel guaranteed to be available before any
/// driver loads.
///
/// This is derived by the nix build from the kernel's own config rather
/// than configured by hand, so the two cannot disagree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootMode {
    /// Boot the kernel straight into the virtiofs root.
    #[default]
    Direct,
    /// Boot through an initramfs that loads boot-critical modules first.
    Initramfs,
}

/// One named guest kernel and its artifacts.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KernelProfile {
    /// Guest architecture this kernel is built for (`x86_64`, `aarch64`).
    ///
    /// Checked against the test binary's own target arch before launch: an
    /// x86_64 `bzImage` is useless under an aarch64 emulator, and catching
    /// that here beats debugging a VM that never prints anything.
    pub arch: String,
    /// How this kernel reaches its root filesystem.
    #[serde(default)]
    pub boot: BootMode,
    /// Container-absolute path to the bootable kernel image.
    pub kernel: String,
    /// Container-absolute path to the kernel's own `.config`, when nix was
    /// able to record it.
    ///
    /// Unused today; this is what a later requirement-verification pass
    /// reads to answer "does this kernel actually provide what the test
    /// declared it needs".
    #[serde(default)]
    pub config: Option<String>,
    /// Container-absolute path to the initramfs, when `boot` is
    /// [`BootMode::Initramfs`].
    #[serde(default)]
    pub initramfs: Option<String>,
    /// Container-absolute path to the module tree, for modular kernels.
    #[serde(default)]
    pub modules: Option<String>,
}

impl KernelProfile {
    /// Checks that this kernel matches the guest architecture.
    ///
    /// # Errors
    ///
    /// Returns [`KernelManifestError::ArchMismatch`] if it does not.
    pub fn check_arch(&self, name: &str, arch: Arch) -> Result<(), KernelManifestError> {
        if self.arch == arch.manifest_name() {
            return Ok(());
        }
        Err(KernelManifestError::ArchMismatch {
            profile: name.to_owned(),
            manifest_arch: self.arch.clone(),
            guest_arch: arch.manifest_name(),
        })
    }
}

/// The set of guest kernels nix built, and which one to use by default.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KernelManifest {
    /// Name of the profile to use when a test does not name one.
    pub default: String,
    /// Every available profile, keyed by name.
    pub profiles: BTreeMap<String, KernelProfile>,
}

impl KernelManifest {
    /// Reads the manifest from the container's well-known location.
    ///
    /// # Errors
    ///
    /// See [`KernelManifestError`].
    pub fn load() -> Result<Self, KernelManifestError> {
        Self::load_from(Path::new(KERNEL_MANIFEST_PATH))
    }

    /// Reads a manifest from an explicit path.
    ///
    /// # Errors
    ///
    /// See [`KernelManifestError`].
    pub fn load_from(path: &Path) -> Result<Self, KernelManifestError> {
        let raw = std::fs::read_to_string(path).map_err(|source| KernelManifestError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&raw, path)
    }

    /// Parses a manifest from JSON, validating internal consistency.
    ///
    /// # Errors
    ///
    /// See [`KernelManifestError`].
    pub fn parse(raw: &str, path: &Path) -> Result<Self, KernelManifestError> {
        let manifest: Self =
            serde_json::from_str(raw).map_err(|source| KernelManifestError::Parse {
                path: path.to_owned(),
                source,
            })?;

        // A `default` naming a profile that does not exist would otherwise
        // surface as a confusing "unknown profile" at launch, pointing at
        // the test rather than at the manifest that is actually wrong.
        if !manifest.profiles.contains_key(&manifest.default) {
            return Err(KernelManifestError::UnknownProfile {
                name: manifest.default.clone(),
                available: manifest.profile_names(),
            });
        }

        Ok(manifest)
    }

    /// The available profile names, for error messages.
    #[must_use]
    pub fn profile_names(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    /// Looks up a profile by name.
    ///
    /// # Errors
    ///
    /// Returns [`KernelManifestError::UnknownProfile`] if there is no such
    /// profile, listing the ones that do exist.
    pub fn profile(&self, name: &str) -> Result<&KernelProfile, KernelManifestError> {
        self.profiles
            .get(name)
            .ok_or_else(|| KernelManifestError::UnknownProfile {
                name: name.to_owned(),
                available: self.profile_names(),
            })
    }

    /// The default profile and its name.
    ///
    /// # Errors
    ///
    /// Returns [`KernelManifestError::UnknownProfile`] if `default` names a
    /// profile that is not present.  [`parse`](Self::parse) rejects that up
    /// front, so this can only fire on a hand-built manifest.
    pub fn default_profile(&self) -> Result<(&str, &KernelProfile), KernelManifestError> {
        let profile = self.profile(&self.default)?;
        Ok((&self.default, profile))
    }
}

/// Errors reading or interpreting the kernel manifest.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum KernelManifestError {
    /// The manifest file could not be read.
    #[error("cannot read kernel manifest at {path:?}")]
    #[diagnostic(
        code(n_vm::kernel_manifest_read),
        help(
            "the manifest is materialized by nix into `testroot` -- run \
              `just setup-roots` from the workspace root, and re-run it after \
              changing anything about the guest kernels"
        )
    )]
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The manifest is not valid JSON, or does not match the expected shape.
    #[error("cannot parse kernel manifest at {path:?}")]
    #[diagnostic(
        code(n_vm::kernel_manifest_parse),
        help(
            "the manifest is generated by the nix build; a parse failure means \
              the generator and this reader have drifted apart"
        )
    )]
    Parse {
        /// The path that failed to parse.
        path: PathBuf,
        /// The underlying deserialization error.
        source: serde_json::Error,
    },

    /// A profile was requested that the manifest does not declare.
    #[error("no kernel profile named `{name}` (available: {})", available.join(", "))]
    #[diagnostic(
        code(n_vm::kernel_manifest_unknown_profile),
        help("add the profile to the nix build, then re-run `just setup-roots`")
    )]
    UnknownProfile {
        /// The profile that was requested.
        name: String,
        /// The profiles that do exist.
        available: Vec<String>,
    },

    /// The profile's kernel is built for a different architecture than the
    /// test binary.
    #[error("kernel profile `{profile}` is for {manifest_arch}, but the guest is {guest_arch}")]
    #[diagnostic(
        code(n_vm::kernel_manifest_arch_mismatch),
        help(
            "a kernel image only boots its own architecture; rebuild the roots \
              for this target (`just platform=<arch> setup-roots`)"
        )
    )]
    ArchMismatch {
        /// The offending profile's name.
        profile: String,
        /// The architecture the manifest claims.
        manifest_arch: String,
        /// The architecture the test binary targets.
        guest_arch: &'static str,
    },
}

#[cfg(test)]
mod test {
    use super::*;

    const SAMPLE: &str = r#"{
      "default": "union",
      "profiles": {
        "union": {
          "arch": "x86_64",
          "boot": "direct",
          "kernel": "/kernels/union/vmlinuz"
        }
      }
    }"#;

    fn parse(raw: &str) -> Result<KernelManifest, KernelManifestError> {
        KernelManifest::parse(raw, Path::new("<test>"))
    }

    #[test]
    fn parses_a_minimal_manifest() {
        let manifest = parse(SAMPLE).expect("sample manifest should parse");
        let (name, profile) = manifest.default_profile().expect("default must resolve");
        assert_eq!(name, "union");
        assert_eq!(profile.kernel, "/kernels/union/vmlinuz");
        assert_eq!(profile.boot, BootMode::Direct);
    }

    /// Optional artifacts default to absent rather than failing to parse,
    /// so a direct-boot profile need not spell out fields that only apply
    /// to modular kernels.
    #[test]
    fn optional_artifacts_default_to_absent() {
        let manifest = parse(SAMPLE).expect("sample manifest should parse");
        let profile = manifest.profile("union").expect("profile exists");
        assert_eq!(profile.config, None);
        assert_eq!(profile.initramfs, None);
        assert_eq!(profile.modules, None);
    }

    #[test]
    fn reads_an_initramfs_profile() {
        let raw = r#"{
          "default": "flatcar",
          "profiles": {
            "flatcar": {
              "arch": "x86_64",
              "boot": "initramfs",
              "kernel": "/kernels/flatcar/vmlinuz",
              "config": "/kernels/flatcar/config",
              "initramfs": "/kernels/flatcar/initramfs.cpio.gz",
              "modules": "/kernels/flatcar/modules/6.12.95-flatcar"
            }
          }
        }"#;
        let manifest = parse(raw).expect("initramfs manifest should parse");
        let profile = manifest.profile("flatcar").expect("profile exists");
        assert_eq!(profile.boot, BootMode::Initramfs);
        assert_eq!(
            profile.modules.as_deref(),
            Some("/kernels/flatcar/modules/6.12.95-flatcar")
        );
    }

    /// A `default` pointing at a missing profile is the manifest's bug, so
    /// it is rejected at parse time rather than at launch, where the error
    /// would appear to blame the test.
    #[test]
    fn rejects_default_naming_a_missing_profile() {
        let raw = r#"{
          "default": "nope",
          "profiles": {
            "union": { "arch": "x86_64", "kernel": "/kernels/union/vmlinuz" }
          }
        }"#;
        let err = parse(raw).expect_err("dangling default must be rejected");
        assert!(
            matches!(&err, KernelManifestError::UnknownProfile { name, .. } if name == "nope"),
            "expected UnknownProfile, got {err:?}",
        );
    }

    /// The error names what *is* available, because the common cause is a
    /// typo or a stale `testroot`, and both are diagnosed by seeing the list.
    #[test]
    fn unknown_profile_error_lists_the_alternatives() {
        let manifest = parse(SAMPLE).expect("sample manifest should parse");
        let err = manifest
            .profile("flatcar")
            .expect_err("missing profile must be rejected");
        assert!(
            format!("{err}").contains("union"),
            "error should list available profiles, got: {err}",
        );
    }

    #[test]
    fn arch_mismatch_is_rejected() {
        let manifest = parse(SAMPLE).expect("sample manifest should parse");
        let profile = manifest.profile("union").expect("profile exists");
        profile
            .check_arch("union", Arch::X86_64)
            .expect("matching arch must be accepted");
        let err = profile
            .check_arch("union", Arch::Aarch64)
            .expect_err("mismatched arch must be rejected");
        assert!(
            matches!(err, KernelManifestError::ArchMismatch { .. }),
            "expected ArchMismatch, got {err:?}",
        );
    }
}
