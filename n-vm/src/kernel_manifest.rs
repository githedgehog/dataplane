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

use crate::backend::EffectiveBackend;
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
    /// Hypervisor this profile runs on (`cloud_hypervisor`, `qemu`).
    ///
    /// A profile is a (kernel, hypervisor) pair, so the hypervisor is a
    /// property of the *environment* rather than of the test.  That is what
    /// lets one test run under several hypervisors instead of being written
    /// out once per backend.
    pub hypervisor: String,
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
    /// The hypervisor this profile runs on.
    ///
    /// # Errors
    ///
    /// Returns [`KernelManifestError::UnknownHypervisor`] if the manifest
    /// names one this build does not have a backend for.  Failing loudly
    /// beats defaulting, which would run the test somewhere other than
    /// where the profile said.
    pub fn backend(&self, name: &str) -> Result<EffectiveBackend, KernelManifestError> {
        match self.hypervisor.as_str() {
            "cloud_hypervisor" => Ok(EffectiveBackend::CloudHypervisor),
            "qemu" => Ok(EffectiveBackend::Qemu),
            other => Err(KernelManifestError::UnknownHypervisor {
                profile: name.to_owned(),
                hypervisor: other.to_owned(),
            }),
        }
    }

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

    /// The profile this invocation should use.
    ///
    /// Three inputs, in order.  `declared` is what the test's own
    /// configuration asked for and wins outright.  Failing that,
    /// [`ENV_PROFILE`] points a whole run at a different environment
    /// (`N_VM_PROFILE=qemu cargo test`) without editing any test.  Failing
    /// that, the manifest's `default`.
    ///
    /// `emulation_required` says the guest cannot run natively on this host,
    /// so the chosen profile's hypervisor has to be able to emulate.  It
    /// only affects the fallback -- see
    /// [`default_emulating_profile`](Self::default_emulating_profile).
    /// Callers must derive it from the same fact in every tier: the host
    /// tier from the Docker daemon's architecture, later tiers from the
    /// [`ENV_ACCEL`](n_vm_protocol::ENV_ACCEL) it forwards.  Two tiers
    /// disagreeing here would boot a different kernel than the one whose
    /// hypervisor was resolved.
    ///
    /// # Errors
    ///
    /// Returns [`KernelManifestError::UnknownProfile`] if the variable names
    /// a profile that does not exist -- a typo there would otherwise
    /// silently run the default environment while appearing to select
    /// another, which is the one outcome worth failing over.
    pub fn selected(
        &self,
        declared: Option<&str>,
        emulation_required: bool,
    ) -> Result<(&str, &KernelProfile), KernelManifestError> {
        // A test that names a profile means it, so it outranks the
        // environment.  Same rule as a pinned `RequestedBackend`, and for
        // the same reason: `N_VM_PROFILE` exists to point tests that have
        // *no* opinion at a different environment, and a test that declares
        // one is declaring what it is for -- a modular-kernel test asking
        // for `flatcar` is not asking to be swept along with the rest.
        let from_env = std::env::var(n_vm_protocol::ENV_PROFILE).ok();
        self.selected_with(declared, from_env.as_deref(), emulation_required)
    }

    /// [`selected`](Self::selected) with the environment passed in.
    ///
    /// Separated so the precedence can be tested without mutating the
    /// process environment, which is global and would race every other test
    /// in the binary.
    ///
    /// # Errors
    ///
    /// As [`selected`](Self::selected).
    pub(crate) fn selected_with(
        &self,
        declared: Option<&str>,
        from_env: Option<&str>,
        emulation_required: bool,
    ) -> Result<(&str, &KernelProfile), KernelManifestError> {
        let named = declared
            .filter(|name| !name.is_empty())
            .or(from_env.filter(|name| !name.is_empty()))
            .map(str::to_owned);

        match named {
            Some(name) => {
                let profile = self.profile(&name)?;
                let key = self
                    .profiles
                    .get_key_value(&name)
                    .map(|(k, _)| k.as_str())
                    .expect("profile() succeeded, so the key is present");
                Ok((key, profile))
            }
            None if emulation_required => Ok(self.default_emulating_profile()),
            None => self.default_profile(),
        }
    }

    /// The profile to use by default when the guest must be *emulated*.
    ///
    /// Falls back to [`default_profile`](Self::default_profile) when that
    /// profile's hypervisor can emulate, or when no profile can.
    ///
    /// This exists because the manifest's `default` is a fact about the nix
    /// build, not about the machine the tests run on, and a cross-arch run
    /// is the case where those diverge: `default` is `cloud_hypervisor`,
    /// which cannot emulate a foreign guest at all.  Left alone, every
    /// unpinned test skipped -- and a skip is reported as a pass, so an
    /// aarch64 run went green in 1.5s having executed 2 of 19 in_vm tests.
    /// A harness that cannot run the guest must not look like one that did.
    ///
    /// Only for the *unset* case.  An explicit `N_VM_PROFILE` naming a
    /// profile that cannot emulate is honoured and skips, because "run this
    /// environment" is a request worth failing to satisfy visibly rather
    /// than silently substituting another.
    ///
    /// Among the profiles that can emulate, prefers one whose `boot` matches
    /// the default's, so the substitute differs from the default in its
    /// hypervisor and nothing else; ties break on name order, which
    /// [`BTreeMap`] makes deterministic.
    fn default_emulating_profile(&self) -> (&str, &KernelProfile) {
        let default = self.default_profile();
        let Ok((default_name, default_profile)) = default else {
            // `parse` rejects a `default` naming a missing profile, so this
            // is a hand-built manifest; let the caller's own lookup report
            // it rather than guessing here.
            return self
                .profiles
                .iter()
                .next()
                .map(|(k, v)| (k.as_str(), v))
                .unwrap_or_else(|| unreachable!("a manifest with no profiles cannot parse"));
        };

        let can_emulate = |p: &KernelProfile, name: &str| {
            p.backend(name).is_ok_and(EffectiveBackend::can_emulate)
        };
        if can_emulate(default_profile, default_name) {
            return (default_name, default_profile);
        }

        let candidates = || {
            self.profiles
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .filter(|(name, p)| can_emulate(p, name))
        };
        candidates()
            .find(|(_, p)| p.boot == default_profile.boot)
            .or_else(|| candidates().next())
            .unwrap_or((default_name, default_profile))
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

    /// The manifest names a hypervisor this build has no backend for.
    #[error("kernel profile `{profile}` names unknown hypervisor `{hypervisor}`")]
    #[diagnostic(
        code(n_vm::kernel_manifest_unknown_hypervisor),
        help("valid hypervisors are `cloud_hypervisor` and `qemu`")
    )]
    UnknownHypervisor {
        /// The offending profile's name.
        profile: String,
        /// The hypervisor the manifest claimed.
        hypervisor: String,
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
          "hypervisor": "cloud_hypervisor",
          "boot": "direct",
          "kernel": "/kernels/union/vmlinuz"
        }
      }
    }"#;

    fn parse(raw: &str) -> Result<KernelManifest, KernelManifestError> {
        KernelManifest::parse(raw, Path::new("<test>"))
    }

    /// The shape nix writes for a cross build: the default cannot emulate,
    /// and two profiles that can.
    const CROSS: &str = r#"{
      "default": "cloud_hypervisor",
      "profiles": {
        "cloud_hypervisor": {
          "arch": "aarch64",
          "hypervisor": "cloud_hypervisor",
          "boot": "direct",
          "kernel": "/kernels/union/vmlinuz"
        },
        "modular": {
          "arch": "aarch64",
          "hypervisor": "qemu",
          "boot": "initramfs",
          "kernel": "/kernels/modular/vmlinuz"
        },
        "qemu": {
          "arch": "aarch64",
          "hypervisor": "qemu",
          "boot": "direct",
          "kernel": "/kernels/union/vmlinuz"
        }
      }
    }"#;

    /// An emulated guest must not default to a hypervisor that cannot
    /// emulate it.
    ///
    /// Every unpinned test then skips, and a skip counts as a pass, so the
    /// run goes green having executed almost nothing -- the failure this
    /// whole fallback exists to prevent.  Asserted on the private resolver
    /// rather than through `selected`, which reads the environment and would
    /// make the test depend on the ambient `N_VM_PROFILE`.
    #[test]
    fn an_emulated_guest_does_not_default_to_a_non_emulating_hypervisor() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, profile) = manifest.default_emulating_profile();
        assert_ne!(name, "cloud_hypervisor", "cannot emulate a foreign guest");
        assert!(
            profile
                .backend(name)
                .expect("known hypervisor")
                .can_emulate(),
            "substituted profile `{name}` must be able to emulate",
        );
    }

    // -- Which profile a run gets -------------------------------------

    /// A test that names a profile gets it, even under a sweep that named
    /// something else.
    ///
    /// The point of the lever: a test declares which kernel it is *for*.
    /// A modular-kernel test swept onto a built-in-only kernel by an
    /// environment variable would not be testing anything, and would say so
    /// only by failing somewhere unrelated.
    #[test]
    fn a_declared_profile_outranks_the_environment() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest
            .selected_with(Some("modular"), Some("qemu"), false)
            .expect("declared profile resolves");
        assert_eq!(name, "modular");
    }

    /// With nothing declared, the environment still points a whole run at
    /// another environment -- which is what it was for.
    #[test]
    fn the_environment_still_steers_a_test_with_no_opinion() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest
            .selected_with(None, Some("qemu"), false)
            .expect("environment profile resolves");
        assert_eq!(name, "qemu");
    }

    /// With neither, the manifest's default.
    #[test]
    fn nothing_declared_and_nothing_set_is_the_default() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest
            .selected_with(None, None, false)
            .expect("default resolves");
        assert_eq!(name, "cloud_hypervisor");
    }

    /// An empty value is not a choice, from either source.
    #[test]
    fn an_empty_name_falls_through() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest
            .selected_with(Some(""), Some(""), false)
            .expect("falls through to the default");
        assert_eq!(name, "cloud_hypervisor");
    }

    /// A declared profile that does not exist is an error naming the ones
    /// that do -- never a silent fallback to the default, which would run
    /// the wrong kernel while appearing to run the requested one.
    #[test]
    fn a_declared_profile_that_does_not_exist_is_an_error() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let err = manifest
            .selected_with(Some("flatcra"), None, false)
            .expect_err("a typo must not fall back");
        assert!(
            matches!(err, KernelManifestError::UnknownProfile { .. }),
            "expected UnknownProfile, got {err:?}",
        );
    }

    /// A declared profile is honoured even when the guest must be emulated
    /// and it cannot emulate: the caller then skips with its own reason.
    /// Substituting silently is only right for a run with no opinion.
    #[test]
    fn a_declared_profile_is_not_substituted_when_emulating() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest
            .selected_with(Some("cloud_hypervisor"), None, true)
            .expect("declared profile resolves");
        assert_eq!(name, "cloud_hypervisor");
    }

    /// The substitute differs from the default in its hypervisor and nothing
    /// else, so switching to it does not quietly also switch boot path.
    #[test]
    fn the_substituted_profile_keeps_the_defaults_boot_mode() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest.default_emulating_profile();
        assert_eq!(
            name, "qemu",
            "`qemu` boots directly like the default; `modular` would also \
             change the boot path",
        );
    }

    /// The fallback applies only on the emulation path: a native run still
    /// gets the manifest's own default, even when it cannot emulate.
    ///
    /// Asserted via `default_profile` rather than `selected(false)` because
    /// `selected` consults `N_VM_PROFILE`, which would make the result depend
    /// on the environment the suite happens to run under -- as it did, when
    /// this test was first written that way and failed under
    /// `N_VM_PROFILE=qemu`.
    #[test]
    fn a_native_guest_keeps_the_manifest_default() {
        let manifest = parse(CROSS).expect("cross manifest should parse");
        let (name, _) = manifest
            .default_profile()
            .expect("default must resolve for a native guest");
        assert_eq!(
            name, "cloud_hypervisor",
            "a native guest runs the default even though it cannot emulate",
        );
    }

    /// With nothing able to emulate, the default is returned unchanged so
    /// the caller skips with its own specific reason rather than this code
    /// inventing a profile that cannot work either.
    #[test]
    fn no_emulating_profile_leaves_the_default_alone() {
        let manifest = parse(SAMPLE).expect("sample manifest should parse");
        let (name, _) = manifest.default_emulating_profile();
        assert_eq!(name, "union");
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
              "hypervisor": "qemu",
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
            "union": { "arch": "x86_64", "hypervisor": "qemu",
                       "kernel": "/kernels/union/vmlinuz" }
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

    // -- Multiple profiles --------------------------------------------

    /// The shape the nix build actually emits: several profiles sharing one
    /// kernel and differing only in hypervisor.  That is the axis the
    /// integration suite currently sweeps by hand.
    const TWO_HYPERVISORS: &str = r#"{
      "default": "cloud_hypervisor",
      "profiles": {
        "cloud_hypervisor": {
          "arch": "x86_64", "hypervisor": "cloud_hypervisor", "boot": "direct",
          "kernel": "/kernels/union/vmlinuz", "config": "/kernels/union/config"
        },
        "qemu": {
          "arch": "x86_64", "hypervisor": "qemu", "boot": "direct",
          "kernel": "/kernels/union/vmlinuz", "config": "/kernels/union/config"
        }
      }
    }"#;

    #[test]
    fn profiles_may_share_a_kernel_and_differ_only_in_hypervisor() {
        let manifest = parse(TWO_HYPERVISORS).expect("two-profile manifest should parse");
        assert_eq!(manifest.profile_names(), vec!["cloud_hypervisor", "qemu"]);

        let chv = manifest.profile("cloud_hypervisor").expect("exists");
        let qemu = manifest.profile("qemu").expect("exists");
        assert_eq!(
            chv.kernel, qemu.kernel,
            "both profiles should reference the same kernel image",
        );
        assert_eq!(
            chv.backend("cloud_hypervisor").expect("known hypervisor"),
            EffectiveBackend::CloudHypervisor,
        );
        assert_eq!(
            qemu.backend("qemu").expect("known hypervisor"),
            EffectiveBackend::Qemu,
        );
    }

    #[test]
    fn default_selects_one_of_several_profiles() {
        let manifest = parse(TWO_HYPERVISORS).expect("two-profile manifest should parse");
        let (name, _) = manifest.default_profile().expect("default must resolve");
        assert_eq!(name, "cloud_hypervisor");
    }

    /// Defaulting an unrecognised hypervisor would run the test somewhere
    /// other than where the profile said, which is worse than not running it.
    #[test]
    fn unknown_hypervisor_is_rejected_rather_than_defaulted() {
        let raw = r#"{
          "default": "weird",
          "profiles": {
            "weird": {
              "arch": "x86_64", "hypervisor": "firecracker",
              "kernel": "/kernels/union/vmlinuz"
            }
          }
        }"#;
        let manifest = parse(raw).expect("manifest itself is well-formed");
        let err = manifest
            .profile("weird")
            .expect("exists")
            .backend("weird")
            .expect_err("unknown hypervisor must be rejected");
        assert!(
            matches!(err, KernelManifestError::UnknownHypervisor { .. }),
            "expected UnknownHypervisor, got {err:?}",
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
