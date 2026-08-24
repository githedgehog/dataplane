// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Kernel features a test depends on, and checking them against the kernel
//! it is about to run on.
//!
//! # Why declare them
//!
//! The set of features a kernel *provides* is decided independently of the
//! tests: by config fragments for a kernel we build, by someone else's build
//! entirely for a distro kernel.  Nothing stops a test from needing a symbol
//! its kernel does not have.
//!
//! Declaring the dependency makes that a stated fact rather than an
//! accident.  A test that needs `NET_CLS_FLOWER` and does not say so passes
//! only because the fragment list happens to enable it -- and keeps passing
//! until someone trims the list, at which point it fails somewhere far from
//! the cause.
//!
//! This is also the check that makes running against a production kernel
//! worth anything.  "requires `CONFIG_NET_CLS_FLOWER`, kernel has it `n`" is
//! a finding about the kernel we ship on.  The same test failing obscurely
//! several tiers down is noise, and noise in that position gets muted.
//!
//! # Why not generate the fragments from these
//!
//! It looks like these declarations should *produce* the kernel config
//! rather than be checked against it.  They cannot: nix builds the kernel
//! before cargo builds the tests, so a union derived from compiled Rust
//! would have to exist before the thing it is derived from.  Scraping the
//! sources instead would work, but would make the kernel derivation depend
//! on every `.rs` file in the workspace -- so any code edit would trigger a
//! full kernel rebuild.
//!
//! So the provided set stays declared independently, and these are verified
//! against it.  Almost nothing is lost: the value was in the check, not in
//! the generation.

use crate::kernel_config::{FeatureState, KernelConfig};

/// A kernel feature a test can depend on.
///
/// Carries both the Kconfig symbol and the module name because the two are
/// used by different consumers and are not mechanically related --
/// `CONFIG_NET_CLS_FLOWER` builds `cls_flower.ko`.  The symbol answers "does
/// this kernel have it"; the module name answers "what has to be loaded
/// before it works".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelFeature {
    /// Kconfig symbol, *without* the `CONFIG_` prefix.
    symbol: &'static str,
    /// Module that provides it when built as `=m`, if it can be modular.
    module: Option<&'static str>,
}

impl KernelFeature {
    /// Declares a feature that can be built as a module.
    #[must_use]
    pub const fn modular(symbol: &'static str, module: &'static str) -> Self {
        Self {
            symbol,
            module: Some(module),
        }
    }

    /// Declares a feature that can only be built in.
    ///
    /// Kept distinct from [`modular`](Self::modular) so that finding such a
    /// symbol set to `=m` is recognisable as a bug in this table rather than
    /// silently producing a module name that does not exist.
    #[must_use]
    pub const fn builtin_only(symbol: &'static str) -> Self {
        Self {
            symbol,
            module: None,
        }
    }

    /// The Kconfig symbol, without the `CONFIG_` prefix.
    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        self.symbol
    }

    /// The module providing this feature when it is built as `=m`.
    #[must_use]
    pub const fn module(&self) -> Option<&'static str> {
        self.module
    }
}

/// Features this workspace's tests depend on.
///
/// A curated table rather than free-form strings so that a typo is a
/// compile error and shows up in completion, per
/// `development/code/avoid-global-reasoning.md` ("use static typing to
/// enforce validity constraints where possible").  It is a module of
/// `const`s rather than an enum so a consuming project can declare its own
/// without editing this one.
pub mod features {
    use super::KernelFeature;

    /// Paravirtualised network device.
    pub const VIRTIO_NET: KernelFeature = KernelFeature::modular("VIRTIO_NET", "virtio_net");
    /// Shared-filesystem transport used for the workspace mount.
    pub const VIRTIO_FS: KernelFeature = KernelFeature::modular("VIRTIO_FS", "virtiofs");
    /// FUSE, which `virtiofs` is built on.
    pub const FUSE_FS: KernelFeature = KernelFeature::modular("FUSE_FS", "fuse");
    /// vsock transport used for the result channel.
    pub const VIRTIO_VSOCKETS: KernelFeature =
        KernelFeature::modular("VIRTIO_VSOCKETS", "vmw_vsock_virtio_transport");

    /// hugetlbfs.  Cannot be modular.
    pub const HUGETLBFS: KernelFeature = KernelFeature::builtin_only("HUGETLBFS");

    /// `tc` flower classifier.
    pub const NET_CLS_FLOWER: KernelFeature =
        KernelFeature::modular("NET_CLS_FLOWER", "cls_flower");
    /// `tc` action support.  Cannot be modular.
    pub const NET_CLS_ACT: KernelFeature = KernelFeature::builtin_only("NET_CLS_ACT");

    /// Userspace device passthrough.
    pub const VFIO: KernelFeature = KernelFeature::modular("VFIO", "vfio");
    /// PCI passthrough via VFIO.
    pub const VFIO_PCI: KernelFeature = KernelFeature::modular("VFIO_PCI", "vfio-pci");

    /// Mellanox ConnectX core driver.
    pub const MLX5_CORE: KernelFeature = KernelFeature::modular("MLX5_CORE", "mlx5_core");

    /// Intel 82540EM, the emulated NIC QEMU calls `e1000`.
    pub const E1000: KernelFeature = KernelFeature::modular("E1000", "e1000");
    /// Intel 82574L, the emulated NIC QEMU calls `e1000e`.
    ///
    /// Worth declaring alongside [`VIRTIO_NET`] on a test that mixes
    /// models: a kernel without the driver does not fail, it simply never
    /// brings the interface up, and the test then reads as "the device was
    /// not presented" when the device was presented and nothing could bind
    /// it.
    pub const E1000E: KernelFeature = KernelFeature::modular("E1000E", "e1000e");
}

/// A feature a kernel does not provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmetRequirement {
    /// The Kconfig symbol that is missing.
    pub symbol: &'static str,
}

/// Checks a test's declared features against a kernel's config.
///
/// A feature is satisfied by `=y` *or* `=m`: a module is present, it just
/// has to be loaded first.  Loading is a separate concern from availability,
/// which is why this does not reject `=m`.
///
/// Returns every unmet requirement rather than the first, because a kernel
/// missing one feature usually misses several related ones, and reporting
/// them one boot at a time is a poor way to find that out.
#[must_use]
pub fn unmet_requirements(
    required: &[KernelFeature],
    config: &KernelConfig,
) -> Vec<UnmetRequirement> {
    required
        .iter()
        .filter(|feature| !config.provides(feature.symbol()))
        .map(|feature| UnmetRequirement {
            symbol: feature.symbol(),
        })
        .collect()
}

/// The modules that must be loaded before the declared features work.
///
/// Only features the kernel built as `=m` appear: a built-in needs no
/// loading, and an absent one is a failed requirement rather than something
/// to load.  Unused until the guest can load modules, but derived here so
/// the rule lives next to the table it reads.
#[must_use]
pub fn modules_to_load(required: &[KernelFeature], config: &KernelConfig) -> Vec<&'static str> {
    required
        .iter()
        .filter(|feature| config.state(feature.symbol()) == FeatureState::Module)
        .filter_map(KernelFeature::module)
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    fn config() -> KernelConfig {
        KernelConfig::parse(
            "CONFIG_VIRTIO_FS=y\n\
             CONFIG_FUSE_FS=y\n\
             CONFIG_NET_CLS_FLOWER=m\n\
             CONFIG_VFIO=m\n\
             # CONFIG_MLX5_CORE is not set\n",
        )
    }

    #[test]
    fn builtin_and_module_both_satisfy_a_requirement() {
        let unmet = unmet_requirements(&[features::VIRTIO_FS, features::NET_CLS_FLOWER], &config());
        assert!(
            unmet.is_empty(),
            "`=y` and `=m` should both satisfy: {unmet:?}",
        );
    }

    #[test]
    fn absent_feature_is_reported() {
        let unmet = unmet_requirements(&[features::MLX5_CORE], &config());
        assert_eq!(
            unmet,
            vec![UnmetRequirement {
                symbol: "MLX5_CORE"
            }],
        );
    }

    /// A kernel missing one feature usually misses several; reporting them
    /// one boot at a time would be a poor way to discover that.
    #[test]
    fn every_unmet_requirement_is_reported_not_just_the_first() {
        let unmet = unmet_requirements(
            &[
                features::MLX5_CORE,
                features::VIRTIO_FS,
                features::HUGETLBFS,
            ],
            &config(),
        );
        let symbols: Vec<_> = unmet.iter().map(|u| u.symbol).collect();
        assert_eq!(symbols, vec!["MLX5_CORE", "HUGETLBFS"]);
    }

    /// Only `=m` features need loading.  A built-in is already there, and an
    /// absent one is a failed requirement rather than something to load.
    #[test]
    fn only_modular_features_need_loading() {
        let modules = modules_to_load(
            &[
                features::VIRTIO_FS,      // =y, already present
                features::NET_CLS_FLOWER, // =m, needs loading
                features::VFIO,           // =m, needs loading
                features::MLX5_CORE,      // absent
            ],
            &config(),
        );
        assert_eq!(modules, vec!["cls_flower", "vfio"]);
    }

    /// The symbol and the module name are not mechanically related, so both
    /// have to be carried.  `CONFIG_NET_CLS_FLOWER` builds `cls_flower.ko`.
    #[test]
    fn symbol_and_module_name_differ() {
        assert_eq!(features::NET_CLS_FLOWER.symbol(), "NET_CLS_FLOWER");
        assert_eq!(features::NET_CLS_FLOWER.module(), Some("cls_flower"));
    }

    /// A feature that cannot be modular has no module name, so nothing can
    /// try to load one that does not exist.
    #[test]
    fn builtin_only_features_have_no_module() {
        assert_eq!(features::HUGETLBFS.module(), None);
        let modules = modules_to_load(
            &[features::HUGETLBFS],
            &KernelConfig::parse("CONFIG_HUGETLBFS=y\n"),
        );
        assert!(modules.is_empty());
    }

    #[test]
    fn no_requirements_is_trivially_satisfied() {
        assert!(unmet_requirements(&[], &config()).is_empty());
        assert!(modules_to_load(&[], &config()).is_empty());
    }
}

/// Names of the kernel profiles the manifest defines.
///
/// A profile is a *(kernel, hypervisor)* pair, and which ones exist is a
/// fact about the nix build rather than about this crate -- so these are
/// names checked against the manifest at launch, not a closed enum.  They
/// are spelled out here for the same reason [`features`] is: a constant
/// gets completion and a rename becomes a build error, where a bare string
/// gets neither.
///
/// A name that is not in the manifest is reported at launch, listing the
/// ones that are.
pub mod kernel_profiles {
    /// The kernel this repo builds, booted directly under cloud-hypervisor.
    ///
    /// The manifest's default, and what a test that names no profile gets.
    pub const CLOUD_HYPERVISOR: &str = "cloud_hypervisor";

    /// The same kernel, booted directly under QEMU.
    ///
    /// Prefer [`RequestedBackend::Qemu`](crate::RequestedBackend::Qemu) to
    /// change only the hypervisor; this exists so the pair can be named as
    /// one thing when that is what is meant.
    pub const QEMU: &str = "qemu";

    /// Flatcar's distribution kernel, booted through an initramfs on QEMU.
    ///
    /// A *modular* kernel with its own module tree, which is what makes it
    /// worth having: the union kernel builds in everything, so nothing that
    /// depends on a module being loaded -- or on failing to load -- can be
    /// tested against it.
    pub const FLATCAR: &str = "flatcar";

    /// Ubuntu's distribution kernel, booted through an initramfs on QEMU.
    pub const UBUNTU: &str = "ubuntu";

    /// This repo's kernel built modular, booted through an initramfs on
    /// QEMU.
    ///
    /// The one to reach for when a test needs modules *and* a kernel whose
    /// configuration this repo controls.
    pub const MODULAR: &str = "modular";
}
