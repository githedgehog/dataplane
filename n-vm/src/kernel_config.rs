// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reading a kernel's own `.config`, so that what a test *requires* can be
//! checked against what its kernel actually *provides*.
//!
//! # Why this exists
//!
//! The set of features a kernel provides is declared independently of the
//! tests -- by config fragments for a kernel we build, by someone else's
//! build entirely for a distro kernel.  Nothing stops a test from needing a
//! symbol its kernel does not have.
//!
//! Without a check, that failure surfaces as whatever the missing feature
//! breaks: a socket option returning `ENOPROTOOPT`, a `tc` filter that will
//! not attach, a mount that fails for no stated reason -- deep inside a test
//! body, in a VM, with no hint that the kernel is the cause.  With one, it
//! surfaces before boot as the name of the missing symbol.
//!
//! That difference matters most for the case this is all aimed at: running
//! the suite against the production kernel we ship on.  A skipped test with
//! *"requires `CONFIG_NET_CLS_FLOWER`, kernel has it `n`"* is a finding
//! about production.  The same test failing obscurely is noise, and noise in
//! that position gets muted.
//!
//! # What a value means
//!
//! Kconfig has three states, and the distinction between two of them is the
//! whole reason foreign kernels are hard:
//!
//! - `y` -- built into the image, available the instant it boots;
//! - `m` -- a separate `.ko` that something must load first;
//! - absent (or `# CONFIG_X is not set`) -- not there at all.
//!
//! A requirement is satisfied by `y` *or* `m`, but `m` additionally implies
//! a module to load, which is why [`FeatureState`] keeps them apart rather
//! than collapsing to a boolean.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Whether a kernel provides a feature, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureState {
    /// Compiled into the image (`=y`).  Usable immediately at boot.
    BuiltIn,
    /// Built as a loadable module (`=m`).  Present, but something has to
    /// `insmod` it before the feature works.
    Module,
    /// Not configured, or explicitly `# CONFIG_X is not set`.
    Absent,
}

impl FeatureState {
    /// Whether the feature is present at all, in either form.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::BuiltIn | Self::Module)
    }

    /// Whether using this feature requires loading a module first.
    #[must_use]
    pub const fn needs_module_load(self) -> bool {
        matches!(self, Self::Module)
    }
}

/// A parsed kernel `.config`.
///
/// Only tristate symbols are retained.  String and integer options
/// (`CONFIG_LOCALVERSION="..."`, `CONFIG_HZ=250`) are parsed but recorded as
/// [`FeatureState::BuiltIn`], since for the purpose of "does this kernel
/// have X" a symbol with a value is present.
#[derive(Debug, Clone, Default)]
pub struct KernelConfig {
    /// Symbol name *without* the `CONFIG_` prefix, mapped to its state.
    symbols: BTreeMap<String, FeatureState>,
}

impl KernelConfig {
    /// Reads and parses a kernel config file.
    ///
    /// # Errors
    ///
    /// Returns [`KernelConfigError::Read`] if the file cannot be read.
    pub fn load(path: &Path) -> Result<Self, KernelConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| KernelConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Ok(Self::parse(&raw))
    }

    /// Parses a kernel config from its text.
    ///
    /// Unparseable lines are ignored rather than rejected.  A `.config` is
    /// generated, not hand-written, and it carries banner comments and blank
    /// lines throughout; refusing to read one because of an unrecognized
    /// line would fail closed on a file that is almost certainly fine.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut symbols = BTreeMap::new();

        for line in raw.lines() {
            let line = line.trim();

            // `# CONFIG_X is not set` is how Kconfig spells an explicit
            // "no".  It is a comment, so it has to be matched before
            // comments are skipped -- and it is worth capturing rather than
            // treating as absent-by-omission, because it distinguishes
            // "considered and disabled" from "this symbol does not exist in
            // this kernel version at all".
            if let Some(rest) = line.strip_prefix("# CONFIG_") {
                if let Some(name) = rest.strip_suffix(" is not set") {
                    symbols.insert(name.to_owned(), FeatureState::Absent);
                }
                continue;
            }

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some(rest) = line.strip_prefix("CONFIG_") else {
                continue;
            };
            let Some((name, value)) = rest.split_once('=') else {
                continue;
            };

            let state = match value {
                "y" => FeatureState::BuiltIn,
                "m" => FeatureState::Module,
                "n" => FeatureState::Absent,
                // A string or integer option: present, with a value.
                _ => FeatureState::BuiltIn,
            };
            symbols.insert(name.to_owned(), state);
        }

        Self { symbols }
    }

    /// The state of one symbol, named *without* the `CONFIG_` prefix.
    ///
    /// A symbol the config never mentions is [`FeatureState::Absent`]: an
    /// unset Kconfig symbol and one that does not exist are
    /// indistinguishable to a running kernel.
    #[must_use]
    pub fn state(&self, symbol: &str) -> FeatureState {
        self.symbols
            .get(symbol)
            .copied()
            .unwrap_or(FeatureState::Absent)
    }

    /// Whether the kernel provides this symbol as either `y` or `m`.
    #[must_use]
    pub fn provides(&self, symbol: &str) -> bool {
        self.state(symbol).is_available()
    }

    /// How many symbols were parsed.  Useful to sanity-check that a config
    /// was actually read rather than silently empty.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the config is empty, which almost always means the file was
    /// not a kernel config at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

/// Errors reading a kernel config.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum KernelConfigError {
    /// The config file could not be read.
    #[error("cannot read kernel config at {path:?}")]
    #[diagnostic(
        code(n_vm::kernel_config_read),
        help(
            "the config is recorded beside the kernel image by the nix build; \
              re-run `just setup-roots` from the workspace root"
        )
    )]
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

#[cfg(test)]
mod test {
    use super::*;

    const SAMPLE: &str = r#"
#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 6.18.20 Kernel Configuration
#
CONFIG_VIRTIO_FS=y
CONFIG_FUSE_FS=y
CONFIG_NET_CLS_FLOWER=m
# CONFIG_MLX5_CORE is not set
CONFIG_LOCALVERSION="-fancy"
CONFIG_HZ=250
"#;

    #[test]
    fn distinguishes_builtin_module_and_absent() {
        let config = KernelConfig::parse(SAMPLE);
        assert_eq!(config.state("VIRTIO_FS"), FeatureState::BuiltIn);
        assert_eq!(config.state("NET_CLS_FLOWER"), FeatureState::Module);
        assert_eq!(config.state("MLX5_CORE"), FeatureState::Absent);
    }

    /// `y` and `m` both satisfy a requirement, but only `m` implies there is
    /// a module to load -- which is the distinction the whole foreign-kernel
    /// path turns on.
    #[test]
    fn module_is_available_but_needs_loading() {
        let config = KernelConfig::parse(SAMPLE);
        assert!(config.provides("NET_CLS_FLOWER"));
        assert!(config.state("NET_CLS_FLOWER").needs_module_load());
        assert!(config.provides("VIRTIO_FS"));
        assert!(!config.state("VIRTIO_FS").needs_module_load());
    }

    /// A symbol the config never mentions must read as absent, not panic or
    /// default to present: an unset symbol and a nonexistent one are the
    /// same to a running kernel.
    #[test]
    fn unmentioned_symbol_is_absent() {
        let config = KernelConfig::parse(SAMPLE);
        assert_eq!(
            config.state("SOME_SYMBOL_THAT_DOES_NOT_EXIST"),
            FeatureState::Absent
        );
        assert!(!config.provides("SOME_SYMBOL_THAT_DOES_NOT_EXIST"));
    }

    /// `# CONFIG_X is not set` is a comment, so it must be matched before
    /// comments are skipped.  Getting this backwards silently loses every
    /// explicit disable in the file.
    #[test]
    fn explicit_not_set_is_recorded_not_skipped_as_comment() {
        let config = KernelConfig::parse(SAMPLE);
        assert_eq!(config.state("MLX5_CORE"), FeatureState::Absent);
        assert!(
            config.len() >= 5,
            "banner comments should not be parsed as symbols, but real \
             entries should survive; got {} symbols",
            config.len(),
        );
    }

    /// String and integer options are not tristates, but for "does this
    /// kernel have X" a symbol with a value is present.
    #[test]
    fn valued_options_count_as_present() {
        let config = KernelConfig::parse(SAMPLE);
        assert!(config.provides("LOCALVERSION"));
        assert!(config.provides("HZ"));
    }

    /// A `.config` is generated and full of banners and blank lines, so
    /// parsing must tolerate them rather than fail closed on a good file.
    #[test]
    fn tolerates_comments_and_blank_lines() {
        let config = KernelConfig::parse("\n\n# a comment\n\nCONFIG_A=y\n   \nCONFIG_B=m\n");
        assert_eq!(config.len(), 2);
        assert_eq!(config.state("A"), FeatureState::BuiltIn);
        assert_eq!(config.state("B"), FeatureState::Module);
    }

    /// The `CONFIG_` prefix is stripped on the way in, so callers name
    /// symbols one way only.  Passing a prefixed name is a mistake that
    /// would otherwise silently read as absent.
    #[test]
    fn symbols_are_stored_without_the_config_prefix() {
        let config = KernelConfig::parse("CONFIG_VIRTIO_FS=y\n");
        assert!(config.provides("VIRTIO_FS"));
        assert!(!config.provides("CONFIG_VIRTIO_FS"));
    }

    #[test]
    fn empty_input_yields_an_empty_config() {
        let config = KernelConfig::parse("");
        assert!(config.is_empty());
        assert_eq!(config.len(), 0);
    }
}
