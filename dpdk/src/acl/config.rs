// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL configuration types.
//!
//! This module provides safe, validated configuration types for the two main ACL setup calls:
//!
//! - [`AclCreateParams`] — parameters for creating an ACL context
//!   ([`rte_acl_create`][dpdk_sys::rte_acl_create]).
//! - [`AclBuildConfig`]`<N>` — parameters for compiling rules into runtime lookup structures
//!   ([`rte_acl_build`][dpdk_sys::rte_acl_build]).
//!
//! Following the project convention of validating inputs at the boundary, both types perform
//! validation at construction time so that downstream code can assume the configuration is valid.

use core::ffi::CStr;
use core::fmt::{self, Debug, Display};

use std::ffi::CString;

use tracing::info;

use crate::socket::SocketId;

use super::error::InvalidAclName;
use super::field::FieldDef;
use super::rule::Rule;

// ---------------------------------------------------------------------------
// AclCreateParams
// ---------------------------------------------------------------------------

/// Validated parameters for creating an ACL context.
///
/// This is the safe Rust equivalent of [`rte_acl_param`][dpdk_sys::rte_acl_param].
/// The name is validated at construction time and stored as a [`CString`] for zero-cost FFI.
///
/// # Construction
///
/// Use [`AclCreateParams::new`] to create a validated instance.
///
/// ```ignore
/// let params = AclCreateParams::new::<5>("my_acl", SocketId::ANY, 1024)?;
/// ```
///
/// The const parameter on [`new`][AclCreateParams::new] specifies the number of fields per rule
/// so that the correct `rule_size` is computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclCreateParams {
    /// Validated ACL context name (ASCII, non-empty, no null bytes, within length limit).
    name: CString,
    /// NUMA socket on which to allocate the context's memory.
    socket_id: SocketId,
    /// Maximum number of rules this context can hold.
    max_rule_num: u32,
    /// Size of each rule in bytes (`size_of::<Rule<N>>()`).
    ///
    /// This is computed from the const generic `N` at creation time and passed to
    /// [`rte_acl_create`][dpdk_sys::rte_acl_create] as `rule_size`.
    rule_size: u32,
}

/// The maximum length (in bytes, **excluding** the null terminator) of an ACL context name.
///
/// DPDK's [`RTE_ACL_NAMESIZE`][dpdk_sys::RTE_ACL_NAMESIZE] includes the null terminator, so the
/// usable string length is one less.
pub const MAX_ACL_NAME_LEN: usize = (dpdk_sys::RTE_ACL_NAMESIZE as usize).saturating_sub(1);

impl AclCreateParams {
    /// Create validated ACL creation parameters.
    ///
    /// The const generic `N` must match the number of [`FieldDef`] entries that will be used when
    /// building the context, as well as the number of fields in every [`Rule<N>`][Rule] added to
    /// the context.  It is used here to compute the `rule_size` that DPDK requires at creation
    /// time.
    ///
    /// # Arguments
    ///
    /// * `name` — human-readable name for the context.  Must be non-empty ASCII without null
    ///   bytes, at most [`MAX_ACL_NAME_LEN`] bytes long.
    /// * `socket_id` — the NUMA socket to allocate memory on.  Use [`SocketId::ANY`] if you don't
    ///   have a preference.
    /// * `max_rule_num` — the maximum number of rules this context will hold.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAclName`] if the name fails validation.
    #[cold]
    #[tracing::instrument(level = "debug", skip(name), fields(name = name.as_ref()))]
    pub fn new<const N: usize>(
        name: impl AsRef<str>,
        socket_id: SocketId,
        max_rule_num: u32,
    ) -> Result<Self, InvalidAclName> {
        let name = Self::validate_name(name.as_ref())?;
        info!(
            "Created ACL params: name={}, socket_id={:?}, max_rule_num={}, rule_size={}",
            name.to_str().unwrap_or("<invalid>"),
            socket_id,
            max_rule_num,
            Rule::<N>::RULE_SIZE,
        );
        Ok(Self {
            name,
            socket_id,
            max_rule_num,
            rule_size: Rule::<N>::RULE_SIZE,
        })
    }

    /// Validate and convert an ACL context name to a [`CString`].
    #[cold]
    fn validate_name(name: &str) -> Result<CString, InvalidAclName> {
        if name.is_empty() {
            return Err(InvalidAclName::Empty);
        }
        if !name.is_ascii() {
            return Err(InvalidAclName::NotAscii);
        }
        if name.len() > MAX_ACL_NAME_LEN {
            return Err(InvalidAclName::TooLong {
                len: name.len(),
                max: MAX_ACL_NAME_LEN,
            });
        }
        CString::new(name).map_err(|_| InvalidAclName::ContainsNullBytes)
    }

    /// Get the context name as a `&str`.
    ///
    /// # Panics
    ///
    /// This should never panic because the name was validated as ASCII at construction time.
    #[must_use]
    pub fn name(&self) -> &str {
        #[allow(clippy::expect_used)]
        // SAFETY: The name is validated at construction time to be a valid, null-terminated ASCII
        // string.
        unsafe { CStr::from_ptr(self.name.as_ptr()) }
            .to_str()
            .expect("Unsound behavior: ACL context name is not valid UTF-8 (validated as ASCII at construction)")
    }

    /// Get the name as a [`CString`] reference, suitable for FFI.
    #[must_use]
    pub fn name_cstr(&self) -> &CStr {
        &self.name
    }

    /// Get the NUMA socket preference.
    #[must_use]
    pub fn socket_id(&self) -> SocketId {
        self.socket_id
    }

    /// Get the maximum rule count.
    #[must_use]
    pub fn max_rule_num(&self) -> u32 {
        self.max_rule_num
    }

    /// Get the per-rule byte size.
    ///
    /// This was computed from the const generic `N` at construction time and equals
    /// `core::mem::size_of::<Rule<N>>()`.
    #[must_use]
    // TODO: should rule size be `NonZero`?
    pub fn rule_size(&self) -> u32 {
        self.rule_size
    }

    /// Convert to the raw DPDK [`rte_acl_param`][dpdk_sys::rte_acl_param].
    ///
    /// # Lifetime
    ///
    /// The returned struct contains a raw pointer to the name string.  The caller **must** ensure
    /// that `self` outlives the returned [`rte_acl_param`][dpdk_sys::rte_acl_param].
    pub(crate) fn to_raw(&self) -> dpdk_sys::rte_acl_param {
        dpdk_sys::rte_acl_param {
            name: self.name.as_ptr(),
            // TODO:  this cast is awkward.  May need better strum et al integration
            //
            socket_id: self.socket_id.as_c_uint() as core::ffi::c_int,
            rule_size: self.rule_size,
            max_rule_num: self.max_rule_num,
        }
    }
}

impl Display for AclCreateParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AclCreateParams {{ name: \"{}\", socket_id: {:?}, max_rule_num: {}, rule_size: {} }}",
            self.name(),
            self.socket_id,
            self.max_rule_num,
            self.rule_size,
        )
    }
}

// ---------------------------------------------------------------------------
// AclBuildConfig
// ---------------------------------------------------------------------------

/// Maximum number of categories that can be used in an ACL context.
///
/// Corresponds to [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES].
pub const MAX_CATEGORIES: u32 = dpdk_sys::RTE_ACL_MAX_CATEGORIES;

/// The required alignment factor for the number of categories.
///
/// The `num_categories` value must be either `1` or a multiple of this value.
///
/// Corresponds to [`RTE_ACL_RESULTS_MULTIPLIER`][dpdk_sys::RTE_ACL_RESULTS_MULTIPLIER].
pub const RESULTS_MULTIPLIER: u32 = dpdk_sys::RTE_ACL_RESULTS_MULTIPLIER;

/// Maximum number of fields per ACL rule.
///
/// Corresponds to [`RTE_ACL_MAX_FIELDS`][dpdk_sys::RTE_ACL_MAX_FIELDS].
pub const MAX_FIELDS: usize = dpdk_sys::RTE_ACL_MAX_FIELDS as usize;

/// Validated build configuration for compiling ACL rules into runtime lookup structures.
///
/// This is the safe Rust equivalent of [`rte_acl_config`][dpdk_sys::rte_acl_config].
///
/// The const generic `N` must match the `N` used in the [`AclContext`][super::context::AclContext]
/// and in the [`Rule`]`<N>` type.  This is enforced by the type system — the
/// [`build`][super::context::AclContext::build] method requires an `AclBuildConfig` with the same
/// `N` as the context.
///
/// # Validation
///
/// The constructor validates:
/// - `N <= 64` ([`RTE_ACL_MAX_FIELDS`][dpdk_sys::RTE_ACL_MAX_FIELDS])
/// - `num_categories` is between 1 and [`MAX_CATEGORIES`] (inclusive)
/// - `num_categories` is 1 or a multiple of [`RESULTS_MULTIPLIER`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclBuildConfig<const N: usize> {
    /// Number of categories to build with.
    ///
    /// Must be in `1..=`[`MAX_CATEGORIES`] and either `1` or a multiple of
    /// [`RESULTS_MULTIPLIER`].
    num_categories: u32,

    /// Field definitions — one per field in the rule.
    ///
    /// The order and semantics of these definitions must match the order of
    /// [`AclField`][super::rule::AclField] entries in the [`Rule`]`<N>` instances added to the
    /// context.
    field_defs: [FieldDef; N],

    /// Maximum memory size (in bytes) for the compiled runtime structures.
    ///
    /// Set to `0` to impose no limit.
    max_size: usize,
}

/// Errors that can occur when constructing an [`AclBuildConfig`].
#[derive(Debug, thiserror::Error, Copy, Clone, PartialEq, Eq)]
pub enum InvalidAclBuildConfig {
    /// `N` exceeds [`RTE_ACL_MAX_FIELDS`][dpdk_sys::RTE_ACL_MAX_FIELDS].
    #[error("Too many fields: {num_fields} exceeds maximum of {max}")]
    TooManyFields {
        /// The number of fields that was requested.
        num_fields: usize,
        /// The maximum allowed.
        max: usize,
    },

    /// `num_categories` is zero.
    #[error("Number of categories must be at least 1")]
    ZeroCategories,

    /// `num_categories` exceeds [`MAX_CATEGORIES`].
    #[error("Number of categories {num_categories} exceeds maximum of {max}")]
    TooManyCategories {
        /// The requested number of categories.
        num_categories: u32,
        /// The maximum allowed.
        max: u32,
    },

    /// `num_categories` is greater than 1 and not a multiple of [`RESULTS_MULTIPLIER`].
    #[error("Number of categories {num_categories} must be 1 or a multiple of {multiplier}")]
    CategoriesNotAligned {
        /// The requested number of categories.
        num_categories: u32,
        /// The required alignment factor.
        multiplier: u32,
    },
}

impl<const N: usize> AclBuildConfig<N> {
    /// Create a validated build configuration.
    ///
    /// # Arguments
    ///
    /// * `num_categories` — the number of result categories.  Must be in
    ///   `1..=`[`MAX_CATEGORIES`] and either `1` or a multiple of [`RESULTS_MULTIPLIER`].
    /// * `field_defs` — the field definitions for the rule layout (one per field).
    /// * `max_size` — maximum memory (in bytes) for compiled structures, or `0` for no limit.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAclBuildConfig`] if any parameter is out of range.
    #[cold]
    #[tracing::instrument(level = "debug")]
    pub fn new(
        num_categories: u32,
        field_defs: [FieldDef; N],
        max_size: usize,
    ) -> Result<Self, InvalidAclBuildConfig> {
        if N > MAX_FIELDS {
            return Err(InvalidAclBuildConfig::TooManyFields {
                num_fields: N,
                max: MAX_FIELDS,
            });
        }
        if num_categories == 0 {
            return Err(InvalidAclBuildConfig::ZeroCategories);
        }
        if num_categories > MAX_CATEGORIES {
            return Err(InvalidAclBuildConfig::TooManyCategories {
                num_categories,
                max: MAX_CATEGORIES,
            });
        }
        if num_categories > 1 && !num_categories.is_multiple_of(RESULTS_MULTIPLIER) {
            return Err(InvalidAclBuildConfig::CategoriesNotAligned {
                num_categories,
                multiplier: RESULTS_MULTIPLIER,
            });
        }

        info!(
            "Created ACL build config: num_categories={num_categories}, num_fields={N}, max_size={max_size}",
        );

        Ok(Self {
            num_categories,
            field_defs,
            max_size,
        })
    }

    /// Get the number of categories.
    #[must_use]
    pub fn num_categories(&self) -> u32 {
        self.num_categories
    }

    /// Get the field definitions.
    #[must_use]
    pub fn field_defs(&self) -> &[FieldDef; N] {
        &self.field_defs
    }

    /// Get the maximum memory size for compiled structures.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Convert to the raw DPDK [`rte_acl_config`][dpdk_sys::rte_acl_config].
    ///
    /// The returned struct is fully owned and has no lifetime dependency on `self`.
    pub(crate) fn to_raw(&self) -> dpdk_sys::rte_acl_config {
        let mut defs = [dpdk_sys::rte_acl_field_def::default(); 64];
        for (i, def) in self.field_defs.iter().enumerate() {
            defs[i] = dpdk_sys::rte_acl_field_def::from(def);
        }
        dpdk_sys::rte_acl_config {
            num_categories: self.num_categories,
            num_fields: N as u32,
            defs,
            max_size: self.max_size,
        }
    }
}

impl<const N: usize> Display for AclBuildConfig<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AclBuildConfig<{N}> {{ num_categories: {}, max_size: {} }}",
            self.num_categories, self.max_size,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::field::{FieldSize, FieldType};

    // -- AclCreateParams name validation --

    #[test]
    fn valid_name_accepted() {
        let result = AclCreateParams::new::<5>("my_acl_ctx", SocketId::ANY, 1024);
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.name(), "my_acl_ctx");
    }

    #[test]
    fn empty_name_rejected() {
        let result = AclCreateParams::new::<1>("", SocketId::ANY, 128);
        assert!(matches!(result, Err(InvalidAclName::Empty)));
    }

    #[test]
    fn non_ascii_name_rejected() {
        let result = AclCreateParams::new::<1>("日本語", SocketId::ANY, 128);
        assert!(matches!(result, Err(InvalidAclName::NotAscii)));
    }

    #[test]
    fn too_long_name_rejected() {
        // MAX_ACL_NAME_LEN is RTE_ACL_NAMESIZE - 1 = 31
        let long_name: String = "a".repeat(MAX_ACL_NAME_LEN + 1);
        let result = AclCreateParams::new::<1>(&long_name, SocketId::ANY, 128);
        assert!(matches!(result, Err(InvalidAclName::TooLong { .. })));
    }

    #[test]
    fn max_length_name_accepted() {
        let name: String = "a".repeat(MAX_ACL_NAME_LEN);
        let result = AclCreateParams::new::<1>(&name, SocketId::ANY, 128);
        assert!(result.is_ok());
    }

    #[test]
    fn name_with_null_byte_rejected() {
        let result = AclCreateParams::new::<1>("hello\0world", SocketId::ANY, 128);
        assert!(matches!(result, Err(InvalidAclName::ContainsNullBytes)));
    }

    #[test]
    fn rule_size_matches_generic() {
        let params = AclCreateParams::new::<5>("test", SocketId::ANY, 128).unwrap();
        assert_eq!(params.rule_size() as usize, core::mem::size_of::<Rule<5>>());
    }

    #[test]
    fn to_raw_preserves_values() {
        let params = AclCreateParams::new::<3>("raw_test", SocketId::ANY, 256).unwrap();
        let raw = params.to_raw();
        // Name pointer should point to the same C string data.
        let raw_name = unsafe { CStr::from_ptr(raw.name) };
        assert_eq!(raw_name.to_str().unwrap(), "raw_test");
        assert_eq!(raw.max_rule_num, 256);
        assert_eq!(raw.rule_size as usize, core::mem::size_of::<Rule<3>>());
    }

    #[test]
    fn display_contains_name() {
        let params = AclCreateParams::new::<1>("display_test", SocketId::ANY, 10).unwrap();
        let s = alloc::format!("{params}");
        assert!(s.contains("display_test"), "got: {s}");
    }

    // -- AclBuildConfig validation --

    fn sample_field_defs<const N: usize>() -> [FieldDef; N] {
        core::array::from_fn(|i| FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: i as u8,
            input_index: i as u8,
            offset: (i * 4) as u32,
        })
    }

    #[test]
    fn valid_build_config_single_category() {
        let cfg = AclBuildConfig::new(1, sample_field_defs::<5>(), 0);
        assert!(cfg.is_ok());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.num_categories(), 1);
        assert_eq!(cfg.max_size(), 0);
        assert_eq!(cfg.field_defs().len(), 5);
    }

    #[test]
    fn valid_build_config_multiple_categories() {
        let cfg = AclBuildConfig::new(4, sample_field_defs::<3>(), 1024);
        assert!(cfg.is_ok());
        assert_eq!(cfg.unwrap().num_categories(), 4);
    }

    #[test]
    fn zero_categories_rejected() {
        let result = AclBuildConfig::new(0, sample_field_defs::<1>(), 0);
        assert!(matches!(result, Err(InvalidAclBuildConfig::ZeroCategories)));
    }

    #[test]
    fn too_many_categories_rejected() {
        let result = AclBuildConfig::new(MAX_CATEGORIES + 1, sample_field_defs::<1>(), 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::TooManyCategories { .. })
        ));
    }

    #[test]
    fn max_categories_accepted() {
        let result = AclBuildConfig::new(MAX_CATEGORIES, sample_field_defs::<1>(), 0);
        assert!(result.is_ok());
    }

    #[test]
    fn misaligned_categories_rejected() {
        // 3 is > 1 but not a multiple of RESULTS_MULTIPLIER (4)
        let result = AclBuildConfig::new(3, sample_field_defs::<1>(), 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::CategoriesNotAligned { .. })
        ));
    }

    #[test]
    fn to_raw_build_config_preserves_fields() {
        let defs: [FieldDef; 2] = [
            FieldDef {
                field_type: FieldType::Mask,
                size: FieldSize::Four,
                field_index: 0,
                input_index: 0,
                offset: 0,
            },
            FieldDef {
                field_type: FieldType::Range,
                size: FieldSize::Two,
                field_index: 1,
                input_index: 1,
                offset: 4,
            },
        ];
        let cfg = AclBuildConfig::new(1, defs, 4096).unwrap();
        let raw = cfg.to_raw();
        assert_eq!(raw.num_categories, 1);
        assert_eq!(raw.num_fields, 2);
        assert_eq!(raw.max_size, 4096);
        assert_eq!(raw.defs[0].type_, FieldType::Mask as u8);
        assert_eq!(raw.defs[0].size, FieldSize::Four as u8);
        assert_eq!(raw.defs[0].offset, 0);
        assert_eq!(raw.defs[1].type_, FieldType::Range as u8);
        assert_eq!(raw.defs[1].size, FieldSize::Two as u8);
        assert_eq!(raw.defs[1].offset, 4);
    }

    #[test]
    fn build_config_display() {
        let cfg = AclBuildConfig::new(4, sample_field_defs::<3>(), 0).unwrap();
        let s = alloc::format!("{cfg}");
        assert!(s.contains("AclBuildConfig<3>"), "got: {s}");
        assert!(s.contains("num_categories: 4"), "got: {s}");
    }
}
