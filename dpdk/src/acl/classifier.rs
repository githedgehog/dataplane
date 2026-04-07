// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Runtime-sized ACL classifier.
//!
//! [`AclClassifier`] provides the same DPDK ACL functionality as
//! [`AclContext<N>`](super::context::AclContext) but without requiring
//! the field count as a const generic.  The field count is provided
//! at construction time and validated dynamically.
//!
//! This is suitable for compilers that determine the field layout at
//! runtime (e.g., from signature grouping or user-defined rule sets).
//!
//! # Lifecycle
//!
//! ```text
//! AclClassifierBuilder::new(...)
//!     .add_rules(&[...])
//!     .build(num_categories, &field_defs)  →  AclClassifier
//!                                              .classify(input, results, categories)
//! ```

use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;
use core::ptr::NonNull;

use tracing::{debug, error, info};

use crate::acl::error::{AclAddRulesError, AclBuildError, AclClassifyError, AclCreateError};
use crate::acl::field::FieldDef;
use crate::acl::rule::{AclField, RuleData};
use crate::socket::SocketId;
use errno::Errno;

/// A rule with runtime-determined field count.
///
/// This is the runtime-sized equivalent of
/// [`Rule<N>`](super::rule::Rule).
#[derive(Debug, Clone)]
pub struct AclRule {
    /// Rule metadata: category mask, priority, and user data.
    pub data: RuleData,
    /// Field values.  Length must equal the classifier's field count.
    pub fields: Vec<AclField>,
}

/// Builder for an [`AclClassifier`].
///
/// Accumulates rules and then compiles them into an optimised
/// runtime lookup structure.
#[derive(Debug)]
pub struct AclClassifierBuilder {
    ctx: NonNull<dpdk_sys::rte_acl_ctx>,
    name: CString,
    num_fields: usize,
}

// SAFETY: the DPDK context handle is a heap allocation, not tied to
// any thread.  Mutation requires &mut self.
unsafe impl Send for AclClassifierBuilder {}
unsafe impl Sync for AclClassifierBuilder {}

impl AclClassifierBuilder {
    /// Create a new classifier builder.
    ///
    /// # Arguments
    ///
    /// * `name` — human-readable name for the DPDK context.
    /// * `socket_id` — NUMA socket to allocate on.
    /// * `max_rules` — maximum number of rules.
    /// * `num_fields` — number of fields per rule.
    pub fn new(
        name: impl AsRef<str>,
        socket_id: SocketId,
        max_rules: u32,
        num_fields: usize,
    ) -> Result<Self, AclCreateError> {
        let name_str = name.as_ref();
        let c_name = CString::new(name_str).map_err(|_| AclCreateError::InvalidParams)?;

        // rule_size must match the C struct layout: RuleData + alignment padding + fields.
        // AclField has 8-byte alignment (contains u64 union), so there may be padding
        // between the 12-byte RuleData and the first AclField.
        let field_align = core::mem::align_of::<AclField>();
        let data_size = core::mem::size_of::<RuleData>();
        let padded_data = (data_size + field_align - 1) & !(field_align - 1);
        let rule_size = padded_data + num_fields * core::mem::size_of::<AclField>();

        let raw_params = dpdk_sys::rte_acl_param {
            name: c_name.as_ptr(),
            socket_id: socket_id.as_c_uint() as core::ffi::c_int,
            rule_size: rule_size as u32,
            max_rule_num: max_rules,
        };

        let ctx_ptr = unsafe { dpdk_sys::rte_acl_create(&raw_params) };

        let ctx = match NonNull::new(ctx_ptr) {
            Some(ptr) => ptr,
            None => {
                let rte_errno = unsafe { dpdk_sys::rte_errno_get() };
                error!(
                    "rte_acl_create failed for '{}': rte_errno = {rte_errno}",
                    name_str,
                );
                return Err(match rte_errno {
                    errno::EINVAL => AclCreateError::InvalidParams,
                    errno::ENOMEM => AclCreateError::OutOfMemory,
                    other => AclCreateError::Unknown(Errno(other)),
                });
            }
        };

        info!(
            "Created ACL classifier '{}' (num_fields={}, max_rules={}, rule_size={})",
            name_str, num_fields, max_rules, rule_size,
        );

        Ok(Self {
            ctx,
            name: c_name,
            num_fields,
        })
    }

    /// Add rules to the classifier.
    ///
    /// Each rule's `fields` slice must have exactly `num_fields` elements
    /// (as specified at construction time).
    ///
    /// # Panics
    ///
    /// Panics if any rule has the wrong number of fields.
    pub fn add_rules(
        &mut self,
        rules: impl AsRef<[AclRule]>,
    ) -> Result<&mut Self, AclAddRulesError> {
        let rules = rules.as_ref();
        if rules.is_empty() {
            return Ok(self);
        }

        // Validate field counts.
        for (i, rule) in rules.iter().enumerate() {
            assert_eq!(
                rule.fields.len(),
                self.num_fields,
                "rule {i} has {} fields, expected {}",
                rule.fields.len(),
                self.num_fields,
            );
        }

        // Pack rules into contiguous memory matching the C struct layout.
        // Each rule is: RuleData + alignment padding + N × AclField.
        let field_align = core::mem::align_of::<AclField>();
        let data_size = core::mem::size_of::<RuleData>();
        let padded_data = (data_size + field_align - 1) & !(field_align - 1);
        let rule_size = padded_data + self.num_fields * core::mem::size_of::<AclField>();
        let mut buf = vec![0u8; rules.len() * rule_size];

        for (i, rule) in rules.iter().enumerate() {
            let offset = i * rule_size;
            // Write RuleData at the start.
            // SAFETY: RuleData is #[repr(C)] and we're reading its bytes.
            let data_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    &rule.data as *const RuleData as *const u8,
                    data_size,
                )
            };
            buf[offset..offset + data_size].copy_from_slice(data_bytes);
            // Padding bytes (offset + data_size .. offset + padded_data) are already zero.

            // Write fields after the padding.
            let fields_offset = offset + padded_data;
            // SAFETY: AclField is #[repr(C)] and we're reading the array bytes.
            let fields_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    rule.fields.as_ptr() as *const u8,
                    rule.fields.len() * core::mem::size_of::<AclField>(),
                )
            };
            buf[fields_offset..fields_offset + fields_bytes.len()]
                .copy_from_slice(fields_bytes);
        }

        let num: u32 = rules.len().try_into().map_err(|_| {
            error!("Rule count {} exceeds u32::MAX", rules.len());
            AclAddRulesError::InvalidParams
        })?;

        let ret = unsafe {
            dpdk_sys::rte_acl_add_rules(
                self.ctx.as_ptr(),
                buf.as_ptr() as *const dpdk_sys::rte_acl_rule,
                num,
            )
        };

        if ret != 0 {
            error!(
                "rte_acl_add_rules failed for '{}': ret = {ret}",
                self.name.to_str().unwrap_or("<invalid>"),
            );
            return Err(match ret {
                errno::NEG_ENOMEM => AclAddRulesError::OutOfMemory,
                errno::NEG_EINVAL => AclAddRulesError::InvalidParams,
                other => AclAddRulesError::Unknown(Errno(other)),
            });
        }

        debug!(
            "Added {} rules to ACL classifier '{}'",
            rules.len(),
            self.name.to_str().unwrap_or("<invalid>"),
        );
        Ok(self)
    }

    /// Compile the rules into an optimised lookup structure.
    ///
    /// Consumes the builder and returns a ready-to-classify
    /// [`AclClassifier`].
    pub fn build(
        self,
        num_categories: u32,
        field_defs: impl AsRef<[FieldDef]>,
    ) -> Result<AclClassifier, AclBuildError> {
        let field_defs = field_defs.as_ref();
        assert_eq!(
            field_defs.len(),
            self.num_fields,
            "field_defs has {} entries, expected {}",
            field_defs.len(),
            self.num_fields,
        );

        let mut raw_defs = [dpdk_sys::rte_acl_field_def::default(); 64];
        for (i, def) in field_defs.iter().enumerate() {
            raw_defs[i] = dpdk_sys::rte_acl_field_def::from(def);
        }

        let raw_cfg = dpdk_sys::rte_acl_config {
            num_categories,
            num_fields: self.num_fields as u32,
            defs: raw_defs,
            max_size: 0,
        };

        let ret = unsafe { dpdk_sys::rte_acl_build(self.ctx.as_ptr(), &raw_cfg) };

        if ret != 0 {
            error!(
                "rte_acl_build failed for '{}': ret = {ret}",
                self.name.to_str().unwrap_or("<invalid>"),
            );
            // Drop self (which frees the context) and return error.
            return Err(match ret {
                errno::NEG_ENOMEM => AclBuildError::OutOfMemory,
                errno::NEG_EINVAL => AclBuildError::InvalidConfig,
                other => AclBuildError::Unknown(Errno(other)),
            });
        }

        info!(
            "Built ACL classifier '{}' (num_fields={}, num_categories={})",
            self.name.to_str().unwrap_or("<invalid>"),
            self.num_fields,
            num_categories,
        );

        // Transfer ownership — prevent Drop from freeing the context.
        let ctx = self.ctx;
        let name = self.name.clone();
        core::mem::forget(self);

        Ok(AclClassifier { ctx, name })
    }
}

impl Drop for AclClassifierBuilder {
    fn drop(&mut self) {
        debug!(
            "Freeing ACL classifier builder '{}'",
            self.name.to_str().unwrap_or("<invalid>"),
        );
        unsafe { dpdk_sys::rte_acl_free(self.ctx.as_ptr()) };
    }
}

/// A compiled, ready-to-classify DPDK ACL context.
///
/// Created by [`AclClassifierBuilder::build`].  Classification is
/// thread-safe (`&self`).
#[derive(Debug)]
pub struct AclClassifier {
    ctx: NonNull<dpdk_sys::rte_acl_ctx>,
    name: CString,
}

// SAFETY: DPDK documents rte_acl_classify as thread-safe.
unsafe impl Send for AclClassifier {}
unsafe impl Sync for AclClassifier {}

impl AclClassifier {
    /// Classify a single input buffer against the compiled rules.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `input` points to a buffer with
    /// at least as many bytes as the largest `offset + size` in the
    /// field definitions used to build this classifier.
    pub unsafe fn classify(
        &self,
        input: *const u8,
        results: &mut [u32],
        categories: u32,
    ) -> Result<(), AclClassifyError> {
        let mut data = [input];
        // SAFETY: single-element array, caller guarantees input validity.
        unsafe { self.classify_batch(data.as_mut_ptr(), results, 1, categories) }
    }

    /// Classify a batch of input buffers against the compiled rules.
    ///
    /// `results` must have at least `num_packets * categories` elements,
    /// laid out as `[pkt0_cat0, pkt0_cat1, ..., pkt1_cat0, ...]`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `input` points to an array of `num_packets` valid pointers
    /// - each pointer in the array points to a buffer matching the
    ///   field definitions
    /// - `results` has at least `num_packets * categories` elements
    pub unsafe fn classify_batch(
        &self,
        input: *mut *const u8,
        results: &mut [u32],
        num_packets: u32,
        categories: u32,
    ) -> Result<(), AclClassifyError> {
        // SAFETY: caller guarantees input points to num_packets valid
        // buffers matching the field layout, and results is correctly sized.
        let ret = unsafe {
            dpdk_sys::rte_acl_classify(
                self.ctx.as_ptr(),
                input,
                results.as_mut_ptr(),
                num_packets,
                categories,
            )
        };

        if ret != 0 {
            return Err(AclClassifyError::InvalidArgs);
        }
        Ok(())
    }

    /// Get the context name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.to_str().unwrap_or("<invalid>")
    }
}

impl Drop for AclClassifier {
    fn drop(&mut self) {
        debug!(
            "Freeing ACL classifier '{}'",
            self.name.to_str().unwrap_or("<invalid>"),
        );
        unsafe { dpdk_sys::rte_acl_free(self.ctx.as_ptr()) };
    }
}
