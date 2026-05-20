// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL classification algorithm selection.
//!
//! DPDK provides multiple SIMD-accelerated implementations of its ACL classification engine.
//! The [`ClassifyAlgorithm`] enum exposes these as a safe Rust type that can be used with
//! [`AclContext::classify_with_algorithm`][super::context::AclContext] or
//! [`AclContext::set_default_algorithm`][super::context::AclContext].
//!
//! In most cases [`ClassifyAlgorithm::Default`] is the right choice -- DPDK will automatically
//! select the best implementation for the current CPU at build time.  Explicit selection is useful
//! for benchmarking or for targeting a specific code path.

use core::fmt::{self, Display, Formatter};

// ---------------------------------------------------------------------------
// ClassifyAlgorithm
// ---------------------------------------------------------------------------

/// SIMD implementation to use for ACL classification.
///
/// Maps 1:1 to the `RTE_ACL_CLASSIFY_*` constants in
/// [`rte_acl_classify_alg`][mod@dpdk_sys::rte_acl_classify_alg].
///
/// # Platform support
///
/// Not every variant is available on every CPU.  Requesting an unsupported algorithm will result
/// in an error from [`rte_acl_classify_alg`][fn@dpdk_sys::rte_acl_classify_alg] or
/// [`rte_acl_set_ctx_classify`][dpdk_sys::rte_acl_set_ctx_classify].
/// [`Default`][ClassifyAlgorithm::Default] is always available and is recommended unless you have
/// a specific reason to select a particular implementation.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum ClassifyAlgorithm {
    /// Let DPDK choose the best available implementation for the current CPU.
    ///
    /// This is almost always what you want.
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_DEFAULT`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_DEFAULT].
    ///
    /// # Asymmetry between the two DPDK entry points
    ///
    /// `Default` carries different meaning across DPDK's two algorithm-selection paths:
    ///
    /// - [`rte_acl_set_ctx_classify(ctx, DEFAULT)`][dpdk_sys::rte_acl_set_ctx_classify]
    ///   expands `DEFAULT` to the best available implementation on the current
    ///   CPU (this is the "DPDK choose best" semantics).
    /// - [`rte_acl_classify_alg(ctx, ..., DEFAULT)`][fn@dpdk_sys::rte_acl_classify_alg]
    ///   indexes table slot 0 in the dispatch table, which is the scalar
    ///   implementation -- *not* "DPDK choose best".
    ///
    /// To make `Default` mean the same thing through either Rust entry point,
    /// [`AclContext::classify_with_algorithm`][super::context::AclContext::classify_with_algorithm]
    /// special-cases `Default` to dispatch via
    /// [`rte_acl_classify`][dpdk_sys::rte_acl_classify] (which uses the
    /// context's currently-set algorithm) instead of through
    /// `rte_acl_classify_alg`.  Use [`Scalar`][ClassifyAlgorithm::Scalar]
    /// explicitly if you want the scalar implementation.
    #[default]
    Default = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_DEFAULT,

    /// Portable scalar (non-SIMD) implementation.
    ///
    /// Available on all platforms.  Useful as a baseline for benchmarks.
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_SCALAR`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_SCALAR].
    Scalar = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_SCALAR,

    /// SSE 4.1 vectorized implementation.
    ///
    /// Requires x86-64 SSE 4.1 support.
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_SSE`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_SSE].
    Sse = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_SSE,

    /// AVX2 vectorized implementation.
    ///
    /// Requires x86-64 AVX2 support.
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_AVX2`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX2].
    Avx2 = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX2,

    /// ARM NEON vectorized implementation.
    ///
    /// Requires AArch64 NEON support.
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_NEON`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_NEON].
    Neon = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_NEON,

    /// PowerPC AltiVec vectorized implementation.
    ///
    /// Requires PowerPC AltiVec / VMX support.
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_ALTIVEC`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_ALTIVEC].
    Altivec = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_ALTIVEC,

    /// AVX-512 vectorized implementation processing 16 flows in parallel.
    ///
    /// Requires x86-64 AVX-512 support (specifically AVX-512BW).
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_AVX512X16`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX512X16].
    Avx512x16 = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX512X16,

    /// AVX-512 vectorized implementation processing 32 flows in parallel.
    ///
    /// Requires x86-64 AVX-512 support (specifically AVX-512BW).
    ///
    /// Corresponds to
    /// [`RTE_ACL_CLASSIFY_AVX512X32`][dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX512X32].
    Avx512x32 = dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX512X32,
}

impl ClassifyAlgorithm {
    /// Convert to the raw `u32` discriminant value expected by the DPDK C API.
    #[must_use]
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Attempt to parse a raw `u32` into a [`ClassifyAlgorithm`].
    ///
    /// Returns `None` if the value does not correspond to a known algorithm.
    /// See also the [`TryFrom<u32>`] impl, which is the same operation framed as the
    /// idiomatic conversion trait.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            x if x == Self::Default as u32 => Some(Self::Default),
            x if x == Self::Scalar as u32 => Some(Self::Scalar),
            x if x == Self::Sse as u32 => Some(Self::Sse),
            x if x == Self::Avx2 as u32 => Some(Self::Avx2),
            x if x == Self::Neon as u32 => Some(Self::Neon),
            x if x == Self::Altivec as u32 => Some(Self::Altivec),
            x if x == Self::Avx512x16 as u32 => Some(Self::Avx512x16),
            x if x == Self::Avx512x32 as u32 => Some(Self::Avx512x32),
            _ => None,
        }
    }

    /// Returns `true` if this is an x86-64 specific algorithm variant.
    #[must_use]
    pub const fn is_x86_64(&self) -> bool {
        matches!(
            self,
            Self::Sse | Self::Avx2 | Self::Avx512x16 | Self::Avx512x32
        )
    }

    /// Returns `true` if this is an ARM specific algorithm variant.
    #[must_use]
    pub const fn is_aarch64(&self) -> bool {
        matches!(self, Self::Neon)
    }

    /// Returns `true` if this is a PowerPC specific algorithm variant.
    #[must_use]
    pub const fn is_powerpc(&self) -> bool {
        matches!(self, Self::Altivec)
    }

    /// Returns `true` if this is a platform-independent variant.
    #[must_use]
    pub const fn is_portable(&self) -> bool {
        matches!(self, Self::Default | Self::Scalar)
    }
}

impl Display for ClassifyAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "Default"),
            Self::Scalar => write!(f, "Scalar"),
            Self::Sse => write!(f, "SSE"),
            Self::Avx2 => write!(f, "AVX2"),
            Self::Neon => write!(f, "NEON"),
            Self::Altivec => write!(f, "AltiVec"),
            Self::Avx512x16 => write!(f, "AVX-512 (x16)"),
            Self::Avx512x32 => write!(f, "AVX-512 (x32)"),
        }
    }
}

impl From<ClassifyAlgorithm> for dpdk_sys::rte_acl_classify_alg::Type {
    #[inline]
    fn from(alg: ClassifyAlgorithm) -> Self {
        alg.as_u32()
    }
}

/// Unknown algorithm discriminant returned by [`ClassifyAlgorithm::try_from`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown rte_acl_classify_alg discriminant {0}")]
pub struct UnknownClassifyAlgorithm(pub u32);

impl TryFrom<u32> for ClassifyAlgorithm {
    type Error = UnknownClassifyAlgorithm;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::from_u32(value).ok_or(UnknownClassifyAlgorithm(value))
    }
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

/// Verify that our enum discriminants match the DPDK constants exactly.
const _: () = {
    use dpdk_sys::rte_acl_classify_alg::*;

    assert!(ClassifyAlgorithm::Default as u32 == RTE_ACL_CLASSIFY_DEFAULT);
    assert!(ClassifyAlgorithm::Scalar as u32 == RTE_ACL_CLASSIFY_SCALAR);
    assert!(ClassifyAlgorithm::Sse as u32 == RTE_ACL_CLASSIFY_SSE);
    assert!(ClassifyAlgorithm::Avx2 as u32 == RTE_ACL_CLASSIFY_AVX2);
    assert!(ClassifyAlgorithm::Neon as u32 == RTE_ACL_CLASSIFY_NEON);
    assert!(ClassifyAlgorithm::Altivec as u32 == RTE_ACL_CLASSIFY_ALTIVEC);
    assert!(ClassifyAlgorithm::Avx512x16 as u32 == RTE_ACL_CLASSIFY_AVX512X16);
    assert!(ClassifyAlgorithm::Avx512x32 as u32 == RTE_ACL_CLASSIFY_AVX512X32);
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zero() {
        assert_eq!(ClassifyAlgorithm::Default.as_u32(), 0);
        assert_eq!(ClassifyAlgorithm::default(), ClassifyAlgorithm::Default);
    }

    #[test]
    fn round_trip_all_variants() {
        let variants = [
            ClassifyAlgorithm::Default,
            ClassifyAlgorithm::Scalar,
            ClassifyAlgorithm::Sse,
            ClassifyAlgorithm::Avx2,
            ClassifyAlgorithm::Neon,
            ClassifyAlgorithm::Altivec,
            ClassifyAlgorithm::Avx512x16,
            ClassifyAlgorithm::Avx512x32,
        ];
        for variant in variants {
            let raw = variant.as_u32();
            let parsed = ClassifyAlgorithm::from_u32(raw);
            assert_eq!(parsed, Some(variant), "round-trip failed for {variant}");
        }
    }

    #[test]
    fn from_u32_rejects_unknown() {
        assert_eq!(ClassifyAlgorithm::from_u32(99), None);
        assert_eq!(ClassifyAlgorithm::from_u32(u32::MAX), None);
    }

    #[test]
    fn display_all_variants() {
        let display_strings = [
            (ClassifyAlgorithm::Default, "Default"),
            (ClassifyAlgorithm::Scalar, "Scalar"),
            (ClassifyAlgorithm::Sse, "SSE"),
            (ClassifyAlgorithm::Avx2, "AVX2"),
            (ClassifyAlgorithm::Neon, "NEON"),
            (ClassifyAlgorithm::Altivec, "AltiVec"),
            (ClassifyAlgorithm::Avx512x16, "AVX-512 (x16)"),
            (ClassifyAlgorithm::Avx512x32, "AVX-512 (x32)"),
        ];
        for (variant, expected) in display_strings {
            assert_eq!(format!("{variant}"), expected);
        }
    }

    #[test]
    fn platform_classification() {
        assert!(ClassifyAlgorithm::Default.is_portable());
        assert!(ClassifyAlgorithm::Scalar.is_portable());

        assert!(ClassifyAlgorithm::Sse.is_x86_64());
        assert!(ClassifyAlgorithm::Avx2.is_x86_64());
        assert!(ClassifyAlgorithm::Avx512x16.is_x86_64());
        assert!(ClassifyAlgorithm::Avx512x32.is_x86_64());

        assert!(ClassifyAlgorithm::Neon.is_aarch64());
        assert!(ClassifyAlgorithm::Altivec.is_powerpc());

        // Cross-checks: portable variants should not be platform-specific.
        assert!(!ClassifyAlgorithm::Default.is_x86_64());
        assert!(!ClassifyAlgorithm::Default.is_aarch64());
        assert!(!ClassifyAlgorithm::Default.is_powerpc());

        // Platform-specific variants should not be portable.
        assert!(!ClassifyAlgorithm::Sse.is_portable());
        assert!(!ClassifyAlgorithm::Neon.is_portable());
        assert!(!ClassifyAlgorithm::Altivec.is_portable());
    }

    #[test]
    fn into_dpdk_type() {
        let alg = ClassifyAlgorithm::Avx2;
        let raw: dpdk_sys::rte_acl_classify_alg::Type = alg.into();
        assert_eq!(raw, dpdk_sys::rte_acl_classify_alg::RTE_ACL_CLASSIFY_AVX2);
    }

    /// All known discriminants -- the universe `from_u32` must accept and the
    /// universe `as_u32` round-trips through.
    const KNOWN: &[ClassifyAlgorithm] = &[
        ClassifyAlgorithm::Default,
        ClassifyAlgorithm::Scalar,
        ClassifyAlgorithm::Sse,
        ClassifyAlgorithm::Avx2,
        ClassifyAlgorithm::Neon,
        ClassifyAlgorithm::Altivec,
        ClassifyAlgorithm::Avx512x16,
        ClassifyAlgorithm::Avx512x32,
    ];

    /// Property: for every `u32`, `from_u32` either round-trips through `as_u32`
    /// (when the value is a known discriminant) or rejects with `None` (when it
    /// is not).  Generalises the hand-rolled `round_trip_all_variants` test over
    /// the entire `u32` domain.
    #[test]
    fn from_u32_round_trip_property() {
        bolero::check!().with_type::<u32>().for_each(
            |value: &u32| match ClassifyAlgorithm::from_u32(*value) {
                Some(alg) => assert_eq!(
                    alg.as_u32(),
                    *value,
                    "from_u32({value}) -> {alg:?} but {alg:?}.as_u32() = {}",
                    alg.as_u32()
                ),
                None => {
                    for variant in KNOWN {
                        assert_ne!(
                            variant.as_u32(),
                            *value,
                            "from_u32({value}) returned None but {variant:?} has that discriminant"
                        );
                    }
                }
            },
        );
    }

    /// Property: `TryFrom<u32>` matches `from_u32` exactly.
    #[test]
    fn try_from_matches_from_u32() {
        bolero::check!().with_type::<u32>().for_each(|value: &u32| {
            let opt = ClassifyAlgorithm::from_u32(*value);
            let res = ClassifyAlgorithm::try_from(*value).ok();
            assert_eq!(opt, res);
        });
    }
}
