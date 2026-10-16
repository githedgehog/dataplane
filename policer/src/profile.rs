// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a meter allows: its rates and burst sizes.

use std::num::NonZeroU64;

/// Why a profile was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// A profile whose burst sizes are both zero would never pass a packet.
    #[error("the committed and excess burst sizes cannot both be zero")]
    NoBurst,
}

/// Tokens per second, in the caller's chosen unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rate(NonZeroU64);

impl Rate {
    /// A rate of `per_second` tokens a second.
    #[must_use]
    pub const fn new(per_second: NonZeroU64) -> Rate {
        Rate(per_second)
    }

    /// Tokens a second.
    #[must_use]
    pub const fn per_second(self) -> NonZeroU64 {
        self.0
    }
}

/// A coupled MEF 10 profile with committed and optional excess rates.
///
/// Green packets consume committed tokens; yellow packets consume excess tokens.
/// Committed overflow also fills the excess bucket, in addition to its own rate.
/// Without an excess rate, this is RFC 2697's single rate marker.
///
/// Rates and bursts use the caller's chosen token unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Profile {
    committed_rate: Rate,
    committed_burst: u64,
    excess_rate: Option<Rate>,
    excess_burst: u64,
}

impl Profile {
    /// Create a profile with the given rates and bucket capacities.
    ///
    /// Callers should size each nonzero bucket to hold the largest packet's token cost.
    ///
    /// # Errors
    ///
    /// Refuses a profile with no burst at all.
    //= https://www.rfc-editor.org/rfc/rfc2697#section-2
    //# The CBS and the EBS and are measured in bytes.  The CBS and EBS must
    //# be configured so that at least one of them is larger than 0.
    //
    //= https://www.rfc-editor.org/rfc/rfc4115#section-2
    //= type=exception
    //= reason=the policer does not know the largest packet; it only refuses empty buckets, and the configuration that builds the profile must size them
    //# The CBS and EBS are measured in bytes and must configure to be
    //# greater than the expected maximum length of the incoming PDU.
    //
    //= https://www.rfc-editor.org/rfc/rfc4115#section-2
    //= type=exception
    //= reason=rates are in tokens a second (bytes a second for a byte meter), as RFC 2697 measures them; the configuration converts from bits
    //# The
    //# CIR and EIR are both measured in bits/s.
    //
    //= https://www.rfc-editor.org/rfc/rfc4115#section-2
    //# The CIR and EIR can be set
    //# independently of each other.
    pub fn new(
        committed_rate: Rate,
        committed_burst: u64,
        excess_rate: Option<Rate>,
        excess_burst: u64,
    ) -> Result<Profile, ProfileError> {
        if committed_burst == 0 && excess_burst == 0 {
            return Err(ProfileError::NoBurst);
        }
        Ok(Profile {
            committed_rate,
            committed_burst,
            excess_rate,
            excess_burst,
        })
    }

    /// The rate the committed bucket fills at (CIR).
    #[must_use]
    pub fn committed_rate(&self) -> Rate {
        self.committed_rate
    }

    /// The committed bucket's size (CBS).
    #[must_use]
    pub fn committed_burst(&self) -> u64 {
        self.committed_burst
    }

    /// The rate the excess bucket fills at besides the committed bucket's overflow (EIR), if any.
    #[must_use]
    pub fn excess_rate(&self) -> Option<Rate> {
        self.excess_rate
    }

    /// The excess bucket's size (EBS).
    #[must_use]
    pub fn excess_burst(&self) -> u64 {
        self.excess_burst
    }
}

impl std::fmt::Display for Rate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/s", self.0)
    }
}

/// Format rates and bursts in tokens, omitting EIR when unset.
impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cir {} cbs {}",
            self.committed_rate, self.committed_burst
        )?;
        if let Some(excess_rate) = self.excess_rate {
            write!(f, " eir {excess_rate}")?;
        }
        write!(f, " ebs {}", self.excess_burst)
    }
}
