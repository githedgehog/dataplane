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

/// Tokens per second: bytes per second when a meter counts bytes, packets per second when it counts
/// packets.
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

/// A MEF 10 bandwidth profile, coupled: a committed rate, and optionally an excess rate.
///
/// Green packets pay the committed bucket (C) and yellow packets the excess bucket (E). C fills at
/// the committed rate up to the committed burst, and what it earns but cannot hold goes to E, which
/// also fills at the excess rate, if there is one, up to the excess burst. So up to the committed
/// rate is green, and up to the sum of the two rates is green or yellow; idle time builds up E at
/// both rates.
///
/// Coupling (MEF 10's CF = 1) is what DPDK's `RTE_MTR_TRTCM_RFC4115` does on mlx5, so a profile
/// colors the same whether it is offloaded or not. Without an excess rate the profile is RFC 2697's
/// single rate three color marker exactly, and offloads as `RTE_MTR_SRTCM_RFC2697`. Uncoupled, it
/// would be RFC 4115.
///
/// A profile counts tokens, not bytes or packets: whoever meters with it decides what a packet costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Profile {
    committed_rate: Rate,
    committed_burst: u64,
    excess_rate: Option<Rate>,
    excess_burst: u64,
}

impl Profile {
    /// Fill the committed bucket at `committed_rate` up to `committed_burst`, and the excess bucket at
    /// `excess_rate`, if any, plus what the committed bucket overflows, up to `excess_burst`.
    ///
    /// The bursts should hold the largest packet metered: a packet larger than a bucket can never be
    /// paid from it. The policer does not know the largest packet, so it is up to whoever builds the
    /// profile.
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

/// `cir 1000/s cbs 1500 eir 500/s ebs 3000`, in tokens, leaving out an excess rate there is not.
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
