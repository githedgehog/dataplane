// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a meter allows: its rates and burst sizes.

use std::num::NonZeroU64;

/// Why a profile was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// A single rate profile whose burst sizes are both zero would never pass a packet.
    #[error("the committed and excess burst sizes cannot both be zero")]
    NoBurst,
    /// A two rate profile whose peak rate is below its committed rate.
    #[error("the peak rate ({peak}/s) is below the committed rate ({committed}/s)")]
    PeakBelowCommitted {
        /// The committed rate, in tokens per second.
        committed: NonZeroU64,
        /// The peak rate, in tokens per second.
        peak: NonZeroU64,
    },
    /// Limits that limit nothing.
    #[error("neither a byte nor a packet limit was given")]
    Unlimited,
}

/// Tokens per second: bytes per second for a byte limit, packets per second for a packet limit.
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

/// A single rate three color marker's profile (RFC 2697).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SingleRate {
    committed_rate: Rate,
    committed_burst: u64,
    excess_burst: u64,
}

impl SingleRate {
    /// Fill both buckets at `committed_rate`: the committed bucket first, up to `committed_burst`,
    /// then the excess bucket, up to `excess_burst`.
    ///
    /// # Errors
    ///
    /// Refuses a profile with no burst at all.
    //= https://www.rfc-editor.org/rfc/rfc2697#section-2
    //# The CBS and the EBS and are measured in bytes.  The CBS and EBS must
    //# be configured so that at least one of them is larger than 0.
    pub fn new(
        committed_rate: Rate,
        committed_burst: u64,
        excess_burst: u64,
    ) -> Result<SingleRate, ProfileError> {
        if committed_burst == 0 && excess_burst == 0 {
            return Err(ProfileError::NoBurst);
        }
        Ok(SingleRate {
            committed_rate,
            committed_burst,
            excess_burst,
        })
    }

    /// The rate both buckets fill at (CIR).
    #[must_use]
    pub fn committed_rate(&self) -> Rate {
        self.committed_rate
    }

    /// The committed bucket's size (CBS).
    #[must_use]
    pub fn committed_burst(&self) -> u64 {
        self.committed_burst
    }

    /// The excess bucket's size (EBS).
    #[must_use]
    pub fn excess_burst(&self) -> u64 {
        self.excess_burst
    }
}

/// A two rate three color marker's profile (RFC 2698).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TwoRate {
    committed_rate: Rate,
    committed_burst: NonZeroU64,
    peak_rate: Rate,
    peak_burst: NonZeroU64,
}

impl TwoRate {
    /// Fill the committed bucket at `committed_rate` up to `committed_burst`, and the peak bucket at
    /// `peak_rate` up to `peak_burst`.
    ///
    /// # Errors
    ///
    /// Refuses a peak rate below the committed rate.
    //= https://www.rfc-editor.org/rfc/rfc2698#section-2
    //# The PIR must be equal to or greater than the CIR.
    //
    //= https://www.rfc-editor.org/rfc/rfc2698#section-2
    //# The PBS and the CBS and are measured in bytes and both of them must
    //# be configured to be greater than 0.
    pub fn new(
        committed_rate: Rate,
        committed_burst: NonZeroU64,
        peak_rate: Rate,
        peak_burst: NonZeroU64,
    ) -> Result<TwoRate, ProfileError> {
        if peak_rate < committed_rate {
            return Err(ProfileError::PeakBelowCommitted {
                committed: committed_rate.per_second(),
                peak: peak_rate.per_second(),
            });
        }
        Ok(TwoRate {
            committed_rate,
            committed_burst,
            peak_rate,
            peak_burst,
        })
    }

    /// The committed bucket's rate (CIR).
    #[must_use]
    pub fn committed_rate(&self) -> Rate {
        self.committed_rate
    }

    /// The committed bucket's size (CBS).
    #[must_use]
    pub fn committed_burst(&self) -> NonZeroU64 {
        self.committed_burst
    }

    /// The peak bucket's rate (PIR).
    #[must_use]
    pub fn peak_rate(&self) -> Rate {
        self.peak_rate
    }

    /// The peak bucket's size (PBS).
    #[must_use]
    pub fn peak_burst(&self) -> NonZeroU64 {
        self.peak_burst
    }
}

/// How one quantity, bytes or packets, is metered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// RFC 2697: one rate, two burst sizes.
    SingleRate(SingleRate),
    /// RFC 2698: two rates, each with its own burst size.
    TwoRate(TwoRate),
}

impl From<SingleRate> for Profile {
    fn from(profile: SingleRate) -> Profile {
        Profile::SingleRate(profile)
    }
}

impl From<TwoRate> for Profile {
    fn from(profile: TwoRate) -> Profile {
        Profile::TwoRate(profile)
    }
}

/// Everything one meter limits: bytes, packets, or both.
///
/// With both, a packet takes the best color both profiles can pay for, and pays for it in both: a
/// packet within the byte limit but over the packet limit is over the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    bytes: Option<Profile>,
    packets: Option<Profile>,
}

impl Limits {
    /// Limit bytes by `bytes` and packets by `packets`.
    ///
    /// A byte is a byte of the IP packet, header included, as RFC 2697 and 2698 count them; link layer
    /// headers, and any encapsulation the packet arrived in, are not counted.
    ///
    /// # Errors
    ///
    /// Refuses to limit neither.
    pub fn new(bytes: Option<Profile>, packets: Option<Profile>) -> Result<Limits, ProfileError> {
        if bytes.is_none() && packets.is_none() {
            return Err(ProfileError::Unlimited);
        }
        Ok(Limits { bytes, packets })
    }

    /// How bytes are limited, if they are.
    #[must_use]
    pub fn bytes(&self) -> Option<Profile> {
        self.bytes
    }

    /// How packets are limited, if they are.
    #[must_use]
    pub fn packets(&self) -> Option<Profile> {
        self.packets
    }
}
