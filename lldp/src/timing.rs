// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The transmit timers of IEEE 802.1AB-2016 §9.2.5.

use net::lldp::TimeToLive;
use std::num::{NonZeroU8, NonZeroU16};
use std::time::Duration;

/// How often a port advertises, and how fast it may react to change.
///
/// Intervals are whole seconds, as the standard defines them, and never zero, so that no setting can
/// make the transmitter spin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// `msgTxInterval`: seconds between routine advertisements.
    pub tx_interval: NonZeroU16,
    /// `msgTxHold`: how many intervals a neighbour keeps what we advertised.
    pub tx_hold: NonZeroU16,
    /// `msgFastTx`: seconds between advertisements while starting up.
    pub fast_tx: NonZeroU16,
    /// `txFastInit`: how many advertisements to send fast after the link comes up.
    pub fast_init: NonZeroU8,
    /// `txCreditMax`: how many advertisements may go out back to back.
    ///
    /// Credit comes back at one per second, so this bounds the burst a flurry of local changes causes.
    pub credit_max: NonZeroU8,
    /// `reinitDelay`: seconds to stay quiet after a shutdown frame before advertising again.
    pub reinit_delay: NonZeroU8,
}

impl Default for Timing {
    /// The defaults of IEEE 802.1AB-2016 §9.2.5.
    fn default() -> Self {
        Timing {
            tx_interval: NonZeroU16::new(30).unwrap_or_else(|| unreachable!()),
            tx_hold: NonZeroU16::new(4).unwrap_or_else(|| unreachable!()),
            fast_tx: NonZeroU16::MIN,
            fast_init: NonZeroU8::new(4).unwrap_or_else(|| unreachable!()),
            credit_max: NonZeroU8::new(5).unwrap_or_else(|| unreachable!()),
            reinit_delay: NonZeroU8::new(2).unwrap_or_else(|| unreachable!()),
        }
    }
}

impl Timing {
    /// The time to live to advertise: `msgTxInterval × msgTxHold + 1`, capped at what the TLV can hold.
    #[must_use]
    pub fn ttl(&self) -> TimeToLive {
        let seconds = u32::from(self.tx_interval.get()) * u32::from(self.tx_hold.get()) + 1;
        TimeToLive::new(u16::try_from(seconds).unwrap_or(u16::MAX))
    }

    pub(crate) fn tx_interval(&self) -> Duration {
        Duration::from_secs(self.tx_interval.get().into())
    }

    pub(crate) fn fast_tx(&self) -> Duration {
        Duration::from_secs(self.fast_tx.get().into())
    }

    pub(crate) fn reinit_delay(&self) -> Duration {
        Duration::from_secs(self.reinit_delay.get().into())
    }
}

#[cfg(test)]
mod tests {
    use super::Timing;
    use std::num::NonZeroU16;

    #[test]
    fn the_default_ttl_is_four_intervals_and_a_second() {
        assert_eq!(Timing::default().ttl().as_secs(), 121);
    }

    #[test]
    fn a_ttl_too_long_for_the_tlv_is_capped() {
        let timing = Timing {
            tx_interval: NonZeroU16::MAX,
            tx_hold: NonZeroU16::MAX,
            ..Timing::default()
        };
        assert_eq!(timing.ttl().as_secs(), u16::MAX);
    }
}
