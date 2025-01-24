use std::num::NonZero;

/// A [VXLAN][RFC7348] Network Identifier.
///
/// A `Vni` is a 24-bit value that identifies a VXLAN [overlay network].
///
/// According to <cite>[RFC7348]</cite>:
///
/// > VXLAN Segment ID/VXLAN Network Identifier (VNI): this is a 24-bit value used to designate the
/// > individual VXLAN overlay network on which the communicating VMs are situated.
///
/// # Legal values
///
/// * Value `0` is reserved by many implementations and should not be used.
/// * The maximum legal value is <var>2<sup>24</sup> - 1 = 16,777,215 = `0x00_FF_FF_FF`</var>.
///
/// It is deliberately not possible to create a `Vni` from a `u32` directly, as that would
/// allow the creation of illegal `Vni` values.
/// Instead, use [`Vni::new`] to create a `Vni` from a `u32`.
///
/// # Note
///
/// This type is marked [`#[repr(transparent)]`][transparent] to ensure that it has the same memory
/// layout as a [`NonZero<u32>`].
/// [`Option<Vni>`] will therefore have the same size and alignment as [`Option<NonZero<u32>>`], and
/// thus the same size and alignment as `u32`.
/// The memory / compute overhead of using `Vni` as opposed to a `u32` is then limited to the price
/// of checking that the represented value is in fact a legal `Vni` (which we should be doing
/// anyway).
///
/// [RFC7348]: https://datatracker.ietf.org/doc/html/rfc7348#section-5
/// [overlay network]: https://en.wikipedia.org/wiki/Overlay_network
/// [transparent]: https://doc.rust-lang.org/reference/type-layout.html#the-transparent-representation
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u32", into = "u32"))]
#[repr(transparent)]
pub struct Vni(NonZero<u32>);

impl Vni {
    /// The minimum legal [`Vni`] value (1).
    pub const MIN: u32 = 1;
    /// The maximum legal [`Vni`] value (2<sup>24</sup> - 1).
    pub const MAX: u32 = 0x00_FF_FF_FF;
    /// First value which is too large to be a legal [`Vni`]
    #[allow(unused)] // used in test suite
    const TOO_LARGE: u32 = Vni::MAX + 1;

    /// Create a new [`Vni`] from a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an [`InvalidVni`] error if the value is 0 or greater than [`Vni::MAX`].
    pub fn new(vni: u32) -> Result<Vni, InvalidVni> {
        match NonZero::<u32>::new(vni) {
            None => Err(InvalidVni::ReservedZero),
            _ if vni > Vni::MAX => Err(InvalidVni::TooLarge(vni)),
            Some(vni) => Ok(Vni(vni)),
        }
    }

    /// Get the value of the [`Vni`] as a `u32`.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        self.0.get()
    }
}

impl AsRef<NonZero<u32>> for Vni {
    #[must_use]
    fn as_ref(&self) -> &NonZero<u32> {
        &self.0
    }
}

/// Errors that can occur when converting a `u32` to a [`Vni`]
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum InvalidVni {
    /// Zero is not a legal Vni in many EVPN / VXLAN implementations.  Don't use it.
    #[error("Zero is not a legal Vni")]
    ReservedZero,
    /// This error type contains the (illegal) value used to attempt creation of a [`Vni`].
    /// The max legal value is found in [`Vni::MAX`].
    #[error("The value {0} is too large to be a Vni (max is {MAX})", MAX = Vni::MAX)]
    TooLarge(u32),
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> u32 {
        vni.as_u32()
    }
}

impl TryFrom<u32> for Vni {
    type Error = InvalidVni;

    fn try_from(vni: u32) -> Result<Vni, Self::Error> {
        Vni::new(vni)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn zero_is_not_a_legal_vni() {
        assert_eq!(Vni::new(0).unwrap_err(), InvalidVni::ReservedZero);
    }

    #[test]
    fn one_is_a_legal_vni() {
        assert_eq!(Vni::new(1).unwrap().as_u32(), 1);
    }

    #[test]
    fn vni_max_is_a_legal_vni() {
        assert_eq!(Vni::new(Vni::MAX).unwrap().as_u32(), Vni::MAX);
    }

    #[test]
    fn vni_max_plus_one_is_not_a_legal_vni() {
        assert_eq!(
            Vni::new(Vni::MAX + 1).unwrap_err(),
            InvalidVni::TooLarge(Vni::MAX + 1)
        );
    }

    #[test]
    fn u32_max_is_not_a_legal_vni() {
        assert_eq!(
            Vni::new(u32::MAX).unwrap_err(),
            InvalidVni::TooLarge(u32::MAX)
        );
    }

    #[test]
    fn try_from_impl() {
        Vni::try_from(2).expect("2 is a legal Vni");
    }

    fn vni_contract(val: u32) {
        match val {
            0 => {
                assert_eq!(Vni::new(val).unwrap_err(), InvalidVni::ReservedZero);
            }
            Vni::MIN..=Vni::MAX => {
                assert_eq!(Vni::new(val).unwrap().as_u32(), val);
            }
            Vni::TOO_LARGE.. => {
                assert_eq!(Vni::new(val).unwrap_err(), InvalidVni::TooLarge(val));
            }
        }
    }

    proptest! {
        #[test]
        fn check_vni_contract(val in any::<u32>()) {
            vni_contract(val);
        }
    }
}
