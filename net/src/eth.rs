//! Ethernet types

pub use etherparse::EtherType;

/// A [MAC Address] type.
///
/// `Mac` is a transparent wrapper around `[u8; 6]` which provides a
/// small collection of methods and type safety.
///
/// [MAC Address]: https://en.wikipedia.org/wiki/MAC_address
#[must_use]
#[repr(transparent)]
#[cfg_attr(any(feature = "bolero", test, kani), derive(bolero::TypeGenerator))]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mac(pub [u8; 6]);


impl From<[u8; 6]> for Mac {
    fn from(value: [u8; 6]) -> Self {
        Mac(value)
    }
}

impl From<Mac> for [u8; 6] {
    fn from(value: Mac) -> Self {
        value.0
    }
}

impl AsRef<[u8; 6]> for Mac {
    #[must_use]
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl AsMut<[u8; 6]> for Mac {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8; 6] {
        &mut self.0
    }
}

impl Mac {
    /// The broadcast `Mac`
    pub const BROADCAST: Mac = Mac([u8::MAX; 6]);
    /// The zero `Mac`.
    ///
    /// `ZERO` is illegal as a source or destination `Mac` in most contexts.
    pub const ZERO: Mac = Mac([0; 6]);

    /// Returns true iff the binary representation of the [`Mac`] is exclusively ones.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        *self == Mac::BROADCAST
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is one.
    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is zero.
    #[must_use]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true iff the binary representation of the [`Mac`] is exclusively zeros.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Returns true iff the second least significant bit of the first octet is one.
    #[must_use]
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Returns true iff the second least significant bit of the first octet is zero.
    #[must_use]
    pub fn is_universal(&self) -> bool {
        !self.is_local()
    }

    /// Returns true if the [`Mac`] is reserved for link local usage.
    ///
    /// Link local usage includes [spanning tree protocol] and [LACP].
    ///
    /// [spanning tree protocol]: https://en.wikipedia.org/wiki/Spanning_Tree_Protocol
    /// [LACP]: https://en.wikipedia.org/wiki/Link_aggregation#Link_Aggregation_Control_Protocol
    #[must_use]
    pub fn is_link_local(&self) -> bool {
        let bytes = self.as_ref();
        (bytes[0..5] == [0x01, 0x80, 0xc2, 0x00, 0x00]) && (bytes[5] & 0x0f == bytes[5])
    }

    /// Returns true iff the [`Mac`] is a legal source `Mac`.
    ///
    /// Multicast and zero are not legal source [`Mac`].
    #[must_use]
    pub fn is_valid_src(&self) -> bool {
        !self.is_zero() && !self.is_multicast()
    }

    /// Returns true iff the [`Mac`] is a legal destination [`Mac`].
    #[must_use]
    pub fn is_valid_dst(&self) -> bool {
        self.is_valid()
    }

    /// Return true iff the [`Mac`] is not zero.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_zero()
    }
}

#[cfg(any(kani, feature = "_proof"))]
mod proof {
    use crate::eth::Mac;
    use kani::{proof, assume, any};

    #[proof]
    fn lsb_indicates_multicast() {
        let input: Mac = any();
        assume(input.0[0] & 1 == 1);
        assert!(input.is_multicast());
    }

    #[proof]
    fn multicast_indicates_lsb() {
        let input: Mac = any();
        assume(input.is_multicast());
        assert_eq!(input.0[0] & 1, 1);
    }

    #[proof]
    fn zero_indicates_zero() {
        let input: Mac = any();
        assume(input.is_zero());
        assert_eq!(input.0, [0; 6]);
    }

    #[proof]
    fn unicast_is_never_multicast() {
        let input: Mac = any();
        assume(input.is_unicast());
        assert!(!input.is_multicast());
    }

    #[proof]
    fn multicast_is_never_unicast() {
        let input: Mac = any();
        assume(input.is_multicast());
        assert!(!input.is_unicast());
    }

    #[proof]
    fn local_is_never_universal() {
        let input: Mac = any();
        assume(input.is_local());
        assert!(!input.is_universal());
    }

    #[proof]
    fn universal_is_never_local() {
        let input: Mac = any();
        assume(input.is_universal());
        assert!(!input.is_local());
    }

    #[proof]
    fn link_local_is_multicast() {
        let input: Mac = any();
        assume(input.is_link_local());
        assert!(!input.is_multicast());
    }

    #[proof]
    fn valid_source_is_never_zero() {
        let input: Mac = any();
        assume(input.is_valid_src());
        assert!(!input.is_zero());
    }

    #[proof]
    fn valid_source_is_never_multicast() {
        let input: Mac = any();
        assume(input.is_multicast());
        assert!(!input.is_valid_src());
    }

    #[proof]
    fn multicast_is_valid_destination() {
        let input: Mac = any();
        assume(input.is_multicast());
        assert!(input.is_valid_dst());
    }
}
