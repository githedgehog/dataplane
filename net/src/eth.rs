//! Ethernet types

#[cfg(any(test, kani, feature = "bolero"))]
use bolero::TypeGenerator;

/// A [MAC Address] type.
///
/// `Mac` is a transparent wrapper around `[u8; 6]` which provides a
/// small collection of methods and type safety.
///
/// [MAC Address]: https://en.wikipedia.org/wiki/MAC_address
#[must_use]
#[repr(transparent)]
#[cfg_attr(any(feature = "bolero", test, kani), derive(TypeGenerator))]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacAddress(pub [u8; 6]);

impl From<[u8; 6]> for MacAddress {
    fn from(value: [u8; 6]) -> Self {
        MacAddress(value)
    }
}

impl From<MacAddress> for [u8; 6] {
    fn from(value: MacAddress) -> Self {
        value.0
    }
}

impl AsRef<[u8; 6]> for MacAddress {
    #[must_use]
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl AsMut<[u8; 6]> for MacAddress {
    #[must_use]
    fn as_mut(&mut self) -> &mut [u8; 6] {
        &mut self.0
    }
}

impl MacAddress {
    /// The broadcast `Mac`
    pub const BROADCAST: MacAddress = MacAddress([u8::MAX; 6]);
    /// The zero `Mac`.
    ///
    /// `ZERO` is illegal as a source or destination `Mac` in most contexts.
    pub const ZERO: MacAddress = MacAddress([0; 6]);

    /// Returns true iff the binary representation of the [`MacAddress`] is exclusively ones.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self == &MacAddress::BROADCAST
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is one.
    #[must_use]
    #[cfg_attr(feature = "_no-panic", no_panic::no_panic)]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 == 0x01
    }

    /// Returns true iff the least significant bit of the first octet of the `[Mac]` is zero.
    #[must_use]
    #[cfg_attr(feature = "_no-panic", no_panic::no_panic)]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true iff the binary representation of the [`MacAddress`] is exclusively zeros.
    #[must_use]
    #[cfg_attr(feature = "_no-panic", no_panic::no_panic)]
    pub fn is_zero(&self) -> bool {
        self == &MacAddress::ZERO
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

    /// Returns true if the [`MacAddress`] is reserved for link local usage.
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

    /// Returns true iff the [`MacAddress`] is a legal source `Mac`.
    ///
    /// Multicast and zero are not legal source [`MacAddress`].
    #[must_use]
    pub fn is_valid_src(&self) -> bool {
        !self.is_zero() && !self.is_multicast()
    }

    /// Returns true iff the [`MacAddress`] is a legal destination [`MacAddress`].
    #[must_use]
    pub fn is_valid_dst(&self) -> bool {
        self.is_valid()
    }

    /// Return true iff the [`MacAddress`] is not zero.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_zero()
    }
}

/// Errors which can occur while setting the source [`MacAddress`] of a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub enum SourceMacAddressError {
    /// Multicast macs are not legal source
    #[error("invalid source mac address: multicast macs are illegal as source macs")]
    MulticastSource,
    /// Zero is not a legal source
    #[error("invalid source mac address: zero mac is illegal as source mac")]
    ZeroSource,
}

/// Errors which can occur while setting the destination [`MacAddress`] of a [`Packet`]
#[derive(Debug, thiserror::Error)]
pub enum DestinationMacAddressError {
    /// Zero is not a legal source
    #[error("invalid destination mac address: zero mac is illegal as destination mac")]
    ZeroDestination,
}

/// Proofs regarding the properties of this crate's ethernet header analysis
#[allow(missing_docs, clippy::panic, clippy::missing_panics_doc, dead_code)]
#[cfg(any(test, kani))]
pub mod test {
    use crate::eth::MacAddress;
    use kani::{any, assume, proof};

    fn lsb_indicates_multicast(input: MacAddress) {
        if input.0[0] & 1 == 1 {
            assert!(input.is_multicast());
        } else {
            assert!(!input.is_multicast());
        }
    }

    #[test]
    #[proof]
    fn check_lsb_indicates_multicast() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(lsb_indicates_multicast);
    }

    #[proof]
    fn not_lsb_indicates_not_multicast() {
        let input: MacAddress = any();
        assume(input.0[0] & 1 == 0);
        assert!(!input.is_multicast());
    }

    #[proof]
    fn multicast_indicates_lsb() {
        let input: MacAddress = any();
        assume(input.is_multicast());
        assert_eq!(input.0[0] & 1, 1);
    }

    #[proof]
    fn zero_indicates_zero() {
        let input: MacAddress = any();
        assume(input.is_zero());
        assert_eq!(input.0, [0; 6]);
    }

    #[proof]
    fn unicast_is_never_multicast() {
        let input: MacAddress = any();
        assume(input.is_unicast());
        assert!(!input.is_multicast());
    }

    #[proof]
    fn multicast_is_never_unicast() {
        let input: MacAddress = any();
        assume(input.is_multicast());
        assert!(!input.is_unicast());
    }

    #[proof]
    fn local_is_never_universal() {
        let input: MacAddress = any();
        assume(input.is_local());
        assert!(!input.is_universal());
    }

    #[proof]
    fn universal_is_never_local() {
        let input: MacAddress = any();
        assume(input.is_universal());
        assert!(!input.is_local());
    }

    #[proof]
    fn link_local_is_multicast() {
        let input: MacAddress = any();
        assume(input.is_link_local());
        assert!(input.is_multicast());
    }

    #[proof]
    fn valid_source_is_never_zero() {
        let input: MacAddress = any();
        assume(input.is_valid_src());
        assert!(!input.is_zero());
    }

    #[proof]
    fn valid_source_is_never_multicast() {
        let input: MacAddress = any();
        assume(input.is_multicast());
        assert!(!input.is_valid_src());
    }

    #[proof]
    fn multicast_is_valid_destination() {
        let input: MacAddress = any();
        assume(input.is_multicast());
        assert!(input.is_valid_dst());
    }
}

/// TODO: document module
#[cfg(any(feature = "bolero", test, kani))]
pub mod fuzz {
    use crate::header::Eth;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use etherparse::Ethernet2Header;

    /// TODO: document module
    #[allow(missing_docs)] // temporary allowance
    pub mod valid {
        use crate::eth::MacAddress;
        use crate::header::Eth;
        use bolero::{Driver, TypeGenerator, ValueGenerator};
        use etherparse::EtherType;
        use std::marker::PhantomData;

        trait Flavor {}

        #[non_exhaustive]
        #[repr(transparent)]
        pub struct SourceMac;

        #[non_exhaustive]
        #[repr(transparent)]
        pub struct DestinationMac;

        pub struct Valid<T: Flavor> {
            _marker: PhantomData<T>,
        }

        impl<T: Flavor> Valid<T> {
            const fn new() -> Valid<T> {
                Self { _marker: PhantomData }
            }
        }

        impl Flavor for SourceMac {}
        impl Flavor for DestinationMac {}
        impl Flavor for Eth {}

        impl ValueGenerator for Valid<SourceMac> {
            type Output = MacAddress;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                let mut source = MacAddress::generate(driver)?;
                source.0[0] &= 0xfe;
                // re-roll if zero
                while !source.is_valid_src() {
                    source = MacAddress::generate(driver)?;
                    source.0[0] &= 0xfe;
                }
                Some(source)
            }
        }

        impl ValueGenerator for Valid<DestinationMac> {
            type Output = MacAddress;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                let mut source = MacAddress::generate(driver)?;
                source.0[0] &= 0xfe; // set multicast to false
                // re-roll if zero
                while !source.is_valid_src() {
                    source = MacAddress::generate(driver)?;
                    source.0[0] &= 0xfe;
                }
                Some(source)
            }
        }

        impl ValueGenerator for Valid<Eth> {
            type Output = Eth;

            fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
                let source = Valid::<SourceMac>::new().generate(driver)?;
                let dest = Valid::<DestinationMac>::new().generate(driver)?;
                Some(Eth::new(
                    source,
                    dest,
                    EtherType::ARP,
                ))
            }
        }
    }
}
