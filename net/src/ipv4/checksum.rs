// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::checksum::Checksum;
use crate::ipv4::Ipv4;
use std::fmt::{Display, Formatter};

/// A [`Ipv4`] checksum
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Ipv4Checksum(u16);

impl Display for Ipv4Checksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
    }
}

impl Ipv4Checksum {
    /// Map a raw value to a [`Ipv4Checksum`]
    #[must_use]
    pub const fn new(raw: u16) -> Ipv4Checksum {
        Ipv4Checksum(raw)
    }
}

impl AsRef<u16> for Ipv4Checksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for Ipv4Checksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for Ipv4Checksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<Ipv4Checksum> for u16 {
    fn from(checksum: Ipv4Checksum) -> Self {
        checksum.0
    }
}

impl Checksum for Ipv4 {
    type Error = ();
    type Payload<'a>
        = ()
    where
        Self: 'a;
    type Checksum = Ipv4Checksum;

    /// Get the [`Ipv4`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<Ipv4Checksum> {
        Some(Ipv4Checksum(self.header_checksum))
    }

    /// Compute the ipv4 header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn compute_checksum(
        &self,
        _payload: &Self::Payload<'_>,
    ) -> Result<Self::Checksum, Self::Error> {
        Ok(Ipv4Checksum(self.compute_header_checksum()))
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error> {
        self.header_checksum = checksum.0;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::checksum::{Checksum, ones_complement_sum};
    use crate::ip::NextHeader;
    use crate::ip::dscp::Dscp;
    use crate::ip::ecn::Ecn;
    use crate::ipv4::{BuiltWithNextHeader, Ipv4, Ipv4Checksum};
    use crate::parse::DeParse;
    use bolero::{Driver, ValueGenerator};
    use std::net::Ipv4Addr;

    /// How far `ipv4` is from valid: the one's-complement sum over the whole header, checksum
    /// included, which is `0xffff` (either zero) for a valid header.
    fn error(ipv4: &Ipv4) -> u16 {
        let mut buf = [0u8; Ipv4::MAX_LEN.get() as usize];
        let written = ipv4.deparse(&mut buf).expect("header does not deparse");
        ones_complement_sum(&buf[..written.get() as usize])
    }

    /// A header built here, carrying any next header.
    struct Built;

    impl ValueGenerator for Built {
        type Output = Ipv4;

        fn generate<D: Driver>(&self, u: &mut D) -> Option<Ipv4> {
            BuiltWithNextHeader(u.produce::<NextHeader>()?).generate(u)
        }
    }

    #[test]
    fn a_built_header_is_valid() {
        bolero::check!()
            .with_generator(Built)
            .for_each(|ipv4: &Ipv4| {
                ipv4.validate_checksum(&())
                    .expect("a header built through the setters is invalid");
            });
    }

    #[test]
    fn setters_carry_a_checksum_error_through_exactly() {
        bolero::check!()
            .with_type::<(Ipv4, u16, u8, u32, u16, Dscp, Ecn)>()
            .for_each(|(header, checksum, ttl, destination, id, dscp, ecn)| {
                let mut ipv4 = header.clone();
                ipv4.set_checksum(Ipv4Checksum::from(*checksum))
                    .expect("setting a checksum never fails");
                let before = error(&ipv4);

                ipv4.set_ttl(*ttl)
                    .set_destination(Ipv4Addr::from(*destination))
                    .set_identification(*id)
                    .set_dscp(*dscp)
                    .set_ecn(*ecn);
                let _ = ipv4.decrement_ttl();

                assert_eq!(
                    error(&ipv4),
                    before,
                    "a setter recomputed the checksum rather than adjusting it"
                );
            });
    }
}
