#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[repr(transparent)]
pub struct Domain(u16);

impl From<u16> for Domain {
    fn from(value: u16) -> Self {
        Domain(value)
    }
}

impl std::fmt::LowerHex for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PciDomainParseError {
    #[error("Invalid PCI domain syntax (must be four hex digits): {0}")]
    Syntax(std::num::ParseIntError),
}

impl TryFrom<&str> for Domain {
    type Error = PciDomainParseError;

    fn try_from(value: &str) -> Result<Self, PciDomainParseError> {
        let domain = u16::from_str_radix(value, 16).map_err(PciDomainParseError::Syntax)?;
        Ok(Domain(domain))
    }
}
