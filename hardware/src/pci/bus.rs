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
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[repr(transparent)]
pub struct Bus(u8);

impl std::fmt::LowerHex for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

impl std::fmt::Display for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self)
    }
}

impl From<u8> for Bus {
    fn from(value: u8) -> Self {
        Bus(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BusParseError {
    #[error("invalid bus syntax: {0}")]
    Syntax(String),
}

impl TryFrom<&str> for Bus {
    type Error = BusParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(BusParseError::Syntax(format!(
                "invalid bus syntax: {}",
                value
            )));
        }
        let bus = u8::from_str_radix(value, 16)
            .map_err(|_| BusParseError::Syntax(format!("invalid bus syntax: {}", value)))?;
        Ok(Bus(bus))
    }
}
