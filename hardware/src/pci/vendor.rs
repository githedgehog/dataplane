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
    serde(try_from = "String", into = "String")
)]
#[repr(transparent)]
pub struct VendorId(u16);

impl std::fmt::LowerHex for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl std::fmt::Display for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self)
    }
}

impl Into<String> for VendorId {
    fn into(self) -> String {
        format!("{:04x}", self.0)
    }
}

impl TryFrom<String> for VendorId {
    type Error = std::num::ParseIntError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let id = u16::from_str_radix(&value, 16)?;
        Ok(VendorId(id))
    }
}
