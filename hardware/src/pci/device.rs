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
pub struct DeviceId(u16);

impl Into<String> for DeviceId {
    fn into(self) -> String {
        format!("{:04x}", self.0)
    }
}

impl TryFrom<String> for DeviceId {
    type Error = std::num::ParseIntError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let id = u16::from_str_radix(&value, 16)?;
        Ok(DeviceId(id))
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
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
#[repr(transparent)]
pub struct Device(u8);

impl Device {
    #[allow(dead_code)]
    pub(crate) const MAX: u8 = 0b11111;
}

impl std::fmt::LowerHex for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidDevice {
    #[error("Device ID maximum is 5 bits: {0} is too large")]
    TooLarge(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceParseError {
    #[error("Invalid PCI device syntax: {0}")]
    Syntax(String),
    #[error(transparent)]
    Invalid(InvalidDevice),
}

impl TryFrom<u8> for Device {
    type Error = InvalidDevice;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 0x1F {
            Err(InvalidDevice::TooLarge(value))
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<&str> for Device {
    type Error = DeviceParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            Err(DeviceParseError::Syntax(value.to_string()))
        } else {
            let device_id = u8::from_str_radix(value, 16).map_err(|_| {
                DeviceParseError::Syntax(format!("Invalid PCI device syntax: {}", value))
            })?;
            Device::try_from(device_id).map_err(DeviceParseError::Invalid)
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::pci::device::Device;

    impl bolero::TypeGenerator for Device {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(
                Device::try_from(driver.produce::<u8>()? & Self::MAX)
                    .unwrap_or_else(|_| unreachable!()),
            )
        }
    }
}
