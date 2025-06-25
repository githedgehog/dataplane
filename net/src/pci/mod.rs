// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Networking abstractions related to PCI

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// A PCI "extended" bus device function string (e.g. "0000:00:03.0")
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct PciEbdf(String);

/// Errors that can occur when parsing a PCI Ebdf string
#[derive(Debug, thiserror::Error)]
pub enum PciEbdfError {
    /// The PCI Ebdf string is not valid
    #[error("Invalid PCI Ebdf format")]
    InvalidFormat(String),
}

impl PciEbdf {
    /// Parse a string and confirm it is a valid PCI Ebdf string
    ///
    /// # Errors
    ///
    /// * `PciEbdfError::InvalidFormat` if the string is not a valid PCI Ebdf string
    pub fn try_new(s: String) -> Result<PciEbdf, PciEbdfError> {
        use PciEbdfError::InvalidFormat;
        if !s.is_ascii() {
            return Err(InvalidFormat(s));
        }
        let split: Vec<_> = s.split(':').collect();
        if split.len() != 3 {
            return Err(InvalidFormat(s));
        }
        let domain = split[0];
        let bus = split[1];
        let dev_and_func = split[2];
        let split: Vec<_> = dev_and_func.split('.').collect();
        if split.len() != 2 {
            return Err(InvalidFormat(s));
        }
        let dev = split[0];
        let func = split[1];
        if domain.len() != 4 || bus.len() != 2 || dev.len() != 2 || func.len() != 1 {
            return Err(InvalidFormat(s));
        }
        if domain.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        if bus.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        if dev.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        if func.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        Ok(PciEbdf(s))
    }
}

impl Display for PciEbdf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::pci::PciEbdf;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for PciEbdf {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let domain = driver.produce::<u16>()?;
            let bus = driver.produce::<u8>()?;
            let device = driver.produce::<u8>()?;
            let function = driver.produce::<u8>()?;
            let s = format!("{domain:04x}:{bus:02x}.{device:02x}.{function:02x}");
            PciEbdf::try_new(s).ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pci::{PciEbdf, PciEbdfError};

    fn validity_checks(s: impl AsRef<str>) {
        let s = s.as_ref();
        assert!(s.is_ascii());
        let split: Vec<_> = s.split(':').collect();
        assert_eq!(split.len(), 3);
        assert_eq!(split[0].len(), 4);
        assert_eq!(split[1].len(), 2);
        assert_eq!(split[2].len(), 4);
        assert!(split[0].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(split[1].chars().all(|c| c.is_ascii_hexdigit()));
        let split: Vec<_> = split[2].split('.').collect();
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].len(), 2);
        assert_eq!(split[1].len(), 1);
        assert!(split[0].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(split[1].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn basic_parse() {
        let s = "0000:00:03.0";
        validity_checks(s);
        let _ = PciEbdf::try_new(s.to_string()).unwrap();
    }

    #[test]
    fn basic_parse_invalid() {
        let s = "0000:00:0x3.0";
        let _ = PciEbdf::try_new(s.to_string()).unwrap_err();
    }

    #[test]
    fn parse_arbitrary_string() {
        bolero::check!()
            .with_type()
            .for_each(|x: &String| match PciEbdf::try_new(x.clone()) {
                Ok(pci_ebdf) => {
                    assert_eq!(pci_ebdf.0, *x);
                    validity_checks(x);
                }
                Err(PciEbdfError::InvalidFormat(_)) => {}
            });
    }

    #[test]
    fn parse_valid() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|x: PciEbdf| {
                validity_checks(&x.0);
                match PciEbdf::try_new(x.0.clone()) {
                    Ok(pci_ebdf) => {
                        assert_eq!(pci_ebdf.0, x.0);
                        validity_checks(pci_ebdf.0);
                    }
                    Err(PciEbdfError::InvalidFormat(invalid)) => {
                        unreachable!("Invalid PCI Ebdf string {}", invalid)
                    }
                }
            });
    }
}
