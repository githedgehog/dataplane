use crate::pci::{
    bus::{Bus, BusParseError},
    device::{Device, DeviceParseError},
    domain::{Domain, PciDomainParseError},
    function::{Function, FunctionParseError},
};

#[cfg(any(test, feature = "scan"))]
#[allow(unused_imports)] // re-export
pub use self::scan::*;

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "&str", into = "String")
)]
pub struct PciAddress {
    pub domain: Domain,
    pub bus: Bus,
    pub device: Device,
    pub function: Function,
}

impl PciAddress {
    pub fn new(domain: Domain, bus: Bus, device: Device, function: Function) -> Self {
        Self {
            domain,
            bus,
            device,
            function,
        }
    }

    pub fn as_ebdf(&self) -> PciEbdfString {
        PciEbdfString::from(*self)
    }
}

impl std::fmt::Display for PciAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:01x}",
            self.domain, self.bus, self.device, self.function
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPciAddress {
    #[error("Invalid syntax: {0}")]
    Syntax(String),
    #[error(transparent)]
    Domain(PciDomainParseError),
    #[error(transparent)]
    Bus(BusParseError),
    #[error(transparent)]
    Device(DeviceParseError),
    #[error(transparent)]
    Function(FunctionParseError),
}

impl TryFrom<&str> for PciAddress {
    type Error = InvalidPciAddress;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.is_ascii() {
            return Err(InvalidPciAddress::Syntax(format!(
                "Invalid ASCII characters in PCI address: {}",
                value
            )));
        }
        if value.len() != 12 {
            return Err(InvalidPciAddress::Syntax(format!(
                "Invalid PCI address: {value}  (length should be 12, was {})",
                value.len()
            )));
        }
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 3 {
            return Err(InvalidPciAddress::Syntax(format!(
                "Invalid PCI address format (should be domain:bus:device.function): {} has incorrect shape",
                value
            )));
        }
        let mut last_bit = parts[2].split(".");
        let device_str = match last_bit.next() {
            Some(device_str) => device_str,
            None => {
                return Err(InvalidPciAddress::Syntax(format!(
                    "(should be domain:bus:device.function): {} has no device",
                    value
                )));
            }
        };

        let function_str = match last_bit.next() {
            Some(function_str) => function_str,
            None => {
                return Err(InvalidPciAddress::Syntax(format!(
                    "(should be domain:bus:device.function): {} has no function",
                    value
                )));
            }
        };

        let domain_str = parts[0];
        let bus_str = parts[1];

        let domain = Domain::try_from(domain_str).map_err(InvalidPciAddress::Domain)?;
        let bus = Bus::try_from(bus_str).map_err(InvalidPciAddress::Bus)?;
        let device = Device::try_from(device_str).map_err(InvalidPciAddress::Device)?;
        let function = Function::try_from(function_str).map_err(InvalidPciAddress::Function)?;

        Ok(Self {
            domain,
            bus,
            device,
            function,
        })
    }
}

impl TryFrom<String> for PciAddress {
    type Error = InvalidPciAddress;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl Into<String> for PciAddress {
    fn into(self) -> String {
        format!("{self}")
    }
}

/// A PCI "extended" bus device function string (e.g. "0000:00:03.0")
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct PciEbdfString(String);

/// Errors that can occur when parsing a PCI Ebdf string
#[derive(Debug, thiserror::Error)]
pub enum PciEbdfError {
    /// The PCI Ebdf string is not valid
    #[error("Invalid PCI Ebdf format")]
    InvalidFormat(String),
}

impl PciEbdfString {
    /// Parse a string and confirm it is a valid PCI Ebdf string
    ///
    /// # Errors
    ///
    /// * `PciEbdfError::InvalidFormat` if the string is not a valid PCI Ebdf string
    pub fn try_new(s: impl AsRef<str>) -> Result<PciEbdfString, PciEbdfError> {
        let s = s.as_ref().to_string();
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
        Ok(PciEbdfString(s))
    }
}

impl TryFrom<&str> for PciEbdfString {
    type Error = PciEbdfError;

    fn try_from(s: &str) -> Result<Self, PciEbdfError> {
        Self::try_new(s)
    }
}

impl std::fmt::Display for PciEbdfString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<PciAddress> for PciEbdfString {
    fn from(address: PciAddress) -> Self {
        PciEbdfString::try_new(address.to_string()).unwrap_or_else(|_| unreachable!())
    }
}

impl From<PciEbdfString> for PciAddress {
    fn from(ebdf: PciEbdfString) -> Self {
        PciAddress::try_from(ebdf.0).unwrap_or_else(|_| unreachable!())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use bolero::{Driver, TypeGenerator};

    use crate::pci::address::{PciAddress, PciEbdfString};

    impl TypeGenerator for PciEbdfString {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let domain = driver.produce::<u16>()?;
            let bus = driver.produce::<u8>()?;
            let device = driver.produce::<u8>()?;
            let function = driver.produce::<u8>()?;
            let s = format!("{domain:04x}:{bus:02x}.{device:02x}.{function:02x}");
            PciEbdfString::try_new(s).ok()
        }
    }

    impl bolero::TypeGenerator for PciAddress {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(PciAddress {
                domain: driver.produce()?,
                bus: driver.produce()?,
                device: driver.produce()?,
                function: driver.produce()?,
            })
        }
    }
}

#[cfg(any(test, feature = "scan"))]
mod scan {
    use hwlocality::object::attributes::PCIDeviceAttributes;
    use num_traits::FromPrimitive;
    use pci_ids::FromId;

    use crate::pci::{
        PciDeviceAttributes, PciDeviceDescription,
        address::PciAddress,
        bus::Bus,
        device::{Device, DeviceId},
        domain::Domain,
        function::Function,
        vendor::VendorId,
    };

    impl From<PCIDeviceAttributes> for PciDeviceAttributes {
        fn from(value: PCIDeviceAttributes) -> Self {
            let address = PciAddress {
                domain: Domain::from(value.domain()),
                bus: Bus::from(value.bus_id()),
                device: Device::try_from(value.bus_device()).unwrap(), // assumed valid
                function: Function::try_from(value.function()).unwrap(), // assumed valid
            };
            PciDeviceAttributes {
                address,
                revision: value.revision(),
                device_description: {
                    let vendor_id = value.vendor_id();
                    let device_id = value.device_id();
                    PciDeviceDescription {
                        vendor_id: VendorId::from_u16(vendor_id).unwrap(),
                        vendor_name: pci_ids::Vendor::from_id(vendor_id)
                            .map(|x| x.name().to_string()),
                        device_id: DeviceId::from_u16(device_id).unwrap(),
                        device_name: pci_ids::Device::from_vid_pid(vendor_id, device_id)
                            .map(|x| x.name().to_string()),
                    }
                },
                sub_device_description: {
                    let vendor_id = value.subvendor_id();
                    let device_id = value.subdevice_id();
                    PciDeviceDescription {
                        vendor_id: VendorId::from_u16(vendor_id).unwrap(),
                        vendor_name: pci_ids::Vendor::from_id(vendor_id)
                            .map(|x| x.name().to_string()),
                        device_id: DeviceId::from_u16(device_id).unwrap(),
                        device_name: pci_ids::Device::from_vid_pid(vendor_id, device_id)
                            .map(|x| x.name().to_string()),
                    }
                },
                link_speed: value.link_speed().to_string(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use hwlocality::Topology;
    use hwlocality::object::types::ObjectType;
    use hwlocality::topology::builder::{BuildFlags, TypeFilter};
    use std::io::Write;

    use crate::Node;
    use crate::pci::address::{PciAddress, PciEbdfError, PciEbdfString};

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
        let _ = PciEbdfString::try_new(s.to_string()).unwrap();
    }

    #[test]
    fn basic_parse_invalid() {
        let s = "0000:00:0x3.0";
        let _ = PciEbdfString::try_new(s.to_string()).unwrap_err();
    }

    #[test]
    fn parse_arbitrary_string() {
        bolero::check!().with_type().for_each(|x: &String| {
            match PciEbdfString::try_new(x.clone()) {
                Ok(pci_ebdf) => {
                    assert_eq!(pci_ebdf.0, *x);
                    validity_checks(x);
                }
                Err(PciEbdfError::InvalidFormat(s)) => {
                    assert_eq!(&s, x);
                }
            }
        });
    }

    #[test]
    fn parse_valid() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|x: PciEbdfString| {
                validity_checks(&x.0);
                match PciEbdfString::try_new(x.0.clone()) {
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

    #[test]
    fn print_children_test() {
        let topology = Topology::builder()
            .with_type_filter(ObjectType::Bridge, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::PCIDevice, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::OSDevice, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Machine, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Core, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Die, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L1Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L2Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L3Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L4Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L5Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::MemCache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Misc, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::NUMANode, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::PU, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Package, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L1ICache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L2ICache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L3ICache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L4Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L5Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Group, TypeFilter::KeepStructure)
            .unwrap()
            .with_flags(BuildFlags::INCLUDE_DISALLOWED)
            .unwrap()
            .build()
            .unwrap();
        let system = Node::from(topology.root_object());
        let mut hardware_file = std::fs::File::create("hardware.yml").unwrap();
        hardware_file
            .write_all(serde_yaml_ng::to_string(&system).unwrap().as_bytes())
            .unwrap();
    }

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(|x: &PciAddress| {
            let back = PciAddress::try_from(x.to_string()).unwrap();
            assert_eq!(x, &back);
        })
    }

    #[test]
    fn parse_valid_ebdf() {
        bolero::check!().with_type().for_each(|x: &PciEbdfString| {
            let y = PciEbdfString::from(PciAddress::from(x.clone()));
            assert_eq!(x, &y);
        })
    }
}
