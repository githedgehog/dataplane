use net::pci::PciEbdf;
use std::str::FromStr;
use tracing::error;

pub struct PciNic {
    device: net::pci::PciEbdf,
}

impl std::fmt::Display for PciNic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.device)
    }
}

#[derive(Debug, strum::EnumString)]
pub enum Driver {
    #[strum(serialize = "mlx5_core")]
    Mlx5Core,
    #[strum(serialize = "vhost")]
    Vhost,
    #[strum(serialize = "virtio-net")]
    VirtioNet,
    #[strum(serialize = "unbound")]
    Unbound,
    #[strum(transparent)]
    Unknown(String),
}

pub trait CurrentDriver {
    fn current_driver(&self) -> impl Future<Output = Result<Driver, std::io::Error>>;
}

pub trait CurrentDriver2 {
    type Error: std::error::Error + Sized;
    fn current_driver2(&self) -> impl Future<Output = Result<Driver, Self::Error>>;
}

impl CurrentDriver2 for PciNic {
    type Error = std::io::Error;

    async fn current_driver2(&self) -> Result<Driver, std::io::Error> {
        let builder = hwlocality::topology::builder::TopologyBuilder::new();
        // let type_filter = builder;
        // .type_filter(hwlocality::object::types::ObjectType::)
        // .unwrap();
        let topology = builder
            // .with_type_filter(hwlocality::object::types::ObjectType::OSDevice, type_filter)
            // .unwrap()
            // .with_io_type_filter(type_filter)
            // .unwrap()
            .build()
            .unwrap();
        for object in topology.objects() {
            println!("object: {:?}", object);
            // let attrs = object.attributes().unwrap();
            // match attrs {
            //     hwlocality::object::attributes::ObjectAttributes::NUMANode(numanode_attributes) => {
            //         todo!()
            //     }
            //     hwlocality::object::attributes::ObjectAttributes::Cache(cache_attributes) => {
            //         todo!()
            //     }
            //     hwlocality::object::attributes::ObjectAttributes::Group(group_attributes) => {
            //         todo!()
            //     }
            //     hwlocality::object::attributes::ObjectAttributes::PCIDevice(
            //         pcidevice_attributes,
            //     ) => {
            //         todo!()
            //     }
            //     hwlocality::object::attributes::ObjectAttributes::Bridge(bridge_attributes) => {
            //         todo!()
            //     }
            //     hwlocality::object::attributes::ObjectAttributes::OSDevice(osdevice_attributes) => {
            //         todo!()
            //     }
            // }
        }
        Ok(Driver::Unbound)
    }
}

impl CurrentDriver for PciNic {
    async fn current_driver(&self) -> Result<Driver, std::io::Error> {
        println!("Current driver for PCI device: {}", self);
        tokio::fs::read_link(format!("/sys/bus/pci/devices/{self}/driver"))
            .await
            .map(|path| match path.components().last() {
                Some(component) => {
                    // TODO: in theory this link could go anywhere.  Use hwlocality lib to get the actual driver.
                    match component.as_os_str().to_str() {
                        Some(driver_name) => Driver::from_str(driver_name).unwrap_or_else(|e| {
                            error!("Failed to parse driver name: {}", e);
                            Driver::Unknown(driver_name.to_string())
                        }),
                        None => {
                            // NOTE: Invalid UTF-8 in the driver name an absolutely wild error case I expect to never
                            // happen.
                            // If it happens it is 99.99% likely that something is deeply wrong (possible kernel memory
                            // corruption or other security issue).
                            // Thus we should deliberately refuse to log the offending path name; injecting arbitrary
                            // bytes into the log may be what an attacker needs for lateral compromise of some other
                            // system.  This is a case where we should just panic.
                            error!("driver name is not valid UTF-8!");
                            panic!("driver name is not valid UTF-8!");
                        }
                    }
                }
                None => {
                    // NOTE: this is another wild error case where the symlink is somehow broken (kernel error)
                    // Also panic here.
                    error!("driver symlink is broken!");
                    panic!("driver symlink is broken!");
                }
            })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let device = PciEbdf::try_new("0000:0c:00.0".to_string()).unwrap();
    let device = PciNic { device };
    let driver = device.current_driver().await.unwrap();
    match driver {
        Driver::Mlx5Core => println!("Driver: Mlx5Core"),
        Driver::Vhost => println!("Driver: Vhost"),
        Driver::VirtioNet => println!("Driver: VirtioNet"),
        Driver::Unknown(driver_name) => println!("Driver: Unknown ({})", driver_name),
        Driver::Unbound => println!("no driver currently bound"),
    }
    let driver2 = device.current_driver2().await.unwrap();
}
