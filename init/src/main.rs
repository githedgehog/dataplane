// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    os::unix::process::CommandExt,
};

use args::{AsFinalizedMemFile, LaunchConfiguration, NetworkDeviceDescription, Parser};
use command_fds::{CommandFdExt, FdMapping};
use hardware::{
    NodeAttributes,
    nic::{BindToVfioPci, PciNic},
    support::SupportedDevice,
};
use miette::{Context, IntoDiagnostic};
use nix::mount::MsFlags;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::layer::SubscriberExt;

fn early_init() {
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_level(true)
        .with_max_level(tracing::Level::DEBUG)
        .with_line_number(true)
        .with_test_writer()
        .finish()
        .with(tracing_error::ErrorLayer::default());
    tracing::subscriber::set_global_default(subscriber)
        .into_diagnostic()
        .wrap_err("failed to set tracing subscriber")
        .unwrap();
    info!("tracing initialized");
    color_eyre::install().unwrap();
    debug!("color-eyre enabled");
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[diagnostic(code(dataplane::initialization::error))]
pub enum InitializationError {
    #[error("no network devices specified for use in the dataplane")]
    NoDevicesSpecified,
    #[error("no network devices available for use in the dataplane")]
    NoDevicesAvailable,
    #[error(transparent)]
    DevicesNotFound(#[from] DevicesNotFound),
    #[error(transparent)]
    DevicesNotSupported(#[from] DevicesNotSupported),
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub struct DevicesNotFound {
    missing: BTreeSet<NetworkDeviceDescription>,
}

impl std::fmt::Display for DevicesNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let devices_str = self
            .missing
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "missing devices: {devices_str}")
    }
}

impl DevicesNotFound {
    pub(crate) fn new<'a>(
        missing: impl Iterator<Item = &'a NetworkDeviceDescription>,
    ) -> DevicesNotFound {
        Self {
            missing: missing.cloned().collect(),
        }
    }
}

#[derive(Debug, thiserror::Error, miette::Diagnostic, serde::Serialize)]
#[error("unsupported devices\n---\n{0}")]
pub struct DevicesNotSupported(String);

impl DevicesNotSupported {
    pub(crate) fn new(not_supported: &BTreeMap<String, &hardware::Node>) -> DevicesNotSupported {
        let yaml = serde_yaml_ng::to_string(not_supported)
            .into_diagnostic()
            .wrap_err("failed to serialize unsupported devices list")
            .unwrap();
        DevicesNotSupported(yaml)
    }
}

pub struct DeviceSearch {
    /// Devices which we were instructed to use.
    /// These are user supplied _requests_ and may include unsupported devices or devices which we can't find in a
    /// hardware scan.
    requested: BTreeSet<NetworkDeviceDescription>,
    /// Total hardware scan
    scan: hardware::Node,
}

impl DeviceSearch {
    #[tracing::instrument(level = "info", skip(requested))]
    pub fn new<'a>(requested: impl Iterator<Item = &'a NetworkDeviceDescription>) -> DeviceSearch {
        let requested: BTreeSet<_> = requested.cloned().collect();
        info!("scanning hardware for devices {requested:?}");
        let scan = hardware::Node::scan_all();
        DeviceSearch { requested, scan }
    }

    /// Walk the full system hardware scan and collect the list of devices which match the requested devices
    ///
    /// # Note
    ///
    /// This method can and will return devices which we can find in the hardware but which we do not support.
    #[tracing::instrument(level = "info", skip(self))]
    pub fn matching(&self) -> BTreeMap<NetworkDeviceDescription, &hardware::Node> {
        self.scan
            .iter()
            .filter_map(|node| {
                if let Some(attributes) = node.attributes() {
                    match attributes {
                        hardware::NodeAttributes::Pci(attributes) => {
                            let target = NetworkDeviceDescription::Pci(attributes.address());
                            if self.requested.contains(&target) {
                                Some((target, node))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Walk the full system hardware scan and collect the list of devices which are requested but which can not be
    /// found in the scan at all.
    #[must_use]
    pub fn missing(&self) -> BTreeSet<NetworkDeviceDescription> {
        let matching: BTreeSet<_> = self.matching().keys().cloned().collect();
        self.requested.difference(&matching).cloned().collect()
    }

    /// Walk a full system hardware scan and collect the list of supportable network devices.
    ///
    /// # Note
    ///
    /// The result can and may include devices which were not requested by the user.
    ///
    /// # Panics
    ///
    /// Panics if unable to serialize the device list as yaml.
    #[tracing::instrument(level = "info", skip(self))]
    pub fn supportable(&self) -> BTreeMap<NetworkDeviceDescription, &hardware::Node> {
        // hardware which we see and which we could use for packet processing if requested to do so.
        let supportable_hardware: BTreeMap<NetworkDeviceDescription, &hardware::Node> = self.scan.iter().filter_map(|node| {
            let attributes = node.attributes()?;
            match attributes {
                hardware::NodeAttributes::Pci(attributes) => {
                    match SupportedDevice::try_from((attributes.vendor_id(), attributes.device_id())) {
                        Ok(supported) => {
                            let yaml_description_of_node = serde_yaml_ng::to_string(node)
                                .into_diagnostic()
                                .wrap_err("failed to construct yaml description of hardware node")
                                .unwrap();
                            info!(
                                "found supported device {supported}:\n---\n{yaml_description_of_node}"
                            );
                            let nic_desc = NetworkDeviceDescription::Pci(attributes.address());
                            Some((nic_desc, node))
                        }
                        Err(unsupported) => {
                            trace!("found unsupported pci device device {unsupported}");
                            None
                        }
                    }
                }
                _ => None,
            }
        }).collect();

        let supportable_hardware_list_yaml = serde_yaml_ng::to_string(&supportable_hardware)
            .into_diagnostic()
            .wrap_err("failed to serialize supportable_hardware list to yaml")
            .unwrap();

        info!(
            "supportable hardware found:\n---\n{}",
            supportable_hardware_list_yaml
        );
        supportable_hardware
    }

    /// Walk the hardware scan and find the devices which are both supported and requested.
    #[must_use]
    pub fn scheduled_for_use(&self) -> BTreeMap<NetworkDeviceDescription, &hardware::Node> {
        let matching: BTreeSet<_> = self.matching().keys().cloned().collect();
        let supportable = self.supportable();
        let supportable_keys: BTreeSet<_> = supportable.keys().cloned().collect();
        let to_use: BTreeSet<_> = matching.intersection(&supportable_keys).collect();
        supportable
            .iter()
            .filter_map(|(desc, node)| {
                if to_use.contains(desc) {
                    Some((desc.clone(), *node))
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn requested_but_not_supported(&self) -> BTreeMap<String, &hardware::Node> {
        let matching = self.matching();
        let matching_keys: BTreeSet<_> = matching.keys().cloned().collect();
        let supportable = self.supportable();
        let supportable_keys: BTreeSet<_> = supportable.keys().cloned().collect();
        let unsupported: BTreeSet<_> = matching_keys
            .difference(&supportable_keys)
            .cloned()
            .collect();
        matching
            .iter()
            .filter_map(|(desc, &node)| {
                if unsupported.contains(desc) {
                    // TODO: conversion to string is required to prevent serialization failure downstream.
                    // I don't understand why this is.  It may be a bug in serde.
                    Some((desc.to_string(), node))
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn report(&self) -> NetworkDeviceSearchReport<'_> {
        NetworkDeviceSearchReport::new(self)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct NetworkDeviceSearchReport<'search> {
    requested: BTreeSet<NetworkDeviceDescription>,
    matching: BTreeMap<String, &'search hardware::Node>,
    missing: BTreeSet<NetworkDeviceDescription>,
    supportable: BTreeMap<String, &'search hardware::Node>,
    scheduled_for_use: BTreeMap<String, &'search hardware::Node>,
    // TODO: I don't understand why this key needs to be a string.
    // The requested_but_not_supported method crashes otherwise when serializing.
    requested_but_not_supported: BTreeMap<String, &'search hardware::Node>,
}

pub enum StartupViability {
    Clean,
    Warn(Vec<InitializationError>),
    Fail(Vec<InitializationError>),
}

impl<'search> NetworkDeviceSearchReport<'search> {
    fn new(search: &'search DeviceSearch) -> NetworkDeviceSearchReport<'search> {
        NetworkDeviceSearchReport {
            requested: search.requested.clone(),
            matching: search
                .matching()
                .iter()
                .map(|(k, &v)| (k.to_string(), v))
                .collect(),
            missing: search.missing(),
            supportable: search
                .supportable()
                .iter()
                .map(|(k, &v)| (k.to_string(), v))
                .collect(),
            requested_but_not_supported: search.requested_but_not_supported(),
            scheduled_for_use: search
                .scheduled_for_use()
                .iter()
                .map(|(k, &v)| (k.to_string(), v))
                .collect(),
        }
    }

    #[tracing::instrument(level = "info", skip(self))]
    fn viability(&self) -> StartupViability {
        if self.requested.is_empty() {
            return StartupViability::Fail(vec![InitializationError::NoDevicesSpecified]);
        }
        if self.scheduled_for_use.is_empty() {
            return StartupViability::Fail(vec![InitializationError::NoDevicesAvailable]);
        }
        let missing = DevicesNotFound::new(self.missing.iter());
        let not_supported = DevicesNotSupported::new(&self.requested_but_not_supported);
        if missing.missing.is_empty() && not_supported.0.is_empty() {
            info!("all requested network devices supported and detected");
            StartupViability::Clean
        } else {
            let mut ret = vec![];
            if !missing.missing.is_empty() {
                ret.push(missing.into());
            }
            if !not_supported.0.is_empty() {
                ret.push(not_supported.into());
            }
            StartupViability::Warn(ret)
        }
    }
}

impl Display for NetworkDeviceSearchReport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let as_yaml = serde_yaml_ng::to_string(self)
            .into_diagnostic()
            .wrap_err("failed to serialize NetworkDeviceSearchReport")
            .unwrap();
        write!(f, "{as_yaml}")
    }
}

pub enum NetworkDeviceDetectionError {
    NotFound(BTreeSet<NetworkDeviceDescription>),
}

#[allow(clippy::too_many_lines)] // I don't think  breaking up this function helps anything
fn main() {
    early_init();
    let main = tracing::span!(tracing::Level::INFO, "main");
    let _main = main.enter();
    debug!(
        "received command line arguments: \n  {cli_args}\n",
        cli_args = std::env::args().collect::<Vec<String>>().join("\n  ")
    );
    let args = args::CmdArgs::parse();

    // todo: format launch config as yaml
    let launch_args_yaml = serde_yaml_ng::to_string(&args)
        .into_diagnostic()
        .wrap_err("failed to serialize launch cli arguments as yaml")
        .unwrap();
    info!("parsed command line arguments as:\n---\n{launch_args_yaml}");
    let launch_config = args::LaunchConfiguration::try_from(args)
        .into_diagnostic()
        .wrap_err("invalid command line arguments given")
        .unwrap();
    // let launch_config_yaml = serde_yaml_ng::to_string(&launch_config)
    //     .into_diagnostic()
    //     .wrap_err("failed to serialize launch configuration as yaml")
    //     .unwrap();
    // info!("interpreted requested lanunch configuration as\n---\n{launch_config_yaml}");
    // Mount /tmp as tmpfs
    match &launch_config.driver {
        args::DriverConfigSection::Dpdk(dpdk_section) => {
            debug!("checking for /dev/hugepages");
            std::fs::DirBuilder::new()
                .recursive(true)
                .create("/dev/hugepages")
                .into_diagnostic()
                .wrap_err("failed to ensure /dev/hugepages exits")
                .unwrap();
            std::fs::DirBuilder::new()
                .recursive(true)
                .create("/dev/hugepages/1G")
                .into_diagnostic()
                .wrap_err("failed to ensure /dev/hugepages/1G exits")
                .unwrap();
            std::fs::DirBuilder::new()
                .recursive(true)
                .create("/dev/hugepages/2M")
                .into_diagnostic()
                .wrap_err("failed to ensure /dev/hugepages/1G exits")
                .unwrap();
            debug!("mounting /dev/hugepages/1G");
            nix::mount::mount(
                Some("hugetlbfs"),
                "/dev/hugepages/1G",
                Some("hugetlbfs"),
                MsFlags::empty(),
                Some("pagesize=1G,size=20G,rw"),
            )
            .into_diagnostic()
            .wrap_err("failed to mount hugetlbfs at /dev/hugepages")
            .unwrap();
            debug!("mounting /dev/hugepages/2M");
            nix::mount::mount(
                Some("hugetlbfs"),
                "/dev/hugepages/2M",
                Some("hugetlbfs"),
                MsFlags::empty(),
                Some("pagesize=2M,size=128M,rw"),
            )
            .into_diagnostic()
            .wrap_err("failed to mount hugetlbfs at /dev/hugepages")
            .unwrap();

            let search = DeviceSearch::new(dpdk_section.interfaces.iter().map(|it| &it.port));
            let report = search.report();
            let report_yml = serde_yaml_ng::to_string(&report)
                .into_diagnostic()
                .wrap_err("failed to serialize hardware scan report")
                .unwrap();
            info!("hardware scan report:\n---\n{report_yml}");
            match report.viability() {
                StartupViability::Clean => {}
                StartupViability::Warn(initialization_warnings) => {
                    for wrn in initialization_warnings {
                        let diagnostic = Result::<(), _>::Err(wrn).into_diagnostic().unwrap_err();
                        warn!("{diagnostic}");
                    }
                }
                StartupViability::Fail(initialization_errors) => {
                    for err in initialization_errors {
                        let diagnostic = Result::<(), _>::Err(err)
                            .into_diagnostic()
                            .wrap_err("fatal error in dataplane startup")
                            .unwrap_err();
                        error!("{diagnostic}");
                    }
                    error!("dataplane failed to initialize");
                    panic!("dataplane failed to initialize");
                }
            }
            search
                .scheduled_for_use()
                .iter()
                .for_each(|(desc, &node)| {
                    let (pci_address, vendor_id, device_id) = match node.attributes() {
                        Some(NodeAttributes::Pci(pci_attributes)) => {
                            (pci_attributes.address(), pci_attributes.vendor_id(), pci_attributes.device_id())
                        }
                        Some(_) | None => todo!(),
                    };
                    match SupportedDevice::try_from((vendor_id, device_id)) {
                        Ok(supported) => match supported {
                            SupportedDevice::IntelE1000
                            | SupportedDevice::IntelX710
                            | SupportedDevice::IntelX710VirtualFunction
                            | SupportedDevice::VirtioNet => match desc {
                                NetworkDeviceDescription::Pci(pci_address) => {
                                    let mut nic = PciNic::new(*pci_address)
                                        .into_diagnostic()
                                        .wrap_err("failed to find expected network device")
                                        .unwrap();
                                    nic.bind_to_vfio_pci()
                                        .into_diagnostic()
                                        .wrap_err(
                                            "failed to ensure network device is bound to vfio",
                                        )
                                        .unwrap();
                                }
                                NetworkDeviceDescription::Kernel(_) => {
                                    // nothing to do here
                                },
                            },
                            SupportedDevice::MellanoxConnectX6DX
                            | SupportedDevice::MellanoxConnectX7
                            | SupportedDevice::MellanoxConnectX8
                            | SupportedDevice::MellanoxBlueField2
                            | SupportedDevice::MellanoxBlueField3 => {
                                info!("device {supported} ({pci_address}) uses bifurcated driver: not attempting to bind it to vfio");
                            },
                        },
                        Err(_) => unreachable!(), // TODO: restructure to remove this branch
                    }
                });
        }
        args::DriverConfigSection::Kernel(kernel_section) => {
            // let search = DeviceSearch::new(kernel_section.interfaces.iter().map(|it| &it.port));
            // let report = search.report();
            // let report_yml = serde_yaml_ng::to_string(&report)
            //     .into_diagnostic()
            //     .wrap_err("failed to serialize hardware scan report")
            //     .unwrap();
            // info!("hardware scan report:\n---\n{report_yml}");
        }
    }

    let mut launch_config = launch_config.finalize();
    let integrity_check = launch_config.integrity_check().finalize().to_owned_fd();

    let launch_config = launch_config.to_owned_fd();

    let io_err = std::process::Command::new("/bin/dataplane")
        .fd_mappings(vec![
            FdMapping {
                parent_fd: integrity_check,
                child_fd: LaunchConfiguration::STANDARD_INTEGRITY_CHECK_FD,
            },
            FdMapping {
                parent_fd: launch_config,
                child_fd: LaunchConfiguration::STANDARD_CONFIG_FD,
            },
        ])
        .into_diagnostic()
        .wrap_err("failed to set file descriptor mapping for child process")
        .unwrap()
        .env_clear()
        .env("RUST_BACKTRACE", "full")
        .exec();

    // if we got here then we failed to exec somehow
    Result::<(), _>::Err(io_err)
        .into_diagnostic()
        .wrap_err("failed to exec child process")
        .unwrap();
}
