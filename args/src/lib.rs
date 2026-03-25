// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Argument parsing and configuration management for the dataplane.
//!
//! This crate provides command-line argument parsing ([`CmdArgs`]) and the
//! complete [`LaunchConfiguration`] type that describes how to start a dataplane
//! worker process.
//!
//! # Architecture
//!
//! 1. **Parent process (`dataplane-init`)**: parses [`CmdArgs`], converts to
//!    [`LaunchConfiguration`], serializes via `rkyv` into a sealed memfd
//!    (see [`ipc`]), and passes the file descriptor to the child.
//! 2. **Child process (`dataplane`)**: calls [`LaunchConfiguration::inherit()`]
//!    to receive, validate, memory-map, and deserialize the configuration.
//!
//! Sealed memfd primitives ([`MemFile`], [`FinalizedMemFile`], [`IntegrityCheck`])
//! are provided by the [`ipc`] crate and re-exported here for convenience.

#![deny(unsafe_code, clippy::pedantic)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub use clap::Parser;
pub use ipc::{
    AsFinalizedMemFile, FinalizedMemFile, IntegrityCheck, IntegrityCheckBytes, MemFile,
    INTEGRITY_CHECK_BYTE_LEN,
};

use hardware::pci::address::InvalidPciAddress;
use hardware::pci::address::PciAddress;
use miette::{Context, IntoDiagnostic};
use net::interface::IllegalInterfaceName;
use net::interface::InterfaceName;
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::str::FromStr;
use std::time::Duration;

#[derive(
    Debug, PartialEq, Eq, Clone, serde::Serialize, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub enum PortArg {
    Pci(PciAddress),       // DPDK driver
    Kernel(InterfaceName), // kernel driver
}

#[derive(
    Debug, PartialEq, Eq, Clone, serde::Serialize, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct InterfaceArg {
    pub interface: InterfaceName,
    pub port: Option<PortArg>,
}

/// Errors that can occur when parsing a [`PortArg`] from a string.
///
/// Port arguments follow the syntax `DISCRIMINANT@VALUE`, where the discriminant
/// is either `pci` (followed by a PCI address) or `kernel` (followed by a kernel
/// interface name).
#[derive(Debug, thiserror::Error)]
pub enum PortArgParseError {
    /// The input string is missing the `@` separator between discriminant and value.
    #[error("bad syntax: expected DISCRIMINANT@VALUE, missing '@' separator")]
    MissingSeparator,
    /// The PCI address following `pci@` could not be parsed.
    #[error("invalid PCI address: {0}")]
    InvalidPciAddress(#[from] InvalidPciAddress),
    /// The kernel interface name following `kernel@` is not a valid interface name.
    #[error("invalid kernel interface name: {0}")]
    InvalidInterfaceName(#[from] IllegalInterfaceName),
    /// The discriminant is not one of the recognized values (`pci` or `kernel`).
    #[error("unknown port type '{0}': expected 'pci' or 'kernel'")]
    UnknownDiscriminant(String),
}

/// Errors that can occur when parsing an [`InterfaceArg`] from a string.
///
/// Interface arguments follow the syntax `INTERFACE=DISCRIMINANT@VALUE` or simply
/// `INTERFACE` when no port mapping is provided.
#[derive(Debug, thiserror::Error)]
pub enum InterfaceArgParseError {
    /// The interface name portion of the argument is not a valid interface name.
    #[error("invalid interface name: {0}")]
    InvalidInterfaceName(#[from] IllegalInterfaceName),
    /// The port specifier following the `=` could not be parsed.
    #[error("invalid port specifier: {0}")]
    InvalidPort(#[from] PortArgParseError),
}

impl FromStr for PortArg {
    type Err = PortArgParseError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (disc, value) = input
            .split_once('@')
            .ok_or(PortArgParseError::MissingSeparator)?;

        match disc {
            "pci" => {
                let pciaddr = PciAddress::try_from(value)?;
                Ok(PortArg::Pci(pciaddr))
            }
            "kernel" => {
                let kernelif = InterfaceName::try_from(value)?;
                Ok(PortArg::Kernel(kernelif))
            }
            _ => Err(PortArgParseError::UnknownDiscriminant(disc.to_string())),
        }
    }
}

impl FromStr for InterfaceArg {
    type Err = InterfaceArgParseError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some((first, second)) = input.split_once('=') {
            let interface = InterfaceName::try_from(first)?;

            let port = PortArg::from_str(second)?;
            Ok(InterfaceArg {
                interface,
                port: Some(port),
            })
        } else {
            let interface = InterfaceName::try_from(input)?;
            Ok(InterfaceArg {
                interface,
                port: None,
            })
        }
    }
}

impl std::fmt::Display for PortArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortArg::Pci(addr) => write!(f, "pci@{addr}"),
            PortArg::Kernel(name) => write!(f, "kernel@{name}"),
        }
    }
}

impl std::fmt::Display for InterfaceArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.port {
            Some(port) => write!(f, "{}={port}", self.interface),
            None => write!(f, "{}", self.interface),
        }
    }
}

use bytecheck::CheckBytes;

/// Default path to the dataplane's control plane unix socket.
///
/// This socket is used by FRR to send route update messages to the dataplane process.
pub const DEFAULT_DP_UX_PATH: &str = "/var/run/frr/hh/dataplane.sock";

/// Default path to the dataplane's CLI socket.
///
/// This socket is used to accept connections from the dataplane CLI tool for
/// runtime inspection and control.
pub const DEFAULT_DP_UX_PATH_CLI: &str = "/var/run/dataplane/cli.sock";

/// Default path to the FRR agent socket.
///
/// This socket is used to connect to the FRR agent that controls FRR
/// configuration reloads.
pub const DEFAULT_FRR_AGENT_PATH: &str = "/var/run/frr/frr-agent.sock";

/// General configuration section for the dataplane.
///
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(Debug, PartialEq, Eq)))]
pub struct GeneralConfigSection {
    /// Name to give to this dataplane/gateway
    name: Option<String>,
}

/// Configuration for the packet processing driver used by the dataplane.
///
/// The dataplane supports two packet processing backends:
///
/// - **DPDK (Data Plane Development Kit)**: High-performance userspace driver for
///   specialized network hardware. Provides kernel-bypass networking with direct access
///   to NIC hardware via PCI.
///
/// - **Kernel**: Standard Linux kernel networking stack. Uses traditional network
///   interfaces and kernel packet processing.
///
/// # Choosing a Driver
///
/// - Use **DPDK** for maximum performance on supported hardware, typically in production
///   environments with dedicated NICs.
/// - Use **Kernel** for development, testing, or environments without DPDK-compatible
///   hardware.
///
/// # Note
///
/// This type does not derive `CheckBytes` because its inner types contain
/// [`InterfaceName`] which does not yet implement `CheckBytes`.
/// Adding that derive to `InterfaceName` in the `net` crate would unblock this.
#[derive(
    Debug, PartialEq, Eq, serde::Serialize, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive,
)]
#[serde(tag = "driver")]
#[serde(rename_all = "snake_case")]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub enum DriverConfigSection {
    /// DPDK userspace driver configuration
    Dpdk(DpdkDriverConfigSection),
    /// Linux kernel driver configuration
    Kernel(KernelDriverConfigSection),
}

/// Configuration for the DPDK (Data Plane Development Kit) driver.
///
/// DPDK provides kernel-bypass networking for high-performance packet processing.
/// This configuration specifies which NICs to use and how to initialize the DPDK
/// Environment Abstraction Layer (EAL).
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(Debug, PartialEq, Eq)))]
pub struct DpdkDriverConfigSection {
    /// Network devices to use with DPDK (identified by PCI address)
    pub interfaces: Vec<InterfaceArg>,
    /// DPDK EAL (Environment Abstraction Layer) initialization arguments
    pub eal_args: Vec<String>,
}

/// Configuration for the Linux kernel networking driver.
///
/// Uses the standard Linux kernel network stack for packet processing.
/// This is suitable for development, testing, or environments without
/// DPDK-compatible hardware.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct KernelDriverConfigSection {
    /// Kernel network interfaces to manage
    pub interfaces: Vec<InterfaceArg>,
}

/// Configuration for the dataplane's command-line interface (CLI).
///
/// Specifies where the CLI server listens for connections from CLI clients
/// that want to inspect or control the running dataplane.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct CliConfigSection {
    /// Unix socket path for CLI connections
    pub cli_sock_path: String,
}

/// Configuration for metrics collection and export.
///
/// Defines the HTTP endpoint where Prometheus-compatible metrics are exposed.
/// Metrics include packet counters, latency statistics, and other operational
/// telemetry.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct MetricsConfigSection {
    /// Socket address (IP and port) where metrics HTTP endpoint listens
    pub address: SocketAddr,
}

/// Configuration for the tracing / logging service used by the dataplane.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct TracingConfigSection {
    /// Display options for trace output
    pub show: TracingShowSection,
    /// Tracing configuration string (e.g., "default=info,nat=debug")
    pub config: Option<String>, // TODO: stronger typing on this config?
}

/// Display option for trace metadata elements.
///
/// Controls whether specific metadata is shown in trace output.
#[derive(
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TracingDisplayOption {
    /// Hide this metadata element
    #[default]
    Hide,
    /// Show this metadata element
    Show,
}

/// Display configuration for trace metadata.
///
/// Controls which metadata elements are included in trace output.
#[derive(
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct TracingShowSection {
    /// Whether to display span/event tags
    pub tags: TracingDisplayOption,
    /// Whether to display target module paths
    pub targets: TracingDisplayOption,
}

/// Configuration for routing control plane integration.
///
/// Defines how the dataplane communicates with FRR (Free Range Routing) and
/// related routing components.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct RoutingConfigSection {
    /// Unix socket path for receiving route updates from FRR
    pub control_plane_socket: String,
    /// Unix socket path for FRR agent communication
    pub frr_agent_socket: String,
}

/// Configuration for the dynamic configuration server.
///
/// The configuration server provides runtime configuration updates to the dataplane
/// via gRPC. This allows modifying dataplane behavior without restarting the process.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct ConfigServerSection {
    pub config_dir: Option<String>,
}

/// BMP server configuration (optional; disabled when absent)
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct BmpConfigSection {
    /// Bind address for the BMP server (IP:PORT)
    pub address: SocketAddr,
    /// Periodic housekeeping/flush interval in milliseconds
    pub interval: Duration,
}

/// Complete dataplane launch configuration.
///
/// This structure contains all configuration parameters needed to initialize and run
/// the dataplane process. It is typically constructed from command-line arguments in
/// the `dataplane-init` process, then serialized and passed to the `dataplane` worker
/// process via sealed memory file descriptors.
///
/// # Architecture
///
/// The configuration flow:
///
/// 1. **Init Process**: Parses [`CmdArgs`] and converts to [`LaunchConfiguration`]
/// 2. **Serialization**: Configuration is serialized using `rkyv` for zero-copy access
/// 3. **Transfer**: Passed via sealed memfd to the worker process
/// 4. **Worker Process**: Calls [`LaunchConfiguration::inherit()`] to access the config
///
/// TODO: implement `bytecheck::Validate` in addition to `CheckBytes` on all components of the launch config.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct LaunchConfiguration {
    /// General configuration section
    pub general: GeneralConfigSection,
    /// Dynamic configuration server settings
    pub config_server: Option<ConfigServerSection>,
    /// Packet processing driver configuration
    pub driver: DriverConfigSection,
    /// CLI server configuration
    pub cli: CliConfigSection,
    /// Routing control plane integration
    pub routing: RoutingConfigSection,
    /// Logging and tracing configuration
    pub tracing: TracingConfigSection,
    /// Metrics collection configuration
    pub metrics: MetricsConfigSection,
    /// Optional BMP server configuration (None => BMP disabled)
    pub bmp: Option<BmpConfigSection>,
    /// Profiling configuration
    pub profiling: ProfilingConfigSection,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct ProfilingConfigSection {
    /// The Pyroscope server URL
    pub pyroscope_url: Option<String>,
    /// Frequency with which we collect stack traces
    pub frequency: u32,
}

impl ProfilingConfigSection {
    pub const DEFAULT_FREQUENCY: u32 = 100;
}

impl Default for ProfilingConfigSection {
    fn default() -> Self {
        Self {
            pyroscope_url: None,
            frequency: Self::DEFAULT_FREQUENCY,
        }
    }
}

impl LaunchConfiguration {
    /// Standard file descriptor number for the integrity check memfd.
    ///
    /// The parent process must pass the integrity check (SHA-384 hash) file at this
    /// file descriptor number.
    pub const STANDARD_INTEGRITY_CHECK_FD: RawFd = 30;

    /// Standard file descriptor number for the configuration memfd.
    ///
    /// The parent process must pass the serialized configuration file at this
    /// file descriptor number.
    pub const STANDARD_CONFIG_FD: RawFd = 40;

    /// Inherit the launch configuration from the parent process.
    ///
    /// This method is called by the dataplane worker process to receive its configuration
    /// from the init process. It expects two sealed memory file descriptors at the standard
    /// FD numbers ([`STANDARD_INTEGRITY_CHECK_FD`](Self::STANDARD_INTEGRITY_CHECK_FD) and
    /// [`STANDARD_CONFIG_FD`](Self::STANDARD_CONFIG_FD)).
    ///
    /// # Process
    ///
    /// 1. Receives integrity check and configuration file descriptors
    /// 2. Validates the SHA-384 hash matches the configuration
    /// 3. Memory-maps the configuration for zero-copy access
    /// 4. Validates the archived data structure (alignment, bounds, enum variants)
    /// 5. Deserializes the configuration
    ///
    /// # Panics
    ///
    /// This method is designed for early process initialization and will panic if:
    ///
    /// - File descriptors are missing or invalid
    /// - Integrity check validation fails (hash mismatch)
    /// - Memory mapping fails
    /// - Archived data is misaligned or has invalid size
    /// - Deserialization fails (corrupt or invalid data)
    ///
    /// These panics are intentional as the dataplane cannot start without valid configuration.
    #[must_use]
    #[allow(unsafe_code)] // no-escape from unsafety in this function as it involves constraints the compiler can't see
    pub fn inherit() -> LaunchConfiguration {
        let integrity_check_fd = unsafe { OwnedFd::from_raw_fd(Self::STANDARD_INTEGRITY_CHECK_FD) };
        let launch_configuration_fd = unsafe { OwnedFd::from_raw_fd(Self::STANDARD_CONFIG_FD) };
        let mut integrity_check_file = unsafe { FinalizedMemFile::from_fd(integrity_check_fd) };
        let mut launch_configuration_file =
            unsafe { FinalizedMemFile::from_fd(launch_configuration_fd) };
        launch_configuration_file
            .validate(&mut integrity_check_file)
            .wrap_err("checksum validation failed for launch configuration")
            .unwrap();

        let mut mmap_options = memmap2::MmapOptions::new();
        let mmap_options = mmap_options.no_reserve_swap();
        let launch_config_memmap = unsafe { mmap_options.map(launch_configuration_file.as_ref()) }
            .into_diagnostic()
            .wrap_err("failed to memory map launch configuration")
            .unwrap();

        // VERY IMPORTANT: we must check for unaligned pointer here or risk undefined behavior.

        // deactivate the lint because checking for alignment is _exactly_ what we are doing here
        #[allow(clippy::cast_ptr_alignment)]
        let is_aligned = launch_config_memmap
            .as_ptr()
            .cast::<ArchivedLaunchConfiguration>()
            .is_aligned();
        assert!(
            is_aligned,
            "invalid alignment for ArchivedLaunchConfiguration found in inherited memfd"
        );

        assert!(
            launch_config_memmap.as_ref().len() >= size_of::<ArchivedLaunchConfiguration>(),
            "invalid size for inherited memfd"
        );

        // from_bytes internally calls access(), which performs CheckBytes validation
        // (alignment, bounds, enum discriminants) before deserializing.
        rkyv::from_bytes::<LaunchConfiguration, rkyv::rancor::Error>(launch_config_memmap.as_ref())
            .into_diagnostic()
            .wrap_err("failed to deserialize launch configuration")
            .unwrap()
    }
}

impl AsFinalizedMemFile for LaunchConfiguration {
    fn finalize(self) -> FinalizedMemFile {
        let serialized_config = rkyv::to_bytes::<rkyv::rancor::Error>(&self)
            .into_diagnostic()
            .wrap_err("failed to serialize dataplane configuration")
            .unwrap();
        let config_bytes = serialized_config.as_slice();

        let mut memfd = MemFile::new();
        memfd
            .as_mut()
            .write_all(config_bytes)
            .into_diagnostic()
            .wrap_err("failed to write dataplane configuration to memfd")
            .unwrap();
        memfd.finalize()
    }
}

/// Errors that can occur when parsing or validating command-line arguments.
///
/// These errors occur during the conversion from [`CmdArgs`] to [`LaunchConfiguration`]
/// when argument values are invalid or inconsistent.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum InvalidCmdArguments {
    /// Invalid PCI device address format.
    ///
    /// PCI addresses must follow the format: `domain:bus:device.function`
    /// (e.g., `0000:01:00.0`)
    #[error(transparent)]
    InvalidPciAddress(#[from] InvalidPciAddress),

    /// Invalid network interface name.
    ///
    /// Interface names must be valid Linux network interface names
    /// (e.g., `eth0`, `ens3`)
    #[error(transparent)]
    InvalidInterfaceName(#[from] IllegalInterfaceName),
    #[error("\"{0}\" is not a valid driver.  Must be dpdk or kernel")]
    InvalidDriver(String),
    #[error("Must specify driver as dpdk or kernel")]
    NoDriverSpecified,
    #[error("No network interfaces specified")]
    NoInterfacesSpecified,
    /// A DPDK interface was specified without a port (PCI address) mapping.
    ///
    /// DPDK requires each interface to have an explicit PCI address binding
    /// via the `pci@ADDR` syntax.
    #[error("DPDK interface '{0}' is missing a port specifier (expected pci@ADDR)")]
    MissingPortSpecifier(InterfaceName),
    #[error(transparent)]
    UnsupportedByDriver(#[from] UnsupportedByDriver),
}

/// Errors resulting from invalid command lines (driver to interface spec mismatch)
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum UnsupportedByDriver {
    #[error(
        "DPDK driver does not support interfaces specified by their kernel driver name; {0} given"
    )]
    Dpdk(InterfaceName),
    #[error(
        "Kernel driver does not support interfaces specified by their dpdk driver name; {0} given"
    )]
    Kernel(PciAddress),
}

impl TryFrom<CmdArgs> for LaunchConfiguration {
    type Error = InvalidCmdArguments;

    fn try_from(value: CmdArgs) -> Result<Self, InvalidCmdArguments> {
        if value.interface.is_empty() {
            return Err(InvalidCmdArguments::NoInterfacesSpecified);
        }
        Ok(LaunchConfiguration {
            general: GeneralConfigSection {
                name: value.get_name().cloned(),
            },
            config_server: Some(ConfigServerSection {
                config_dir: value.config_dir().cloned(),
            }),
            driver: value.build_driver_config()?,
            cli: CliConfigSection {
                cli_sock_path: value.cli_sock_path().to_owned(),
            },
            routing: RoutingConfigSection {
                control_plane_socket: value.cpi_sock_path().to_owned(),
                frr_agent_socket: value.frr_agent_path().to_owned(),
            },
            tracing: value.build_tracing_config(),
            metrics: MetricsConfigSection {
                address: value.metrics_address(),
            },
            bmp: value.build_bmp_config(),
            profiling: ProfilingConfigSection {
                pyroscope_url: value.pyroscope_url().map(std::string::ToString::to_string),
                frequency: ProfilingConfigSection::DEFAULT_FREQUENCY,
            },
        })
    }
}

#[derive(Parser, serde::Serialize)]
#[command(name = "Hedgehog Gateway dataplane version:")]
#[command(version = option_env!("VERSION").unwrap_or("dev"))]
#[command(about = "A dataplane for hedgehog's fabric gateway", long_about = None)]
#[allow(clippy::struct_excessive_bools)]
pub struct CmdArgs {
    #[arg(long, value_name = "packet driver to use: kernel or dpdk")]
    driver: Option<String>,
    #[arg(
        long,
        value_name = "interface name",
        value_parser=InterfaceArg::from_str,
        value_delimiter=',',
        help = "Interface name mapping, with syntax INTERFACE=DISCRIMINANT@{PCI,IFNAME}. Two discriminants are possible: pci and kernel.
Pci should be followed by a PCI address. Kernel should be followed by a valid kernel interface name.
Examples:
   --interface eth0=pci@0000:02:01.0
   --interface eth1=kernel@enp2s1
Note: multiple interfaces can be specified separated by commas and no spaces"
    )]
    interface: Vec<InterfaceArg>,

    /// Number of worker threads for the kernel driver.
    #[arg(
        long,
        value_name = "N",
        default_value_t = 1,
        value_parser = clap::value_parser!(u16).range(1..=64),
        help = "Number of worker threads for the kernel driver in [1..64]"
    )]
    num_workers: u16,

    #[arg(
        long,
        value_name = "CPI Unix socket path",
        help = "Unix socket for FRR to send route update messages to the dataplane",
        default_value = DEFAULT_DP_UX_PATH
    )]
    cpi_sock_path: String,

    #[arg(
        long,
        value_name = "CLI Unix socket path",
        help = "Unix socket to listen for dataplane cli connections",
        default_value = DEFAULT_DP_UX_PATH_CLI
    )]
    cli_sock_path: String,

    #[arg(
        long,
        value_name = "FRR Agent Unix socket path",
        help = "Unix socket to connect to FRR agent that controls FRR configuration reload",
        default_value = DEFAULT_FRR_AGENT_PATH
    )]
    frr_agent_path: String,

    /// Prometheus metrics server bind address
    #[arg(
        long,
        value_name = "Metrics Address and Port",
        default_value_t = SocketAddr::from(([127, 0, 0, 1], 9090)),
        help = "Bind address and port for Prometheus metrics HTTP endpoint"
    )]
    metrics_address: SocketAddr,

    /// Pyroscope server address for profiling uploads
    #[arg(
        long,
        value_name = "URL of pyroscope server",
        help = "URL of Pyroscope server (e.g. http://127.0.0.1:4040)"
    )]
    pyroscope_url: Option<url::Url>,

    #[arg(
        long,
        default_value_t = false,
        help = "Show the available tracing tags and exit"
    )]
    show_tracing_tags: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Show configurable tracing targets and exit"
    )]
    show_tracing_targets: bool,

    #[arg(long, help = "generate tracing configuration as a string and exit")]
    tracing_config_generate: bool,

    #[arg(
        long,
        value_name = "tracing configuration",
        help = "Tracing config string as comma-separated sequence of tag=level, with level one in [off,error,warn,info,debug,trace].
Passing default=level sets the default log-level.
Passing all=level allows setting the log-level of all targets to level.
E.g. default=error,all=info,nat=debug will set the default target to error, and all the registered targets to info, but enable debug for nat"
    )]
    tracing: Option<String>,

    #[arg(long, help = "Set the name of this gateway")]
    name: Option<String>,

    #[arg(
        long,
        help = "Run in k8s-less mode using this directory to watch for configurations.
You can copy json/yaml config files in this directory to reconfigure dataplane. You can modify existing
files or just 'touch' them to trigger a new reconfiguration. Every change will increase the generation id by one.
NOTE: dataplane tracks file 'save' events. If you modify an existing file, depending on the editor used, this will
trigger more than one reconfiguration (e.g. gedit). If this is undesired, use nano or vi(m), or edit your file
elsewhere and copy it in the configuration directory. This mode is meant mostly for debugging or early testing."
    )]
    config_dir: Option<String>,
    /// Enable BMP server
    #[arg(long, default_value_t = false, help = "Enable BMP server")]
    bmp_enable: bool,

    #[arg(
        long,
        value_name = "IP:PORT",
        default_value_t = SocketAddr::from(([0, 0, 0, 0], 5000)),
        help = "Bind address for the BMP server"
    )]
    bmp_address: SocketAddr,

    #[arg(
        long,
        value_name = "MILLISECONDS",
        default_value_t = 10_000,
        help = "BMP periodic interval for housekeeping/flush (ms)"
    )]
    bmp_interval: u64,
}

impl CmdArgs {
    /// Build the [`DriverConfigSection`] from the parsed command-line arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No driver was specified.
    /// - The driver name is not recognized.
    /// - A DPDK interface is missing a PCI address binding.
    /// - A kernel interface name was given to the DPDK driver (or vice-versa).
    fn build_driver_config(&self) -> Result<DriverConfigSection, InvalidCmdArguments> {
        match &self.driver {
            Some(driver) if driver == "dpdk" => {
                // TODO: adjust command line to specify lcore usage more flexibly in next PR
                let eal_args = self
                    .interfaces()
                    .map(|nic| match nic.port {
                        Some(PortArg::Pci(pci_address)) => {
                            Ok(["--allow".to_string(), format!("{pci_address}")])
                        }
                        Some(PortArg::Kernel(interface_name)) => {
                            Err(InvalidCmdArguments::UnsupportedByDriver(
                                UnsupportedByDriver::Dpdk(interface_name.clone()),
                            ))
                        }
                        None => Err(InvalidCmdArguments::MissingPortSpecifier(
                            nic.interface.clone(),
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .flatten()
                    .collect();
                Ok(DriverConfigSection::Dpdk(DpdkDriverConfigSection {
                    interfaces: self.interfaces().collect(),
                    eal_args,
                }))
            }
            Some(driver) if driver == "kernel" => {
                Ok(DriverConfigSection::Kernel(KernelDriverConfigSection {
                    interfaces: self.interfaces().collect(),
                }))
            }
            Some(other) => Err(InvalidCmdArguments::InvalidDriver(other.clone())),
            None => Err(InvalidCmdArguments::NoDriverSpecified),
        }
    }

    /// Build the [`TracingConfigSection`] from the parsed command-line arguments.
    fn build_tracing_config(&self) -> TracingConfigSection {
        TracingConfigSection {
            show: TracingShowSection {
                tags: if self.show_tracing_tags() {
                    TracingDisplayOption::Show
                } else {
                    TracingDisplayOption::Hide
                },
                targets: if self.show_tracing_targets() {
                    TracingDisplayOption::Show
                } else {
                    TracingDisplayOption::Hide
                },
            },
            config: self.tracing.clone(),
        }
    }

    /// Build the optional [`BmpConfigSection`] from the parsed command-line
    /// arguments.
    ///
    /// Returns `None` when BMP is not enabled.
    fn build_bmp_config(&self) -> Option<BmpConfigSection> {
        if self.bmp_enabled() {
            Some(BmpConfigSection {
                address: self.bmp_address(),
                interval: self.bmp_interval(),
            })
        } else {
            None
        }
    }

    /// Get the configured driver name.
    ///
    /// Returns `"dpdk"` if no driver was explicitly specified (the default),
    /// otherwise returns the specified driver name (`"dpdk"` or `"kernel"`).
    #[must_use]
    pub fn driver_name(&self) -> Option<&str> {
        self.driver.as_deref()
    }

    /// Check if the `--show-tracing-tags` flag was set.
    ///
    /// When true, the application should display available tracing tags and exit.
    ///
    /// # Returns
    ///
    /// `true` if `--show-tracing-tags` was passed, `false` otherwise.
    #[must_use]
    pub fn show_tracing_tags(&self) -> bool {
        self.show_tracing_tags
    }

    /// Check if the `--show-tracing-targets` flag was set.
    ///
    /// When true, the application should display configurable tracing targets and exit.
    ///
    /// # Returns
    ///
    /// `true` if `--show-tracing-targets` was passed, `false` otherwise.
    #[must_use]
    pub fn show_tracing_targets(&self) -> bool {
        self.show_tracing_targets
    }

    /// Check if the `--tracing-config-generate` flag was set.
    ///
    /// When true, the application should generate a tracing configuration string
    /// as output and exit.
    ///
    /// # Returns
    ///
    /// `true` if `--tracing-config-generate` was passed, `false` otherwise.
    #[must_use]
    pub fn tracing_config_generate(&self) -> bool {
        self.tracing_config_generate
    }

    /// Get the tracing configuration string, if provided.
    ///
    /// Returns the value of the `--tracing` argument, which specifies log levels
    /// for different components in the format `target1=level1,target2=level2`.
    ///
    /// # Returns
    ///
    /// `Some(&String)` if a tracing configuration was provided, `None` otherwise.
    #[must_use]
    pub fn tracing(&self) -> Option<&String> {
        self.tracing.as_ref()
    }

    /// Get the number of worker threads for the kernel driver.
    ///
    /// This value comes from the `--num-workers` argument (default: 1, range: 1-64).
    ///
    /// # Returns
    ///
    /// The number of worker threads as a `usize`.
    ///
    /// # Note
    ///
    /// This value is only relevant when using the kernel driver. The DPDK driver
    /// uses its own threading model configured via EAL arguments.
    #[must_use]
    pub fn kernel_num_workers(&self) -> usize {
        self.num_workers.into()
    }

    /// Get the list of kernel network interfaces to use.
    ///
    /// Returns the interfaces specified via `--interface` arguments.
    ///
    /// # Returns
    ///
    /// A vector of interface name strings (e.g., `vec!["eth0", "eth1"]`).
    ///
    /// # Note
    ///
    /// This is only used with the kernel driver.
    #[must_use]
    pub fn kernel_interfaces(&self) -> Vec<String> {
        self.interface
            .iter()
            .map(|spec| spec.interface.to_string())
            .collect()
    }

    /// Get all configured network interfaces.
    ///
    /// This is the primary interface getter and should be used by all drivers.
    #[must_use]
    pub fn interfaces(&self) -> impl Iterator<Item = InterfaceArg> {
        self.interface.iter().cloned()
    }

    /// Get the control plane interface socket path.
    ///
    /// Returns the path where FRR (Free Range Routing) sends route updates to the dataplane.
    #[must_use]
    pub fn cpi_sock_path(&self) -> &str {
        &self.cpi_sock_path
    }

    /// Get the CLI socket path.
    ///
    /// Returns the path where the dataplane CLI server listens for client connections.
    #[must_use]
    pub fn cli_sock_path(&self) -> &str {
        &self.cli_sock_path
    }

    /// Get the FRR agent socket path.
    ///
    /// Returns the path to connect to the FRR agent that controls FRR configuration reloads.
    #[must_use]
    pub fn frr_agent_path(&self) -> &str {
        &self.frr_agent_path
    }

    /// Get the Prometheus metrics HTTP endpoint address.
    ///
    /// Returns the socket address (IP and port) where the dataplane exposes
    /// Prometheus-compatible metrics for scraping.
    #[must_use]
    pub fn metrics_address(&self) -> SocketAddr {
        self.metrics_address
    }

    #[must_use]
    pub fn pyroscope_url(&self) -> Option<&url::Url> {
        self.pyroscope_url.as_ref()
    }

    /// Get the name to configure this gateway with.
    #[must_use]
    pub fn get_name(&self) -> Option<&String> {
        self.name.as_ref()
    }
    #[must_use]
    pub fn bmp_enabled(&self) -> bool {
        self.bmp_enable
    }
    #[must_use]
    pub fn bmp_address(&self) -> SocketAddr {
        self.bmp_address
    }
    #[must_use]
    pub fn bmp_interval(&self) -> Duration {
        Duration::from_millis(self.bmp_interval)
    }

    /// Get the configuration directory.
    /// Setting the configuration directory enables k8s-less mode, where configurations are retrieved from files
    /// or their changes in the configuration directory.
    #[must_use]
    pub fn config_dir(&self) -> Option<&String> {
        self.config_dir.as_ref()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{InterfaceArg, PortArg};
    use bolero::{Driver, TypeGenerator};
    use net::interface::InterfaceName;

    impl TypeGenerator for PortArg {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            if driver.produce::<bool>()? {
                Some(PortArg::Pci(driver.produce()?))
            } else {
                Some(PortArg::Kernel(driver.produce()?))
            }
        }
    }

    impl TypeGenerator for InterfaceArg {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let interface: InterfaceName = driver.produce()?;
            let port = if driver.produce::<bool>()? {
                Some(driver.produce::<PortArg>()?)
            } else {
                None
            };
            Some(InterfaceArg { interface, port })
        }
    }
}

#[cfg(test)]
mod tests {
    use hardware::pci::address::PciAddress;
    use hardware::pci::bus::Bus;
    use hardware::pci::device::Device;
    use hardware::pci::domain::Domain;
    use hardware::pci::function::Function;
    use net::interface::InterfaceName;

    use crate::{
        CmdArgs, DriverConfigSection, InterfaceArg, InvalidCmdArguments, LaunchConfiguration,
        PortArg, TracingDisplayOption, UnsupportedByDriver,
    };
    use clap::Parser;
    use std::str::FromStr;

    #[test]
    fn test_parse_interface() {
        // interface + port as PCI address
        let spec = InterfaceArg::from_str("GbEth1.9000=pci@0000:02:01.7").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");
        assert_eq!(
            spec.port,
            Some(PortArg::Pci(PciAddress::new(
                Domain::from(0),
                Bus::new(2),
                Device::try_from(1).unwrap(),
                Function::try_from(7).unwrap()
            )))
        );

        // interface + port as kernel interface
        let spec = InterfaceArg::from_str("GbEth1.9000=kernel@enp2s1.100").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");
        assert_eq!(
            spec.port,
            Some(PortArg::Kernel(
                InterfaceName::try_from("enp2s1.100").unwrap()
            ))
        );

        // interface only (backwards compatibility)
        let spec = InterfaceArg::from_str("GbEth1.9000").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");
        assert!(spec.port.is_none());

        // bad pci address
        assert!(InterfaceArg::from_str("GbEth1.9000=pci@0000:02:01").is_err());

        // bad kernel interface
        assert!(InterfaceArg::from_str("GbEth1.9000=kernel@0000:02:01").is_err());

        // bad discriminant
        assert!(InterfaceArg::from_str("GbEth1.9000=foo@0000:02:01.7").is_err());
    }

    // -------------------------------------------------------------------
    // Property-based tests (bolero)
    // -------------------------------------------------------------------

    #[test]
    fn port_arg_display_parse_roundtrip_pci() {
        bolero::check!()
            .with_type::<PciAddress>()
            .for_each(|pci| {
                let original = PortArg::Pci(pci.clone());
                let serialized = original.to_string();
                let parsed = PortArg::from_str(&serialized).unwrap();
                assert_eq!(original, parsed);
            });
    }

    #[test]
    fn port_arg_display_parse_roundtrip_kernel() {
        bolero::check!()
            .with_type::<InterfaceName>()
            .for_each(|name| {
                let original = PortArg::Kernel(name.clone());
                let serialized = original.to_string();
                let parsed = PortArg::from_str(&serialized).unwrap();
                assert_eq!(original, parsed);
            });
    }

    #[test]
    fn interface_arg_parse_roundtrip_with_pci_port() {
        bolero::check!()
            .with_type::<(InterfaceName, PciAddress)>()
            .for_each(|(iface, pci)| {
                let original = InterfaceArg {
                    interface: iface.clone(),
                    port: Some(PortArg::Pci(pci.clone())),
                };
                let serialized = original.to_string();
                let parsed = InterfaceArg::from_str(&serialized).unwrap();
                assert_eq!(original, parsed);
            });
    }

    #[test]
    fn interface_arg_parse_roundtrip_with_kernel_port() {
        bolero::check!()
            .with_type::<(InterfaceName, InterfaceName)>()
            .for_each(|(iface, port_name)| {
                let original = InterfaceArg {
                    interface: iface.clone(),
                    port: Some(PortArg::Kernel(port_name.clone())),
                };
                let serialized = original.to_string();
                let parsed = InterfaceArg::from_str(&serialized).unwrap();
                assert_eq!(original, parsed);
            });
    }

    #[test]
    fn interface_arg_parse_roundtrip_no_port() {
        bolero::check!()
            .with_type::<InterfaceName>()
            .for_each(|name| {
                let original = InterfaceArg {
                    interface: name.clone(),
                    port: None,
                };
                let serialized = original.to_string();
                // Skip names that happen to contain '=' (not generated, but be safe).
                if !serialized.contains('=') {
                    let parsed = InterfaceArg::from_str(&serialized).unwrap();
                    assert_eq!(original, parsed);
                }
            });
    }

    #[test]
    fn port_arg_rejects_missing_separator() {
        bolero::check!()
            .with_type::<InterfaceName>()
            .for_each(|name| {
                let input = format!("pci{name}");
                // No '@' separator, so this should fail.
                assert!(PortArg::from_str(&input).is_err());
            });
    }

    #[test]
    fn port_arg_rejects_unknown_discriminant() {
        bolero::check!()
            .with_type::<PciAddress>()
            .for_each(|pci| {
                let input = format!("unknown@{pci}");
                let err = PortArg::from_str(&input).unwrap_err();
                assert!(
                    matches!(err, crate::PortArgParseError::UnknownDiscriminant(_)),
                    "expected UnknownDiscriminant, got {err:?}"
                );
            });
    }

    // -------------------------------------------------------------------
    // CmdArgs → LaunchConfiguration conversion tests
    // -------------------------------------------------------------------

    /// Helper to parse a command line into [`CmdArgs`] without process exit on
    /// error.
    fn parse_args(args: &[&str]) -> CmdArgs {
        let mut full_args = vec!["dataplane"];
        full_args.extend_from_slice(args);
        CmdArgs::parse_from(full_args)
    }

    #[test]
    fn try_from_kernel_driver_with_interface() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert!(matches!(config.driver, DriverConfigSection::Kernel(_)));
        if let DriverConfigSection::Kernel(ref k) = config.driver {
            assert_eq!(k.interfaces.len(), 1);
            assert_eq!(k.interfaces[0].interface.as_ref(), "eth0");
        }
    }

    #[test]
    fn try_from_kernel_driver_multiple_interfaces() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1,eth1=kernel@enp3s0",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        if let DriverConfigSection::Kernel(ref k) = config.driver {
            assert_eq!(k.interfaces.len(), 2);
        } else {
            panic!("expected kernel driver config");
        }
    }

    #[test]
    fn try_from_dpdk_driver_with_pci_interface() {
        let args = parse_args(&[
            "--driver",
            "dpdk",
            "--interface",
            "eth0=pci@0000:02:01.0",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert!(matches!(config.driver, DriverConfigSection::Dpdk(_)));
        if let DriverConfigSection::Dpdk(ref d) = config.driver {
            assert_eq!(d.interfaces.len(), 1);
            // Two EAL args per interface: "--allow" and the PCI address.
            assert_eq!(d.eal_args.len(), 2);
            assert_eq!(d.eal_args[0], "--allow");
            assert_eq!(d.eal_args[1], "0000:02:01.0");
        }
    }

    #[test]
    fn try_from_no_driver_is_error() {
        let args = parse_args(&["--interface", "eth0=kernel@enp2s1"]);
        let err = LaunchConfiguration::try_from(args).unwrap_err();
        assert!(matches!(err, InvalidCmdArguments::NoDriverSpecified));
    }

    #[test]
    fn try_from_no_interfaces_is_error() {
        let args = parse_args(&["--driver", "kernel"]);
        let err = LaunchConfiguration::try_from(args).unwrap_err();
        assert!(
            matches!(err, InvalidCmdArguments::NoInterfacesSpecified),
            "expected NoInterfacesSpecified, got {err:?}"
        );
    }

    #[test]
    fn try_from_invalid_driver_is_error() {
        let args = parse_args(&[
            "--driver",
            "foobar",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let err = LaunchConfiguration::try_from(args).unwrap_err();
        assert!(
            matches!(err, InvalidCmdArguments::InvalidDriver(ref d) if d == "foobar"),
            "expected InvalidDriver, got {err:?}"
        );
    }

    #[test]
    fn try_from_dpdk_with_kernel_port_is_error() {
        let args = parse_args(&[
            "--driver",
            "dpdk",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let err = LaunchConfiguration::try_from(args).unwrap_err();
        assert!(
            matches!(err, InvalidCmdArguments::UnsupportedByDriver(UnsupportedByDriver::Dpdk(_))),
            "expected UnsupportedByDriver::Dpdk, got {err:?}"
        );
    }

    #[test]
    fn try_from_dpdk_with_missing_port_is_error() {
        let args = parse_args(&["--driver", "dpdk", "--interface", "eth0"]);
        let err = LaunchConfiguration::try_from(args).unwrap_err();
        assert!(
            matches!(err, InvalidCmdArguments::MissingPortSpecifier(_)),
            "expected MissingPortSpecifier, got {err:?}"
        );
    }

    #[test]
    fn try_from_bmp_disabled_by_default() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert!(config.bmp.is_none());
    }

    #[test]
    fn try_from_bmp_enabled() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
            "--bmp-enable",
            "--bmp-address",
            "127.0.0.1:5555",
            "--bmp-interval",
            "2000",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        let bmp = config.bmp.unwrap();
        assert_eq!(bmp.address.port(), 5555);
        assert_eq!(bmp.interval, std::time::Duration::from_millis(2000));
    }

    #[test]
    fn try_from_tracing_show_flags() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
            "--show-tracing-tags",
            "--show-tracing-targets",
            "--tracing",
            "default=info,nat=debug",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert_eq!(config.tracing.show.tags, TracingDisplayOption::Show);
        assert_eq!(config.tracing.show.targets, TracingDisplayOption::Show);
        assert_eq!(
            config.tracing.config.as_deref(),
            Some("default=info,nat=debug")
        );
    }

    #[test]
    fn try_from_tracing_defaults_to_hide() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert_eq!(config.tracing.show.tags, TracingDisplayOption::Hide);
        assert_eq!(config.tracing.show.targets, TracingDisplayOption::Hide);
        assert!(config.tracing.config.is_none());
    }

    #[test]
    fn try_from_socket_path_defaults() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert_eq!(
            config.routing.control_plane_socket,
            crate::DEFAULT_DP_UX_PATH
        );
        assert_eq!(config.cli.cli_sock_path, crate::DEFAULT_DP_UX_PATH_CLI);
        assert_eq!(
            config.routing.frr_agent_socket,
            crate::DEFAULT_FRR_AGENT_PATH
        );
    }

    #[test]
    fn try_from_custom_socket_paths() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
            "--cpi-sock-path",
            "/tmp/cpi.sock",
            "--cli-sock-path",
            "/tmp/cli.sock",
            "--frr-agent-path",
            "/tmp/frr.sock",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert_eq!(config.routing.control_plane_socket, "/tmp/cpi.sock");
        assert_eq!(config.cli.cli_sock_path, "/tmp/cli.sock");
        assert_eq!(config.routing.frr_agent_socket, "/tmp/frr.sock");
    }

    #[test]
    fn try_from_gateway_name() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
            "--name",
            "my-gateway",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert_eq!(config.general.name.as_deref(), Some("my-gateway"));
    }

    #[test]
    fn try_from_no_name_is_none() {
        let args = parse_args(&[
            "--driver",
            "kernel",
            "--interface",
            "eth0=kernel@enp2s1",
        ]);
        let config = LaunchConfiguration::try_from(args).unwrap();
        assert!(config.general.name.is_none());
    }
}
