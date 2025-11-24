// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Argument parsing and configuration management for the dataplane.
//!
//! This crate provides the infrastructure for safely passing configuration from the
//! `dataplane-init` process to the `dataplane` worker process using Linux memory file
//! descriptors (memfd). This approach enables zero-copy deserialization while maintaining
//! strong security guarantees through file sealing mechanisms.
//!
//! # Architecture
//!
//! The configuration flow follows this pattern:
//!
//! 1. **Parent Process (dataplane-init)**:
//!    - Parses command-line arguments using [`CmdArgs`]
//!    - Converts arguments into a [`LaunchConfiguration`]
//!    - Serializes the configuration using `rkyv` for zero-copy deserialization
//!    - Writes serialized data to a [`MemFile`] and finalizes it into a [`FinalizedMemFile`]
//!    - Computes an [`IntegrityCheck`] (SHA-384 hash) of the configuration
//!    - Passes both file descriptors to the child process at known FD numbers
//!
//! 2. **Child Process (dataplane)**:
//!    - Inherits the configuration via [`LaunchConfiguration::inherit()`]
//!    - Validates the integrity check matches the configuration
//!    - Memory-maps the sealed memfd for zero-copy access
//!    - Accesses the configuration through the rkyv archive format
//!
//! # Key Types
//!
//! - [`CmdArgs`]: Command-line argument parser using clap
//! - [`LaunchConfiguration`]: Complete dataplane configuration (driver, routing, metrics, etc.)
//! - [`MemFile`]: Mutable memfd wrapper for building configuration
//! - [`FinalizedMemFile`]: Immutable, sealed memfd for safe inter-process sharing
//! - [`IntegrityCheck`]: SHA-384-based validation for configuration integrity check
//!
//! # `FinalizedMemFile` Integrity
//!
//! [`FinalizedMemFile`] provides multiple layers of protection:
//!
//! - **Read-only mode**: File permissions are set to 0o400 (owner read-only)
//! - **Sealed against modification**: `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK` prevent changes
//! - **Sealed seals**: `F_SEAL_SEAL` prevents removing the seals
//! - **Integrity checking**: SHA-384 hash validates the configuration hasn't been tampered with or corrupted.
//! - (optional) **Close-on-exec**: we have the ability to mark `MemFd` as close-on-exec to prevent accidental leaking
//!   to subprocesses.
//!   This can't be done in the parent process, but should be done by the child process as soon as the file descriptor
//!   is identified.

#![deny(unsafe_code, clippy::pedantic)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub use clap::Parser;
use hardware::pci::address::InvalidPciAddress;
use hardware::pci::address::PciAddress;
use miette::{Context, IntoDiagnostic};
use net::interface::IllegalInterfaceName;
use net::interface::InterfaceName;
use sha2::Digest;
use std::borrow::Borrow;
use std::fmt::Display;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::num::NonZero;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(
    CheckBytes,
    Clone,
    Debug,
    Eq,
    PartialEq,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
#[allow(unused)]
pub struct InterfaceArg {
    pub interface: InterfaceName,
    pub port: NetworkDeviceDescription,
}

impl FromStr for NetworkDeviceDescription {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (disc, value) = input
            .split_once('@')
            .ok_or("Bad syntax: missing @".to_string())?;

        match disc {
            "pci" => {
                let pciaddr = PciAddress::try_from(value).map_err(|e| e.to_string())?;
                Ok(NetworkDeviceDescription::Pci(pciaddr))
            }
            "kernel" => {
                let kernelif = InterfaceName::try_from(value)
                    .map_err(|e| format!("Bad kernel interface name: {e}"))?;
                Ok(NetworkDeviceDescription::Kernel(kernelif))
            }
            _ => Err(format!(
                "Unknown discriminant '{disc}': allowed values are pci|kernel"
            )),
        }
    }
}

impl FromStr for InterfaceArg {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some((first, second)) = input.split_once('=') {
            let interface =
                InterfaceName::try_from(first).map_err(|e| format!("Bad interface name: {e}"))?;
            let port = NetworkDeviceDescription::from_str(second)?;
            Ok(InterfaceArg { interface, port })
        } else {
            Err(format!("invalid interface argument: {input}"))
        }
    }
}

use tracing::instrument;

use bytecheck::CheckBytes;
use nix::fcntl::{FcntlArg, FdFlag};
use nix::{fcntl::SealFlag, sys::memfd::MFdFlags};

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

/// A type wrapper around [`std::fs::File`] which is reserved to describe linux [memfd] files.
///
/// Memory file descriptors are anonymous, file-like objects that exist only in memory
/// and are not backed by any filesystem. They are particularly useful for passing
/// ephemeral configuration data between processes.
///
/// # Mutability
///
/// [`MemFile`] is intended for mutation during construction. Once you've written your
/// data, use [`MemFile::finalize`] to create a [`FinalizedMemFile`] which provides
/// strong immutability guarantees suitable for inter-process sharing.
///
/// [memfd]: https://man7.org/linux/man-pages/man2/memfd_create.2.html
#[derive(Debug)]
pub struct MemFile(std::fs::File);

/// An immutable, sealed memory file descriptor that cannot be modified.
///
/// Multiple protections are in place to deny all attempts to mutate the memory contents of these files.
/// These protections make this type of file suitable for as-safe-as-practical zero-copy deserialization of data
/// structure serialized by one process and given to a different process.
///
/// # Integrity Properties
///
/// Multiple protections are enforced to prevent any data mutation:
///
/// If these files contain secrets (or even if they don't), it is usually best to mark the file as close-on-exec to
/// further mitigate opportunities for the data to be corrupted / mutated.
/// This task, by its nature, can not be done by the parent process (or the child would not get the file descriptor).
/// As a consequence, this marking step should be taken as soon as the file is received by the child process.
/// The (unsafe) method [`FinalizedMemFile::from_fd`] takes this action automatically, and is the recommended way to
/// receive and read the file from child processes.
pub struct FinalizedMemFile(MemFile);

impl MemFile {
    /// Create a new, blank [`MemFile`].
    ///
    /// # Panics
    ///
    /// Panics if the operating system is unable to allocate an in-memory file descriptor.
    #[must_use]
    pub fn new() -> MemFile {
        let id: id::Id<MemFile> = id::Id::new();
        let descriptor =
            nix::sys::memfd::memfd_create(id.to_string().as_bytes(), MFdFlags::MFD_ALLOW_SEALING)
                .into_diagnostic()
                .wrap_err("failed to create memfd")
                .unwrap();
        MemFile(std::fs::File::from(descriptor))
    }

    /// Finalize and seal this [`MemFile`]
    ///
    /// # Note
    ///
    /// This method does its very best to protect the memory region against any future mutation.
    /// This sealing operation is not reversible.
    ///
    /// Although this operation consumes `self`, any memory maps to this file will become immutable or be invalidated
    /// immediately after this operation.
    /// You should make sure no memory maps to this file are open when this finalize operation is invoked.
    ///
    /// # Panics
    ///
    /// This method is intended for use only during early process initialization and makes no attempt to recover from
    /// errors.
    ///
    /// This method will panic if
    ///
    /// 1. The file can not be modified to exclude write operations (basically chmod 400)
    /// 2. if the file can not be sealed against extension, truncation, mutation, and any attempt to remove the seals.
    #[must_use]
    pub fn finalize(self) -> FinalizedMemFile {
        let mut this = self;
        // mark the file as read only
        nix::sys::stat::fchmod(&this, nix::sys::stat::Mode::S_IRUSR)
            .into_diagnostic()
            .wrap_err("failed to set dataplane configuration memfd to readonly mode")
            .unwrap();
        this.seal(
            SealFlag::F_SEAL_WRITE
                | SealFlag::F_SEAL_GROW
                | SealFlag::F_SEAL_SHRINK
                | SealFlag::F_SEAL_SEAL,
        );
        this.0
            .seek(SeekFrom::Start(0))
            .into_diagnostic()
            .wrap_err("unable to seek finalized file to start")
            .unwrap();
        FinalizedMemFile(this)
    }

    /// Seal the file with the provided seal flags.
    #[tracing::instrument(level = "info")]
    fn seal(&mut self, seals: SealFlag) {
        nix::fcntl::fcntl(self, FcntlArg::F_ADD_SEALS(seals))
            .into_diagnostic()
            .wrap_err(format!(
                "failed to add seals to mfd; attempted to add seals {seals:?}"
            ))
            .unwrap();
    }
}

impl Default for MemFile {
    fn default() -> Self {
        Self::new()
    }
}

impl AsFd for MemFile {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Borrow<std::fs::File> for MemFile {
    fn borrow(&self) -> &std::fs::File {
        &self.0
    }
}

impl AsRef<std::fs::File> for MemFile {
    fn as_ref(&self) -> &std::fs::File {
        &self.0
    }
}

impl AsMut<std::fs::File> for MemFile {
    fn as_mut(&mut self) -> &mut std::fs::File {
        &mut self.0
    }
}

impl From<MemFile> for std::fs::File {
    fn from(value: MemFile) -> Self {
        value.0
    }
}

impl AsRef<std::fs::File> for FinalizedMemFile {
    fn as_ref(&self) -> &std::fs::File {
        &self.0.0
    }
}

impl Read for FinalizedMemFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.0.read(buf)
    }
}

impl From<MemFile> for FinalizedMemFile {
    fn from(value: MemFile) -> Self {
        value.finalize()
    }
}

/// Enum to represent either a TCP socket address or a UNIX socket path
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub enum GrpcAddress {
    /// TCP socket address (IP address and port)
    Tcp(SocketAddr),
    /// Unix domain socket path
    UnixSocket(String),
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
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
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

/// Description of a network device by its bus address.
///
/// Currently supports PCI-addressed devices, which is the standard addressing
/// scheme for NICs in modern systems.
///
/// # Example
///
/// ```
/// use dataplane_args::NetworkDeviceDescription;
/// use hardware::pci::address::PciAddress;
///
/// // PCI device at bus 0000:01:00.0
/// let device = NetworkDeviceDescription::Pci(
///     PciAddress::try_from("0000:01:00.0").unwrap()
/// );
/// ```
#[derive(
    Debug,
    Ord,
    PartialEq,
    PartialOrd,
    Eq,
    Hash,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub enum NetworkDeviceDescription {
    /// The PCI address of the network device to be used
    Pci(hardware::pci::address::PciAddress),
    /// The kernel's name for net network interface
    Kernel(InterfaceName),
}

impl Display for NetworkDeviceDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkDeviceDescription::Pci(addr) => {
                write!(f, "pci@{addr}")
            }
            NetworkDeviceDescription::Kernel(name) => {
                write!(f, "kernel@{name}")
            }
        }
    }
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
    serde::Deserialize,
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
    serde::Deserialize,
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
    serde::Deserialize,
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
    serde::Deserialize,
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
    serde::Deserialize,
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
    serde::Deserialize,
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
    serde::Deserialize,
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
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
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
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct ConfigServerSection {
    /// gRPC server address (TCP or Unix socket)
    pub address: GrpcAddress,
}

/// The configuration of the dataplane.
///
/// This structure should be computed from the command line arguments supplied to the dataplane-init.
// TODO: implement bytecheck::Validate in addition to CheckBytes on all components of the launch config.
#[derive(
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    CheckBytes,
)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct LaunchConfiguration {
    pub config_server: ConfigServerSection,
    pub driver: DriverConfigSection,
    pub cli: CliConfigSection,
    pub routing: RoutingConfigSection,
    pub tracing: TracingConfigSection,
    pub metrics: MetricsConfigSection,
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
    /// The URL of the pryroscope url
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
        let integrity_check_file = unsafe { FinalizedMemFile::from_fd(integrity_check_fd) };
        let mut launch_configuration_file =
            unsafe { FinalizedMemFile::from_fd(launch_configuration_fd) };
        launch_configuration_file
            .validate(integrity_check_file)
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

        // we slightly abuse the access method here just to get byte level validation.
        // The actual objective here is to ensure all enums are valid and that all pointers point within the
        // archive.
        rkyv::access::<ArchivedLaunchConfiguration, rkyv::rancor::Failure>(
            launch_config_memmap.as_ref(),
        )
        .into_diagnostic()
        .wrap_err("failed to validate ArchivedLaunchConfiguration")
        .unwrap();

        // here we actually deserialize the data
        rkyv::from_bytes::<LaunchConfiguration, rkyv::rancor::Error>(launch_config_memmap.as_ref())
            .into_diagnostic()
            .wrap_err("failed to deserialize launch configuration")
            .unwrap()
    }
}

impl AsFinalizedMemFile for LaunchConfiguration {
    fn finalize(&self) -> FinalizedMemFile {
        let serialized_config = rkyv::to_bytes::<rkyv::rancor::Error>(self)
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

/// Trait for data that can be serialized into a sealed memory file descriptor.
///
/// Types implementing this trait can be converted into a [`FinalizedMemFile`],
/// which provides strong immutability guarantees suitable for inter-process
/// communication.
pub trait AsFinalizedMemFile {
    /// Serialize and seal this data into a [`FinalizedMemFile`].
    ///
    /// The returned file is immutable and suitable for zero-copy deserialization
    /// in other processes.
    fn finalize(&self) -> FinalizedMemFile;
}

impl FinalizedMemFile {
    /// Compute an integrity check of the contents of this file.
    ///
    /// # Panics
    ///
    /// Panics if the backing memfd file can not be `seek`ed to the start.
    pub fn integrity_check(&mut self) -> IntegrityCheck {
        self.0
            .0
            .seek(SeekFrom::Start(0))
            .into_diagnostic()
            .wrap_err("failed to seek to start of memfd when computing integrity check")
            .unwrap();
        IntegrityCheck::from_reader(&mut self.as_ref())
    }

    /// Consume the memfd and return an owned file descriptor.
    ///
    /// # Note
    ///
    /// This step is needed in order to hand the file descriptor to the child process.
    ///
    /// That said, it also obscures the fact that this file is a sealed memfd, which is potentially very confusing if
    /// given to any system not expecting those mechanics.
    ///
    /// You should generally only call this method as when you are about to hand the file to a child process which is
    /// expecting such a file descriptor.
    #[must_use]
    pub fn to_owned_fd(self) -> OwnedFd {
        OwnedFd::from(self.0.0)
    }

    /// Construct a [`FinalizedMemFile`] from a file descriptor
    ///
    /// # Safety
    ///
    /// This function _attempts_ to check that it has been given a real [`FinalizedMemFile`] (typically from another
    /// process).
    /// This check is on a best effort basis, and is not infallible.
    /// Additional checks (e.g., checksums or cryptographic signatures) should be used to ensure that this file contains
    /// the expected bits.
    /// That said, these checks are not and can't really be infallible.
    ///
    /// # Panics
    ///
    /// 1. panics if the provided file descriptor does not exist
    /// 2. panics if the name of the detected file is not valid unicode
    /// 3. panics if the provided file descriptor does not refer to a memfd file
    /// 4. panics if the provided file descriptor can not be `stat`ed.
    /// 5. panics if the provided memfd is not strictly read only
    /// 6. panics if the provided memfd is not sealed (against writes, truncation, extension, and seal modifications)
    /// 7. panics if the provided memfd can not be `seek`ed to the start of the file (very unlikely)
    /// 8. panics if the provided memfd can not be marked as close-on-exec (very unlikely)
    #[instrument(level = "debug", skip(fd))]
    #[allow(unsafe_code)] // external contract documented and checked as well as I can for now
    pub unsafe fn from_fd(fd: OwnedFd) -> FinalizedMemFile {
        // TODO: is procfs actually mounted at /proc?  Are we reading the correct file.  Annoying to fix this properly.
        let os_str =
            nix::fcntl::readlink(format!("/proc/self/fd/{fd}", fd = fd.as_raw_fd()).as_str())
                .into_diagnostic()
                .wrap_err("failed to read memfd link in /proc")
                .unwrap();
        let readlink_result = os_str
            .into_string()
            .map_err(|_| std::io::Error::other("file descriptor readlink returned invalid unicode"))
            .into_diagnostic()
            .unwrap();
        assert!(
            readlink_result.starts_with("/memfd:"),
            "supplied file descriptor is not a memfd: {readlink_result}"
        );
        let stat = nix::sys::stat::fstat(fd.as_fd())
            .into_diagnostic()
            .wrap_err("failed to stat memfd")
            .unwrap();
        const EXPECTED_PERMISSIONS: u32 = 0o10_400; // expect read only + sticky bit
        assert!(
            stat.st_mode == EXPECTED_PERMISSIONS,
            "finalized memfd not in read only mode: given mode is {:o}, expected {EXPECTED_PERMISSIONS:o}",
            stat.st_mode
        );

        let Some(seals) = SealFlag::from_bits(
            nix::fcntl::fcntl(fd.as_fd(), FcntlArg::F_GET_SEALS)
                .into_diagnostic()
                .wrap_err("failed to get seals on file descriptor")
                .unwrap(),
        ) else {
            panic!("seal bits on memfd are set but are unknown to the system");
        };
        let expected_bits: SealFlag = SealFlag::F_SEAL_GROW
            | SealFlag::F_SEAL_SHRINK
            | SealFlag::F_SEAL_WRITE
            | SealFlag::F_SEAL_SEAL;
        assert!(
            seals.contains(expected_bits),
            "missing seal bits on finalized memfd: bits set {seals:?}, bits expected: {expected_bits:?}"
        );
        let mut file = std::fs::File::from(fd);
        file.seek(SeekFrom::Start(0))
            .into_diagnostic()
            .wrap_err("failed to seek to start of memfd")
            .unwrap();
        // mark file close on exec so we are less likely to accidentally leak it
        nix::fcntl::fcntl(file.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .into_diagnostic()
            .wrap_err("unable to mark memfd as close-on-exec")
            .unwrap();
        FinalizedMemFile(MemFile(file))
    }

    /// Validate this file using an [`IntegrityCheck`] serialized into the provided `check_file`
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// 1. unable to read the integrity check file
    /// 2. invalid file (checksum mismatch)
    pub fn validate(&mut self, check_file: FinalizedMemFile) -> Result<(), miette::Report> {
        let mut check_file = check_file;
        check_file
            .0
            .0
            .seek(SeekFrom::Start(0))
            .into_diagnostic()
            .wrap_err("failed to seek to start of check_file")?;
        let mut given_bytes: IntegrityCheckBytes = [0; _];
        check_file
            .as_ref()
            .read_exact(&mut given_bytes)
            .into_diagnostic()
            .wrap_err("unable to read check file")?;
        let given = IntegrityCheck::deserialize(given_bytes);
        let calculated = self.integrity_check();
        if given == calculated {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid checksum",
            ))
            .into_diagnostic()
        }
    }
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum IntegrityCheckError {
    #[error(
        "wrong check file length for hash type; received {0} bytes, expected {SHA384_BYTE_LEN} bytes"
    )]
    WrongCheckFileLength(u64),
}

const SHA384_BYTE_LEN: usize = 384 / 8;
const INTEGRITY_CHECK_BYTE_LEN: usize = SHA384_BYTE_LEN;

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
struct Sha384Bytes([u8; SHA384_BYTE_LEN]);

/// An integrity check for a file.
///
/// Currently implemented as SHA384, but without any contractual requirement to continue using that hash in the future.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct IntegrityCheck {
    sha384: Sha384Bytes,
}

/// A byte array which may hold an [`IntegrityCheck`]
pub type IntegrityCheckBytes = [u8; INTEGRITY_CHECK_BYTE_LEN];

impl IntegrityCheck {
    /// Serialize this integrity check into bytes
    fn serialize(&self) -> IntegrityCheckBytes {
        let mut output: IntegrityCheckBytes = [0; _];
        output.copy_from_slice(&self.sha384.0);
        output
    }

    /// Deserialize this integrity check as bytes
    fn deserialize(input: IntegrityCheckBytes) -> IntegrityCheck {
        IntegrityCheck {
            sha384: Sha384Bytes(input),
        }
    }

    /// Hash a file / reader.
    ///
    /// # Note:
    ///
    /// If providing this method with a file, make sure that the file has been `seek`ed to the start or you will
    /// end up only hashing from the seek position to the end of the file.
    fn from_reader(r: &mut impl Read) -> Self {
        const CHUNK_SIZE: usize = 128;
        let mut hasher = sha2::Sha384::new();
        loop {
            let mut chunk = [0_u8; CHUNK_SIZE];
            let amount = r
                .read(&mut chunk)
                .into_diagnostic()
                .wrap_err("failed to read integrity check")
                .unwrap();
            hasher.update(&chunk[..amount]);
            if amount == 0 {
                break;
            }
        }
        let mut hash = [0; INTEGRITY_CHECK_BYTE_LEN];
        hash.copy_from_slice(&hasher.finalize()[..]);
        let sha384 = Sha384Bytes(hash);
        IntegrityCheck { sha384 }
    }
}

impl AsFinalizedMemFile for IntegrityCheck {
    #[tracing::instrument(level = "info")]
    fn finalize(&self) -> FinalizedMemFile {
        let bytes = self.serialize();
        let mut memfd = MemFile::new();
        memfd
            .as_mut()
            .set_len(bytes.len() as u64)
            .into_diagnostic()
            .wrap_err("failed to set length of integrity check memfd")
            .unwrap();
        memfd
            .as_mut()
            .write_all(bytes.as_slice())
            .into_diagnostic()
            .wrap_err("failed to write integrity check to memfd")
            .unwrap();
        memfd.finalize()
    }
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum InvalidCmdArguments {
    #[error("Illegal grpc address: {0}")]
    InvalidGrpcAddress(String), // TODO: this should have a stronger error type
    #[error(transparent)]
    InvalidPciAddress(#[from] InvalidPciAddress),
    #[error(transparent)]
    InvalidInterfaceName(#[from] IllegalInterfaceName),
    #[error("\"{0}\" is not a valid driver.  Must be dpdk or kernel")]
    InvalidDriver(String),
    #[error("Must specify driver as dpdk or  kernel")]
    NoDriverSpecified,
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
        let use_nics: Vec<_> = value
            .interfaces()
            .map(|x| match x.port {
                Some(PortArg::KERNEL(name)) => NetworkDeviceDescription::Kernel(name),
                Some(PortArg::PCI(address)) => NetworkDeviceDescription::Pci(address),
                None => todo!(), // I am not clear what this case means
            })
            .collect();
        Ok(LaunchConfiguration {
            config_server: ConfigServerSection {
                address: value
                    .grpc_address()
                    .map_err(InvalidCmdArguments::InvalidGrpcAddress)?,
            },
            driver: match &value.driver {
                Some(driver) if driver == "dpdk" => {
                    // TODO: adjust command line to specify lcore usage more flexibly in next PR
                    let eal_args = use_nics
                        .iter()
                        .map(|nic| match nic {
                            NetworkDeviceDescription::Pci(pci_address) => {
                                Ok(["--allow".to_string(), format!("{pci_address}")])
                            }
                            NetworkDeviceDescription::Kernel(interface_name) => {
                                Err(InvalidCmdArguments::UnsupportedByDriver(
                                    UnsupportedByDriver::Dpdk(interface_name.clone()),
                                ))
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten()
                        .collect();
                    DriverConfigSection::Dpdk(DpdkDriverConfigSection { use_nics, eal_args })
                }
                Some(driver) if driver == "kernel" => {
                    DriverConfigSection::Kernel(KernelDriverConfigSection {
                        interfaces: use_nics
                            .iter()
                            .map(|nic| match nic {
                                NetworkDeviceDescription::Pci(address) => {
                                    Err(InvalidCmdArguments::UnsupportedByDriver(
                                        UnsupportedByDriver::Kernel(*address),
                                    ))
                                }
                                NetworkDeviceDescription::Kernel(interface) => {
                                    Ok(interface.clone())
                                }
                            })
                            .collect::<Result<_, _>>()?,
                    })
                }
                Some(other) => Err(InvalidCmdArguments::InvalidDriver(other.clone()))?,
                None => Err(InvalidCmdArguments::NoDriverSpecified)?,
            },
            cli: CliConfigSection {
                cli_sock_path: value.cli_sock_path(),
            },
            routing: RoutingConfigSection {
                control_plane_socket: value.cpi_sock_path(),
                frr_agent_socket: value.frr_agent_path(),
            },
            tracing: TracingConfigSection {
                show: TracingShowSection {
                    tags: match value.show_tracing_tags() {
                        true => TracingDisplayOption::Show,
                        false => TracingDisplayOption::Hide,
                    },
                    targets: match value.show_tracing_targets() {
                        true => TracingDisplayOption::Show,
                        false => TracingDisplayOption::Hide,
                    },
                },
                config: value.tracing.clone(),
            },
            metrics: MetricsConfigSection {
                address: value.metrics_address(),
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

    /// gRPC server address (IP:PORT for TCP or path for UNIX socket)
    #[arg(
        long,
        value_name = "ADDRESS",
        default_value = "[::1]:50051",
        help = "IP Address and port or UNIX socket path to listen for management connections"
    )]
    grpc_address: String,

    /// Treat grpc-address as a UNIX socket path
    #[arg(long, help = "Use a unix socket to listen for management connections")]
    grpc_unix_socket: bool,

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
}

impl CmdArgs {
    pub fn driver_name(&self) -> &str {
        match &self.driver {
            None => "dpdk",
            Some(name) => name,
        }
    }

    pub fn show_tracing_tags(&self) -> bool {
        self.show_tracing_tags
    }
    pub fn show_tracing_targets(&self) -> bool {
        self.show_tracing_targets
    }
    pub fn tracing_config_generate(&self) -> bool {
        self.tracing_config_generate
    }
    pub fn tracing(&self) -> Option<&String> {
        self.tracing.as_ref()
    }

    pub fn kernel_num_workers(&self) -> usize {
        self.num_workers.into()
    }
    // backwards-compatible, to deprecate
    pub fn kernel_interfaces(&self) -> Vec<String> {
        self.interface
            .iter()
            .map(|spec| spec.interface.to_string())
            .collect()
    }

    // interface getter. This should be used by all drivers
    pub fn interfaces(&self) -> impl Iterator<Item = InterfaceArg> {
        self.interface.iter().cloned()
    }

    /// Get the gRPC server address configuration
    pub fn grpc_address(&self) -> Result<GrpcAddress, String> {
        // If UNIX socket flag is set, treat the address as a UNIX socket path
        if self.grpc_unix_socket {
            // Validate that the address is a valid UNIX socket path
            let grpc_path = PathBuf::from(&self.grpc_address);
            if !grpc_path.is_absolute() {
                return Err(format!(
                    "Invalid configuration: --grpc-unix-socket flag is set, but --grpc-address '{}' is not a valid absolute UNIX socket path",
                    self.grpc_address
                ));
            }
            return Ok(GrpcAddress::UnixSocket(self.grpc_address.clone()));
        }

        // Otherwise, parse as a TCP socket address
        match self.grpc_address.parse::<SocketAddr>() {
            Ok(addr) => Ok(GrpcAddress::Tcp(addr)),
            Err(e) => Err(format!(
                "Invalid gRPC TCP address '{}': {e}",
                self.grpc_address
            )),
        }
    }

    pub fn cpi_sock_path(&self) -> String {
        self.cpi_sock_path.clone()
    }

    pub fn cli_sock_path(&self) -> String {
        self.cli_sock_path.clone()
    }

    pub fn frr_agent_path(&self) -> String {
        self.frr_agent_path.clone()
    }

    /// Get the metrics bind address, returns None if metrics are disabled
    pub fn metrics_address(&self) -> SocketAddr {
        self.metrics_address
    }

    pub fn pyroscope_url(&self) -> Option<&url::Url> {
        self.pyroscope_url.as_ref()
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

    use crate::{InterfaceArg, PortArg};
    use std::str::FromStr;

    #[test]
    fn test_parse_interface() {
        // interface + port as PCI address
        let spec = InterfaceArg::from_str("GbEth1.9000=pci@0000:02:01.7").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");
        assert_eq!(
            spec.port,
            Some(PortArg::PCI(PciAddress::new(
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
            Some(PortArg::KERNEL(
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
}
