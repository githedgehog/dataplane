// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum PortArg {
    PCI(PciAddress),       // DPDK driver
    KERNEL(InterfaceName), // kernel driver
}

#[derive(Debug, Clone, serde::Serialize)]
#[allow(unused)]
pub struct InterfaceArg {
    pub interface: InterfaceName,
    pub port: Option<PortArg>,
}

impl FromStr for PortArg {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (disc, value) = input
            .split_once('@')
            .ok_or("Bad syntax: missing @".to_string())?;

        match disc {
            "pci" => {
                let pciaddr = PciAddress::try_from(value).map_err(|e| e.to_string())?;
                Ok(PortArg::PCI(pciaddr))
            }
            "kernel" => {
                let kernelif = InterfaceName::try_from(value)
                    .map_err(|e| format!("Bad kernel interface name: {e}"))?;
                Ok(PortArg::KERNEL(kernelif))
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
        match input.split_once('=') {
            Some((first, second)) => {
                let interface = InterfaceName::try_from(first)
                    .map_err(|e| format!("Bad interface name: {e}"))?;

                let port = PortArg::from_str(second)?;
                Ok(InterfaceArg {
                    interface,
                    port: Some(port),
                })
            }
            // this branch will go away
            None => {
                let interface = InterfaceName::try_from(input)
                    .map_err(|e| format!("Bad interface name: {e}"))?;
                Ok(InterfaceArg {
                    interface,
                    port: None,
                })
            }
        }
    }
}

use tracing::instrument;

use bytecheck::CheckBytes;
use nix::fcntl::{FcntlArg, FdFlag};
use nix::{fcntl::SealFlag, sys::memfd::MFdFlags};

pub const DEFAULT_DP_UX_PATH: &str = "/var/run/frr/hh/dataplane.sock";
pub const DEFAULT_DP_UX_PATH_CLI: &str = "/var/run/dataplane/cli.sock";
pub const DEFAULT_FRR_AGENT_PATH: &str = "/var/run/frr/frr-agent.sock";

/// A type wrapper around [`std::fs::File`] which is reserved to describe linux [memfd] files.
///
/// Our main use case for these files is passing ephemeral, launch-time configuration data to
/// the dataplane process from the dataplane-init process.
///
/// # Note
///
/// [`MemFile`] is intended for mutation.  Use the [`MemFile::finalize`] method to create a [`FinalizedMemFile`] to pass
/// to child processes.
///
/// [memfd]: https://man7.org/linux/man-pages/man2/memfd_create.2.html
#[derive(Debug)]
pub struct MemFile(std::fs::File);

/// A type wrapper around [`MemFile`] for memfd files which are emphatically NOT intended for any kind of data mutation
/// ever again.
///
/// Multiple protections are in place to deny all attempts to mutate the memory contents of these files.
/// These protections make this type of file suitable for as-safe-as-practical zero-copy deserialization of data
/// structure serialized by one process and given to a different process.
///
/// Protections include both basic linux DAC read only mode, as well as write, truncation, and extension sealing, as well
/// as sealing the seals in place to prevent their removal.
///
/// # Note
///
/// If these files contain secrets (or even if they don't), it is usually best to mark the file as close-on-exec to
/// further mitigate opportunities for the data to be corrupted / mutated.
/// This task, by its nature, can not be done by the parent process (or the child would not get the file descriptor).
///
/// As a consequence, this marking step should be taken as soon as the file is received by the child process.
/// The (unsafe) method [`FinalizedMemFile::from_fd`] takes this action automatically, and is the recommended way to
/// receive and read the file from child processes.
pub struct FinalizedMemFile(MemFile);

impl MemFile {
    /// Create a new, blank [`MemFile`].
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
    /// This method is intended for use only during early process initialization and make no attempt to recover from
    /// errors.
    ///
    /// This method will panic if
    ///
    /// 1. The file can not be modified to exclude write operations (basically chmod 400)
    /// 2. if the file can not be sealed against extension, truncation, mutation, and any attempt to remove the seals.
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
    Tcp(SocketAddr),
    UnixSocket(String),
}

/// Configuration for the driver used by the dataplane to process packets.
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
    Dpdk(DpdkDriverConfigSection),
    Kernel(KernelDriverConfigSection),
}

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
    Pci(hardware::pci::address::PciAddress),
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

pub type KiB = NonZero<u64>;

#[derive(
    Debug,
    Default,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub enum WorkerStackSize {
    #[default]
    Default,
    Size(KiB),
}

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
    pub use_nics: Vec<NetworkDeviceDescription>,
    pub eal_args: Vec<String>,
}

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
    pub interfaces: Vec<InterfaceName>,
}

/// Configuration for the command line interface of the dataplane
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
    pub cli_sock_path: String,
}

/// Configuration which defines how metrics are collected from the dataplane.
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
    pub show: TracingShowSection,
    pub config: Option<String>, // TODO: stronger typing on this config?
}

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
    #[default]
    Hide,
    Show,
}

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
    pub tags: TracingDisplayOption,
    pub targets: TracingDisplayOption,
}

/// Configuration which defines the interaction between the dataplane and the routing control plane.
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
    pub control_plane_socket: String,
    pub frr_agent_socket: String,
}

/// Configuration section for the parameters of the dynamic configuration server which supplies
/// updated configuration to the dataplane at runtime.
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

impl LaunchConfiguration {
    pub const STANDARD_INTEGRITY_CHECK_FD: RawFd = 30;
    pub const STANDARD_CONFIG_FD: RawFd = 40;

    /// Inherit a launch configuration from your parent process (assuming it correctly specified one).
    ///
    /// This method assumes that agreed upon file descriptor numbers are assigned by the parent.
    ///
    /// # Panics
    ///
    /// This method is intended for use at system startup and makes little attempt to recover from errors.
    /// This method will panic if the configuration is missing, invalid, or otherwise impossible to manipulate.
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

        {
            // VERY IMPORTANT: we must check for unaligned pointer here or risk undefined behavior.
            // There is absolutely no reason to keep this pointer alive past this scope.
            // Don't let it escape the scope (even if it is aligned).
            const EXPECTED_ALIGNMENT: usize = std::mem::align_of::<ArchivedLaunchConfiguration>();
            const {
                if !EXPECTED_ALIGNMENT.is_power_of_two() {
                    panic!("nonsense alignment computed for ArchivedLaunchConfiguration");
                }
            }
            let potentially_invalid_pointer =
                launch_config_memmap.as_ptr() as *const ArchivedLaunchConfiguration;
            if !potentially_invalid_pointer.is_aligned() {
                panic!(
                    "invalid alignment for ArchivedLaunchConfiguration found in inherited memfd"
                );
            }
        }

        if launch_config_memmap.as_ref().len() < size_of::<ArchivedLaunchConfiguration>() {
            panic!("invalid size for inherited memfd");
        }

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
        // seal the memfd
        memfd.finalize()
    }
}

/// Trait for data which may be "frozen" into a [`FinalizedMemFile`]
pub trait AsFinalizedMemFile {
    /// Consume self and convert it into a [`FinalizedMemFile`]
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
        if !readlink_result.starts_with("/memfd:") {
            panic!("supplied file descriptor is not a memfd: {readlink_result}");
        }
        let stat = nix::sys::stat::fstat(fd.as_fd())
            .into_diagnostic()
            .wrap_err("failed to stat memfd")
            .unwrap();
        if stat.st_mode != 0o100400 {
            panic!(
                "finalized memfd not in read only mode: given mode is {:o}",
                stat.st_mode
            );
        }
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
        if !seals.contains(expected_bits) {
            panic!(
                "missing seal bits on finalized memfd: bits set {seals:?}, bits expected: {expected_bits:?}"
            );
        }
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

    /// Validate this file using an [`IntegrityCheck`] serialized into the provided check_file
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
#[command(name = "Hedgehog Fabric Gateway dataplane")]
#[command(version = "1.0")] // FIXME
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

    /// Grafana Alloy (Pyroscope) server address for profiling uploads
    #[arg(
            long,
            value_name = "ALLOY_ADDR:PORT",
            default_value_t = SocketAddr::from(([127, 0, 0, 1], 4040)),
            help = "Address of Grafana Alloy/Pyroscope server (e.g. 127.0.0.1:4040)"
        )]
    alloy_address: SocketAddr,

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

    pub fn alloy_address(&self) -> SocketAddr {
        self.alloy_address
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
