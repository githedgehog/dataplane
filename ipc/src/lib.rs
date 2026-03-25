// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Inter-process communication primitives for the dataplane.
//!
//! This crate provides secure IPC building blocks, starting with abstractions
//! over Linux [memfd] file descriptors with strong immutability guarantees
//! enforced by kernel-level file sealing.
//! These primitives are suitable for zero-copy deserialization of data
//! serialized by one process and consumed by another.
//!
//! # Key Types
//!
//! - [`MemFile`]: Mutable memfd wrapper for writing data during construction.
//! - [`FinalizedMemFile`]: Immutable, sealed memfd that cannot be modified.
//! - [`AsFinalizedMemFile`]: Trait for types that can serialize themselves into a sealed memfd.
//! - [`IntegrityCheck`]: SHA-384 hash for validating file contents across process boundaries.
//!
//! # Typical Workflow
//!
//! 1. Create a [`MemFile`] and write serialized data into it.
//! 2. Call [`MemFile::finalize`] to seal the file, producing a [`FinalizedMemFile`].
//! 3. Compute an [`IntegrityCheck`] over the finalized file.
//! 4. Pass both file descriptors to a child process.
//! 5. In the child, reconstruct via [`FinalizedMemFile::from_fd`] and validate
//!    with [`FinalizedMemFile::validate`].
//!
//! # Security Properties
//!
//! [`FinalizedMemFile`] provides multiple layers of protection:
//!
//! - **Read-only mode**: File permissions are set to 0o400 (owner read-only).
//! - **Sealed against modification**: `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK` prevent changes.
//! - **Sealed seals**: `F_SEAL_SEAL` prevents removing the other seals.
//! - **Integrity checking**: SHA-384 hash validates contents haven't been tampered with or corrupted.
//! - **Close-on-exec** (optional): prevents accidental leaking to subprocesses.
//!   The child process should mark the fd as close-on-exec as soon as it is received.
//!   [`FinalizedMemFile::from_fd`] does this automatically.
//!
//! [memfd]: https://man7.org/linux/man-pages/man2/memfd_create.2.html

#![deny(unsafe_code, clippy::pedantic)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use miette::{Context, IntoDiagnostic};
use nix::fcntl::{FcntlArg, FdFlag, SealFlag};
use nix::sys::memfd::MFdFlags;
use sha2::Digest;
use std::borrow::Borrow;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use tracing::instrument;

// ---------------------------------------------------------------------------
// MemFile
// ---------------------------------------------------------------------------

/// A type wrapper around [`std::fs::File`] which is reserved to describe linux [memfd] files.
///
/// Memory file descriptors are anonymous, file-like objects that exist only in memory
/// and are not backed by any filesystem.
/// They are particularly useful for passing ephemeral configuration data between processes.
///
/// # Mutability
///
/// [`MemFile`] is intended for mutation during construction.
/// Once you've written your data, use [`MemFile::finalize`] to create a [`FinalizedMemFile`]
/// which provides strong immutability guarantees suitable for inter-process sharing.
///
/// [memfd]: https://man7.org/linux/man-pages/man2/memfd_create.2.html
#[derive(Debug)]
pub struct MemFile(std::fs::File);

/// An immutable, sealed memory file descriptor that cannot be modified.
///
/// Multiple protections are in place to deny all attempts to mutate the memory
/// contents of these files.
/// These protections make this type of file suitable for as-safe-as-practical
/// zero-copy deserialization of data serialized by one process and given to a
/// different process.
///
/// # Integrity Properties
///
/// Multiple protections are enforced to prevent any data mutation.
///
/// If these files contain secrets (or even if they don't), it is usually best to
/// mark the file as close-on-exec to further mitigate opportunities for the data
/// to be corrupted / mutated.
/// This task, by its nature, can not be done by the parent process (or the child
/// would not get the file descriptor).
/// As a consequence, this marking step should be taken as soon as the file is
/// received by the child process.
/// The (unsafe) method [`FinalizedMemFile::from_fd`] takes this action
/// automatically, and is the recommended way to receive and read the file from
/// child processes.
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

    /// Finalize and seal this [`MemFile`].
    ///
    /// # Note
    ///
    /// This method does its very best to protect the memory region against any
    /// future mutation.
    /// This sealing operation is not reversible.
    ///
    /// Although this operation consumes `self`, any memory maps to this file will
    /// become immutable or be invalidated immediately after this operation.
    /// You should make sure no memory maps to this file are open when this
    /// finalize operation is invoked.
    ///
    /// # Panics
    ///
    /// This method is intended for use only during early process initialization
    /// and makes no attempt to recover from errors.
    ///
    /// This method will panic if
    ///
    /// 1. The file can not be modified to exclude write operations (basically chmod 400).
    /// 2. The file can not be sealed against extension, truncation, mutation, and
    ///    any attempt to remove the seals.
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
        &self.0 .0
    }
}

impl Read for FinalizedMemFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0 .0.read(buf)
    }
}

impl From<MemFile> for FinalizedMemFile {
    fn from(value: MemFile) -> Self {
        value.finalize()
    }
}

// ---------------------------------------------------------------------------
// FinalizedMemFile methods
// ---------------------------------------------------------------------------

impl FinalizedMemFile {
    /// Compute an integrity check of the contents of this file.
    ///
    /// # Panics
    ///
    /// Panics if the backing memfd file can not be `seek`ed to the start.
    pub fn integrity_check(&mut self) -> IntegrityCheck {
        let file = &mut self.0 .0;
        file.seek(SeekFrom::Start(0))
            .into_diagnostic()
            .wrap_err("failed to seek to start of memfd when computing integrity check")
            .unwrap();
        IntegrityCheck::from_reader(file)
    }

    /// Consume the memfd and return an owned file descriptor.
    ///
    /// # Note
    ///
    /// This step is needed in order to hand the file descriptor to the child
    /// process.
    ///
    /// That said, it also obscures the fact that this file is a sealed memfd,
    /// which is potentially very confusing if given to any system not expecting
    /// those mechanics.
    ///
    /// You should generally only call this method when you are about to hand the
    /// file to a child process which is expecting such a file descriptor.
    #[must_use]
    pub fn to_owned_fd(self) -> OwnedFd {
        OwnedFd::from(self.0 .0)
    }

    /// Construct a [`FinalizedMemFile`] from a file descriptor.
    ///
    /// # Safety
    ///
    /// This function _attempts_ to check that it has been given a real
    /// [`FinalizedMemFile`] (typically from another process).
    /// This check is on a best effort basis, and is not infallible.
    /// Additional checks (e.g., checksums or cryptographic signatures) should be
    /// used to ensure that this file contains the expected bits.
    /// That said, these checks are not and can't really be infallible.
    ///
    /// # Panics
    ///
    /// 1. Panics if the provided file descriptor does not exist.
    /// 2. Panics if the name of the detected file is not valid unicode.
    /// 3. Panics if the provided file descriptor does not refer to a memfd file.
    /// 4. Panics if the provided file descriptor can not be `stat`ed.
    /// 5. Panics if the provided memfd is not strictly read only.
    /// 6. Panics if the provided memfd is not sealed (against writes, truncation,
    ///    extension, and seal modifications).
    /// 7. Panics if the provided memfd can not be `seek`ed to the start of the
    ///    file (very unlikely).
    /// 8. Panics if the provided memfd can not be marked as close-on-exec (very
    ///    unlikely).
    #[instrument(level = "debug", skip(fd))]
    #[allow(unsafe_code)] // external contract documented and checked as well as I can for now
    pub unsafe fn from_fd(fd: OwnedFd) -> FinalizedMemFile {
        Self::verify_is_memfd(&fd);
        Self::verify_readonly(&fd);
        Self::verify_sealed(&fd);
        let mut file = std::fs::File::from(fd);
        file.seek(SeekFrom::Start(0))
            .into_diagnostic()
            .wrap_err("failed to seek to start of memfd")
            .unwrap();
        Self::mark_cloexec(&file);
        FinalizedMemFile(MemFile(file))
    }

    /// Verify that `fd` refers to a memfd by reading its `/proc/self/fd` symlink.
    ///
    /// # Panics
    ///
    /// 1. Panics if the symlink for the file descriptor cannot be read.
    /// 2. Panics if the symlink target is not valid unicode.
    /// 3. Panics if the symlink target does not start with `/memfd:`.
    fn verify_is_memfd(fd: &OwnedFd) {
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
    }

    /// Verify that `fd` is a regular file with owner-read-only permissions
    /// (mode `0o100400`).
    ///
    /// # Panics
    ///
    /// 1. Panics if the file descriptor cannot be `stat`ed.
    /// 2. Panics if the file mode does not match the expected permissions.
    fn verify_readonly(fd: &OwnedFd) {
        let stat = nix::sys::stat::fstat(fd.as_fd())
            .into_diagnostic()
            .wrap_err("failed to stat memfd")
            .unwrap();
        const EXPECTED_PERMISSIONS: u32 = nix::libc::S_IFREG | nix::libc::S_IRUSR;
        assert!(
            stat.st_mode == EXPECTED_PERMISSIONS,
            "finalized memfd not in read only mode: given mode is {:o}, expected {EXPECTED_PERMISSIONS:o}",
            stat.st_mode
        );
    }

    /// Verify that `fd` carries the full set of seals expected on a finalized
    /// memfd (`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`).
    ///
    /// # Panics
    ///
    /// 1. Panics if the seal flags cannot be read from the file descriptor.
    /// 2. Panics if the seal bits are not recognized by the system.
    /// 3. Panics if any expected seal bit is missing.
    fn verify_sealed(fd: &OwnedFd) {
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
    }

    /// Mark a file as close-on-exec to prevent accidental leaking to
    /// subprocesses.
    ///
    /// # Panics
    ///
    /// Panics if the `FD_CLOEXEC` flag cannot be set.
    fn mark_cloexec(file: &std::fs::File) {
        nix::fcntl::fcntl(file.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .into_diagnostic()
            .wrap_err("unable to mark memfd as close-on-exec")
            .unwrap();
    }

    /// Validate this file using an [`IntegrityCheck`] serialized into the
    /// provided `check_file`.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// 1. Unable to read the integrity check file.
    /// 2. Invalid file (checksum mismatch).
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

// ---------------------------------------------------------------------------
// AsFinalizedMemFile trait
// ---------------------------------------------------------------------------

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
    fn finalize(self) -> FinalizedMemFile;
}

// ---------------------------------------------------------------------------
// IntegrityCheck
// ---------------------------------------------------------------------------

/// Size of SHA-384 hash in bytes (384 bits / 8 = 48 bytes).
const SHA384_BYTE_LEN: usize = 384 / 8;

/// Current size of integrity check in bytes (currently SHA-384).
pub const INTEGRITY_CHECK_BYTE_LEN: usize = SHA384_BYTE_LEN;

/// Internal representation of SHA-384 hash bytes.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
struct Sha384Bytes([u8; SHA384_BYTE_LEN]);

/// Cryptographic integrity check for validating file contents.
///
/// Currently implemented using SHA-384, providing a cryptographically secure hash
/// that can detect any tampering or corruption of the file contents.
/// The hash implementation may change in future versions without API changes.
///
/// # Use Cases
///
/// - Validating configuration files passed between processes.
/// - Detecting corruption in sealed memory file descriptors.
/// - Ensuring data integrity during process handoff.
///
/// # Security Properties
///
/// SHA-384 is a member of the SHA-2 family and provides:
///
/// - 384-bit (48-byte) hash output.
/// - Cryptographic collision resistance.
/// - Pre-image resistance (cannot reverse the hash to find the original data).
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct IntegrityCheck {
    sha384: Sha384Bytes,
}

/// Byte array representation of an [`IntegrityCheck`].
///
/// This type can hold the serialized form of an integrity check (currently 48
/// bytes for SHA-384).
pub type IntegrityCheckBytes = [u8; INTEGRITY_CHECK_BYTE_LEN];

impl IntegrityCheck {
    /// Serialize this integrity check into bytes.
    fn serialize(&self) -> IntegrityCheckBytes {
        let mut output: IntegrityCheckBytes = [0; _];
        output.copy_from_slice(&self.sha384.0);
        output
    }

    /// Deserialize this integrity check from bytes.
    fn deserialize(input: IntegrityCheckBytes) -> IntegrityCheck {
        IntegrityCheck {
            sha384: Sha384Bytes(input),
        }
    }

    /// Hash a file / reader.
    ///
    /// # Note
    ///
    /// If providing this method with a file, make sure that the file has been
    /// `seek`ed to the start or you will end up only hashing from the seek
    /// position to the end of the file.
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
    fn finalize(self) -> FinalizedMemFile {
        let bytes = self.serialize();
        let mut memfd = MemFile::new();
        memfd
            .as_mut()
            .write_all(bytes.as_slice())
            .into_diagnostic()
            .wrap_err("failed to write integrity check to memfd")
            .unwrap();
        memfd.finalize()
    }
}