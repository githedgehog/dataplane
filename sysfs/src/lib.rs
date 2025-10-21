// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [sysfs] manipulation utilities.
//!
//! Basically, this is a module full of minor guard rails to discourage mistakes when manipulating system impacting
//! kernel functionality as a privileged process.
//!
//! [sysfs]: https://www.kernel.org/doc/Documentation/filesystems/sysfs.txt

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use tracing::{error, info};

/// Errors which might occur when accessing sysfs directories
#[derive(Debug, thiserror::Error)]
pub enum SysfsErr {
    /// The path is not under a mounted sysfs and therefore does not qualify as a [`SysfsPath`].
    #[error("path {0:?} is not under sysfs")]
    PathNotUnderSysfs(PathBuf),
    /// Some [`std::io::Error`] error occurred
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Invalid UTF-8 in a path under sysfs is an absolutely wild error case we expect to
    /// never see.
    ///
    /// The kernel just uses ascii byte strings for sysfs, so you should never see this
    /// error under healthy conditions.
    /// In the event of illegal UTF-8, something is likely deeply wrong with the kernel;
    /// likely memory corruption or some other security impacting issue.
    ///
    /// As such, the [`SysfsErr::SysfsPathIsNotValidUtf8`] branch deliberately does not include
    /// any information about the offending string name or any derivative, even for logging
    /// or error reporting.
    /// At best you will just end up mangling the log with unknown/unprintable bytes.
    /// At worst, injecting arbitrary bytes into a system log may be what an attacker needs
    /// for lateral compromise of some other system.
    ///
    /// You should likely `panic!` if you reach this error case as there is no plausible
    /// recovery from this type of low level operating system malfunction.
    #[error("path under sysfs is not a valid UTF-8 string")]
    SysfsPathIsNotValidUtf8,
}

/// We manipulate paths under sysfs, but, for the sake of safety, we also determine where sysfs is
/// actually mounted before we start messing with directories.
pub fn sysfs_root() -> &'static SysfsPath {
    static SYSFS: LazyLock<SysfsPath> = LazyLock::new(|| {
        let sysfs_mounts: Vec<_> = procfs::mounts()
            .unwrap() // acceptable panic: if we can't find /sys then this process will never work
            .into_iter()
            .filter(|mount| mount.fs_vfstype == "sysfs")
            .collect();
        let sysfs_path = if sysfs_mounts.is_empty() {
            panic!("sysfs is not mounted: unable to initialize dataplane");
        } else if sysfs_mounts.len() > 1 {
            const MSG_PREFIX: &str =
                "suspicious configuration found: sysfs is mounted at more than one location.";
            let message = format!("{MSG_PREFIX}. Filesystems found at {sysfs_mounts:#?}");
            error!("{message}");
            panic!("{message}");
        } else {
            sysfs_mounts[0].fs_file.clone()
        };
        #[allow(clippy::unwrap_used)] // failure to find here is completely fatal
        let sysfs_root = SysfsPath::new(&sysfs_path).unwrap();
        info!("found sysfs filesystem at {sysfs_root}");
        sysfs_root
    });
    &SYSFS
}

/// Path which is promised to
///
/// 1. exist under a mounted sysfs at the time of creation,
/// 2. be both absolute and canonical,
/// 3. be both safely and correctly represented as a valid UTF-8 string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SysfsPath(PathBuf);

impl SysfsPath {
    /// Create a new `SysfsPath` from a path.
    ///
    /// This function takes a path and returns a `SysfsPath` if the path is under sysfs.
    ///
    /// <div class="note">
    ///
    /// The path will be canonicalized prior to any other checks, so passing paths to symlinks here
    /// is completely fine (sysfs uses a lot of symlinks).
    /// </div>
    ///
    /// # Errors
    ///
    /// - If the canonicalized path is not under sysfs, an error is returned.
    /// - If the path is under sysfs but is (somehow) not a valid UTF-8 string, an error is returned.
    /// - io errors (such as permission denied) can also occur
    pub fn new(path: impl AsRef<Path>) -> Result<SysfsPath, SysfsErr> {
        let path = path.as_ref();
        if path.as_os_str().to_str().is_none() {
            return Err(SysfsErr::SysfsPathIsNotValidUtf8);
        }
        let path = std::fs::canonicalize(path)?;
        if path.as_os_str().to_str().is_none() {
            return Err(SysfsErr::SysfsPathIsNotValidUtf8);
        }
        match nix::sys::statfs::statfs(&path) {
            Ok(stats) => {
                if stats.filesystem_type() == nix::sys::statfs::SYSFS_MAGIC {
                    Ok(SysfsPath(path))
                } else {
                    Err(SysfsErr::PathNotUnderSysfs(path))
                }
            }
            Err(errno) => Err(SysfsErr::IoError(errno.into())),
        }
    }

    /// Get an immutable reference to the inner [`PathBuf`].
    pub fn inner(&self) -> &PathBuf {
        &self.0
    }

    /// Construct a path relative to this [`SysfsPath`]
    ///
    /// # Errors
    ///
    /// [`SysfsErr`] will occur if
    ///
    /// 1. the child path does not exist
    /// 2. the child path does not resolve to a path in sysfs (e.g. something is bind mounted under sysfs)
    /// 3. [`std::io::Error`] error occurs (e.g. permission denied)
    /// 4. a path is somehow not valid utf-8
    ///
    /// <div class="caution">
    ///
    /// - The returned path _will_ be a [`SysfsPath`], but it will not strictly exist under the starting point.
    ///
    ///   - the child may be a symlink which resolves somewhere else in the sysfs.
    ///   - the supplied path may contain some valid use of `".."` which walks above the starting directory.
    ///
    /// In all cases, the returned path will be canonicalized.
    /// </div>
    pub fn relative(&self, path: impl AsRef<Path>) -> Result<SysfsPath, SysfsErr> {
        let path = path.as_ref();
        let mut child_path = self.inner().clone();
        child_path.push(path);
        SysfsPath::new(child_path)
    }
}

impl AsRef<Path> for SysfsPath {
    fn as_ref(&self) -> &Path {
        self.inner()
    }
}

// this is safe because we have already validated the conversion to UTF-8 in the constructor
impl AsRef<str> for SysfsPath {
    fn as_ref(&self) -> &str {
        self.inner().assert_str()
    }
}

// this is safe because we have already validated the conversion to UTF-8 in the constructor
impl<'a> From<&'a SysfsPath> for &'a str {
    fn from(value: &'a SysfsPath) -> &'a str {
        value.inner().assert_str()
    }
}

// this is safe because we have already validated the conversion to UTF-8 in the constructor
impl std::fmt::Display for SysfsPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner().assert_str())
    }
}

/// Trait intended to insist that a value can be represented as valid UTF-8.
///
/// This trait is intended to be used in the situation where deviation from that expectation represents a
/// severe system error and crashing is the only reasonable response.
pub trait AssertAsStr {
    /// Insist that a value can be represented as valid UTF-8 and panic with a deliberately vague error message if not.
    ///
    /// # Panics
    ///
    /// If the conversion fails, all implementations are
    ///
    /// - **required** to panic or abort the process and,
    /// - are **forbidden** from logging the offending value or any value derived from the invalid value.
    fn assert_str(&self) -> &str;
}

/// We insist that path names are valid UTF-8 and immediately panic with a deliberately vague error message if not.
impl AssertAsStr for PathBuf {
    fn assert_str(&self) -> &str {
        match self.as_os_str().to_str() {
            Some(s) => s,
            None => panic!("PathBuf is not valid UTF-8 (this is suspicious)"),
        }
    }
}

/// Rationale for implementing [`AssertAsStr`] for [`std::path::Component`] is the same as for [`PathBuf`]
impl AssertAsStr for std::path::Component<'_> {
    fn assert_str(&self) -> &str {
        match self.as_os_str().to_str() {
            Some(s) => s,
            None => panic!("path component is not valid UTF-8 (this is suspicious)"),
        }
    }
}

/// File which is promised to be under a mounted sysfs,
pub struct SysfsFile(std::fs::File);

impl SysfsFile {
    /// Open a file under a mounted sysfs.
    ///
    /// # Errors
    ///
    /// - If the path leads out of the sysfs mount
    /// - On permissions errors or otherwise invalid file access
    pub fn open(path: impl AsRef<Path>, options: &std::fs::OpenOptions) -> Result<Self, SysfsErr> {
        let path = SysfsPath::new(path.as_ref())?;
        let file = options.open(path.inner()).map_err(SysfsErr::IoError)?;
        match nix::sys::statfs::fstatfs(file.as_fd()) {
            Ok(stat) => {
                if stat.filesystem_type() == nix::sys::statfs::SYSFS_MAGIC {
                    Ok(SysfsFile(file))
                } else {
                    Err(SysfsErr::PathNotUnderSysfs(path.inner().clone()))
                }
            }
            Err(e) => Err(SysfsErr::IoError(e.into())),
        }
    }
}

impl std::io::Read for SysfsFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for SysfsFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
