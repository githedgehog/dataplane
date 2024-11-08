// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Standard errno values, meanings, and lookups
//!
//! This code is tedious but quite safe.
//!
//! It is also perfectly happy to work in `no_std` environments, which other `errno` oriented crates
//! do not seem to.

#![cfg_attr(not(test), no_std)]
#![deny(clippy::all, clippy::pedantic, clippy::panic)]
#![forbid(unsafe_code, missing_docs)]
#![forbid(clippy::unwrap_used, clippy::expect_used, clippy::missing_errors_doc)]

/// No error, operation succeeded
pub const SUCCESS: i32 = 0;
///  Not super-user
pub const EPERM: i32 = 1;
///  No such file or directory
pub const ENOENT: i32 = 2;
///  No such process
pub const ESRCH: i32 = 3;
///  Interrupted system call
pub const EINTR: i32 = 4;
///  I/O error
pub const EIO: i32 = 5;
///  No such device or address
pub const ENXIO: i32 = 6;
///  Arg list too long
pub const E2BIG: i32 = 7;
///  Exec format error
pub const ENOEXEC: i32 = 8;
///  Bad file number
pub const EBADF: i32 = 9;
/// No children
pub const ECHILD: i32 = 10;
/// No more processes
pub const EAGAIN: i32 = 11;
/// Not enough memory
pub const ENOMEM: i32 = 12;
/// Permission denied
pub const EACCES: i32 = 13;
/// Bad address
pub const EFAULT: i32 = 14;
/// Block device required
pub const ENOTBLK: i32 = 15;
/// Mount device busy
pub const EBUSY: i32 = 16;
/// File exists
pub const EEXIST: i32 = 17;
/// Cross-device link
pub const EXDEV: i32 = 18;
/// No such device
pub const ENODEV: i32 = 19;
/// Not a directory
pub const ENOTDIR: i32 = 20;
/// Is a directory
pub const EISDIR: i32 = 21;
/// Invalid argument
pub const EINVAL: i32 = 22;
/// Too many open files in the system
pub const ENFILE: i32 = 23;
/// Too many open files
pub const EMFILE: i32 = 24;
/// Not a typewriter
pub const ENOTTY: i32 = 25;
/// Text file busy
pub const ETXTBSY: i32 = 26;
/// File too large
pub const EFBIG: i32 = 27;
/// No space left on a device
pub const ENOSPC: i32 = 28;
/// Illegal seek
pub const ESPIPE: i32 = 29;
/// Read-only file system
pub const EROFS: i32 = 30;
/// Too many links
pub const EMLINK: i32 = 31;
/// Broken pipe
pub const EPIPE: i32 = 32;
/// Math arg out of the domain of func
pub const EDOM: i32 = 33;
/// Math result not representable
pub const ERANGE: i32 = 34;
/// No message of desired type
pub const ENOMSG: i32 = 35;
/// Identifier removed
pub const EIDRM: i32 = 36;
/// Channel number out of range
pub const ECHRNG: i32 = 37;
/// Level 2 not synchronized
pub const EL2NSYNC: i32 = 38;
/// Level 3 halted
pub const EL3HLT: i32 = 39;
/// Level 3 reset
pub const EL3RST: i32 = 40;
/// Link number out of range
pub const ELNRNG: i32 = 41;
/// Protocol driver not attached
pub const EUNATCH: i32 = 42;
/// No CSI structure available
pub const ENOCSI: i32 = 43;
/// Level 2 halted
pub const EL2HLT: i32 = 44;
/// Deadlock condition
pub const EDEADLK: i32 = 45;
/// No record locks available
pub const ENOLCK: i32 = 46;
/// Invalid exchange
pub const EBADE: i32 = 50;
/// Invalid request descriptor
pub const EBADR: i32 = 51;
/// Exchange full
pub const EXFULL: i32 = 52;
/// No anode
pub const ENOANO: i32 = 53;
/// Invalid request code
pub const EBADRQC: i32 = 54;
/// Invalid slot
pub const EBADSLT: i32 = 55;
/// File locking deadlock error
pub const EDEADLOCK: i32 = 56;
/// Bad font file fmt
pub const EBFONT: i32 = 57;
/// Device not a stream
pub const ENOSTR: i32 = 60;
/// No data (for no delay io)
pub const ENODATA: i32 = 61;
/// Timer expired
pub const ETIME: i32 = 62;
/// Out of streams resources
pub const ENOSR: i32 = 63;
/// Machine is not on the network
pub const ENONET: i32 = 64;
/// Package not installed
pub const ENOPKG: i32 = 65;
/// The object is remote
pub const EREMOTE: i32 = 66;
/// The link has been severed
pub const ENOLINK: i32 = 67;
/// Advertise error
pub const EADV: i32 = 68;
/// Srmount error
pub const ESRMNT: i32 = 69;
/// Communication error on send
pub const ECOMM: i32 = 70;
/// Protocol error
pub const EPROTO: i32 = 71;
/// Multihop attempted
pub const EMULTIHOP: i32 = 74;
/// Inode is remote (not really error)
pub const ELBIN: i32 = 75;
/// Cross-mount point (not really error)
pub const EDOTDOT: i32 = 76;
/// Trying to read an unreadable message
pub const EBADMSG: i32 = 77;
/// Inappropriate file type or format
pub const EFTYPE: i32 = 79;
/// Given log name not unique
pub const ENOTUNIQ: i32 = 80;
/// f.d. invalid for this operation
pub const EBADFD: i32 = 81;
/// Remote address changed
pub const EREMCHG: i32 = 82;
/// Can't access a necessary shared lib
pub const ELIBACC: i32 = 83;
/// Accessing a corrupted shared lib
pub const ELIBBAD: i32 = 84;
/// .lib section in a.out corrupted
pub const ELIBSCN: i32 = 85;
/// Attempting to link in too many libs
pub const ELIBMAX: i32 = 86;
/// Attempting to exec a shared library
pub const ELIBEXEC: i32 = 87;
/// Function is not implemented
pub const ENOSYS: i32 = 88;
/// No more files
pub const ENMFILE: i32 = 89;
/// Directory is not empty
pub const ENOTEMPTY: i32 = 90;
/// File or path name too long
pub const ENAMETOOLONG: i32 = 91;
/// Too many symbolic links
pub const ELOOP: i32 = 92;
/// Operation not supported on transport endpoint
pub const EOPNOTSUPP: i32 = 95;
/// Protocol family is not supported
pub const EPFNOSUPPORT: i32 = 96;
/// Connection reset by peer
pub const ECONNRESET: i32 = 104;
/// No buffer space available
pub const ENOBUFS: i32 = 105;
/// Address family is not supported by protocol family
pub const EAFNOSUPPORT: i32 = 106;
/// Protocol wrong type for socket
pub const EPROTOTYPE: i32 = 107;
/// Socket operation on non-socket
pub const ENOTSOCK: i32 = 108;
/// Protocol not available
pub const ENOPROTOOPT: i32 = 109;
/// Can't send after socket shutdown
pub const ESHUTDOWN: i32 = 110;
/// Connection refused
pub const ECONNREFUSED: i32 = 111;
/// Address already in use
pub const EADDRINUSE: i32 = 112;
/// Connection aborted
pub const ECONNABORTED: i32 = 113;
/// Network is unreachable
pub const ENETUNREACH: i32 = 114;
/// Network interface is not configured
pub const ENETDOWN: i32 = 115;
/// Connection timed out
pub const ETIMEDOUT: i32 = 116;
/// Host is down
pub const EHOSTDOWN: i32 = 117;
/// Host is unreachable
pub const EHOSTUNREACH: i32 = 118;
/// Connection already in progress
pub const EINPROGRESS: i32 = 119;
/// Socket already connected
pub const EALREADY: i32 = 120;
/// Destination address required
pub const EDESTADDRREQ: i32 = 121;
/// Message too long
pub const EMSGSIZE: i32 = 122;
/// Unknown protocol
pub const EPROTONOSUPPORT: i32 = 123;
/// Socket type is not supported
pub const ESOCKTNOSUPPORT: i32 = 124;
/// Address not available
pub const EADDRNOTAVAIL: i32 = 125;
/// Network dropped connection on reset
pub const ENETRESET: i32 = 126;
/// Socket is already connected
pub const EISCONN: i32 = 127;
/// Socket is not connected
pub const ENOTCONN: i32 = 128;
/// The number of "in-flight" file descriptors exceeds the
/// `RLIMIT_NOFILE` resource limit, and the caller does not have
/// the `CAP_SYS_RESOURCE` capability.
pub const ETOOMANYREFS: i32 = 129;
/// The per-user limit on the new process would be exceeded by an attempted fork.
pub const EPROCLIM: i32 = 130;
/// The file quota system is confused because there are too many users.
pub const EUSERS: i32 = 131;
/// The user's disk quota was exceeded.
pub const EDQUOT: i32 = 132;
/// Stale NFS file handle.
///
/// This indicates an internal confusion in the NFS system, which is due to file system
/// rearrangements on the server host.
/// Repairing this condition usually requires unmounting and remounting the NFS file system on the
/// local host.
pub const ESTALE: i32 = 133;
/// Not supported
pub const ENOTSUP: i32 = 134;
/// No medium (in tape drive)
pub const ENOMEDIUM: i32 = 135;
/// No such host or network path
pub const ENOSHARE: i32 = 136;
/// Filename exists with different case
pub const ECASECLASH: i32 = 137;
/// While decoding a multibyte character the function came along an invalid or an incomplete
/// sequence of bytes or the given wide character is invalid.
pub const EILSEQ: i32 = 138;
/// Value too large for defined data type
pub const EOVERFLOW: i32 = 139;

///  Not super-user
pub const NEG_EPERM: i32 = -1;
///  No such file or directory
pub const NEG_ENOENT: i32 = -2;
///  No such process
pub const NEG_ESRCH: i32 = -3;
///  Interrupted system call
pub const NEG_EINTR: i32 = -4;
///  I/O error
pub const NEG_EIO: i32 = -5;
///  No such device or address
pub const NEG_ENXIO: i32 = -6;
///  Arg list too long
pub const NEG_E2BIG: i32 = -7;
///  Exec format error
pub const NEG_ENOEXEC: i32 = -8;
///  Bad file number
pub const NEG_EBADF: i32 = -9;
/// No children
pub const NEG_ECHILD: i32 = -10;
/// No more processes
pub const NEG_EAGAIN: i32 = -11;
/// Not enough memory
pub const NEG_ENOMEM: i32 = -12;
/// Permission denied
pub const NEG_EACCES: i32 = -13;
/// Bad address
pub const NEG_EFAULT: i32 = -14;
/// Block device required
pub const NEG_ENOTBLK: i32 = -15;
/// Mount device busy
pub const NEG_EBUSY: i32 = -16;
/// File exists
pub const NEG_EEXIST: i32 = -17;
/// Cross-device link
pub const NEG_EXDEV: i32 = -18;
/// No such device
pub const NEG_ENODEV: i32 = -19;
/// Not a directory
pub const NEG_ENOTDIR: i32 = -20;
/// Is a directory
pub const NEG_EISDIR: i32 = -21;
/// Invalid argument
pub const NEG_EINVAL: i32 = -22;
/// Too many open files in the system
pub const NEG_ENFILE: i32 = -23;
/// Too many open files
pub const NEG_EMFILE: i32 = -24;
/// Not a typewriter
pub const NEG_ENOTTY: i32 = -25;
/// Text file busy
pub const NEG_ETXTBSY: i32 = -26;
/// File too large
pub const NEG_EFBIG: i32 = -27;
/// No space left on a device
pub const NEG_ENOSPC: i32 = -28;
/// Illegal seek
pub const NEG_ESPIPE: i32 = -29;
/// Read-only file system
pub const NEG_EROFS: i32 = -30;
/// Too many links
pub const NEG_EMLINK: i32 = -31;
/// Broken pipe
pub const NEG_EPIPE: i32 = -32;
/// Math arg out of the domain of func
pub const NEG_EDOM: i32 = -33;
/// Math result not representable
pub const NEG_ERANGE: i32 = -34;
/// No message of desired type
pub const NEG_ENOMSG: i32 = -35;
/// Identifier removed
pub const NEG_EIDRM: i32 = -36;
/// Channel number out of range
pub const NEG_ECHRNG: i32 = -37;
/// Level 2 not synchronized
pub const NEG_EL2NSYNC: i32 = -38;
/// Level 3 halted
pub const NEG_EL3HLT: i32 = -39;
/// Level 3 reset
pub const NEG_EL3RST: i32 = -40;
/// Link number out of range
pub const NEG_ELNRNG: i32 = -41;
/// Protocol driver not attached
pub const NEG_EUNATCH: i32 = -42;
/// No CSI structure available
pub const NEG_ENOCSI: i32 = -43;
/// Level 2 halted
pub const NEG_EL2HLT: i32 = -44;
/// Deadlock condition
pub const NEG_EDEADLK: i32 = -45;
/// No record locks available
pub const NEG_ENOLCK: i32 = -46;
/// Invalid exchange
pub const NEG_EBADE: i32 = -50;
/// Invalid request descriptor
pub const NEG_EBADR: i32 = -51;
/// Exchange full
pub const NEG_EXFULL: i32 = -52;
/// No anode
pub const NEG_ENOANO: i32 = -53;
/// Invalid request code
pub const NEG_EBADRQC: i32 = -54;
/// Invalid slot
pub const NEG_EBADSLT: i32 = -55;
/// File locking deadlock error
pub const NEG_EDEADLOCK: i32 = -56;
/// Bad font file fmt
pub const NEG_EBFONT: i32 = -57;
/// Device not a stream
pub const NEG_ENOSTR: i32 = -60;
/// No data (for no delay io)
pub const NEG_ENODATA: i32 = -61;
/// Timer expired
pub const NEG_ETIME: i32 = -62;
/// Out of streams resources
pub const NEG_ENOSR: i32 = -63;
/// Machine is not on the network
pub const NEG_ENONET: i32 = -64;
/// Package not installed
pub const NEG_ENOPKG: i32 = -65;
/// The object is remote
pub const NEG_EREMOTE: i32 = -66;
/// The link has been severed
pub const NEG_ENOLINK: i32 = -67;
/// Advertise error
pub const NEG_EADV: i32 = -68;
/// Srmount error
pub const NEG_ESRMNT: i32 = -69;
/// Communication error on send
pub const NEG_ECOMM: i32 = -70;
/// Protocol error
pub const NEG_EPROTO: i32 = -71;
/// Multihop attempted
pub const NEG_EMULTIHOP: i32 = -74;
/// Inode is remote (not really error)
pub const NEG_ELBIN: i32 = -75;
/// Cross-mount point (not really error)
pub const NEG_EDOTDOT: i32 = -76;
/// Trying to read an unreadable message
pub const NEG_EBADMSG: i32 = -77;
/// Inappropriate file type or format
pub const NEG_EFTYPE: i32 = -79;
/// Given log name not unique
pub const NEG_ENOTUNIQ: i32 = -80;
/// f.d. invalid for this operation
pub const NEG_EBADFD: i32 = -81;
/// Remote address changed
pub const NEG_EREMCHG: i32 = -82;
/// Can't access a necessary shared lib
pub const NEG_ELIBACC: i32 = -83;
/// Accessing a corrupted shared lib
pub const NEG_ELIBBAD: i32 = -84;
/// .lib section in a.out corrupted
pub const NEG_ELIBSCN: i32 = -85;
/// Attempting to link in too many libs
pub const NEG_ELIBMAX: i32 = -86;
/// Attempting to exec a shared library
pub const NEG_ELIBEXEC: i32 = -87;
/// Function is not implemented
pub const NEG_ENOSYS: i32 = -88;
/// No more files
pub const NEG_ENMFILE: i32 = -89;
/// Directory is not empty
pub const NEG_ENOTEMPTY: i32 = -90;
/// File or path name too long
pub const NEG_ENAMETOOLONG: i32 = -91;
/// Too many symbolic links
pub const NEG_ELOOP: i32 = -92;
/// Operation not supported on transport endpoint
pub const NEG_EOPNOTSUPP: i32 = -95;
/// Protocol family is not supported
pub const NEG_EPFNOSUPPORT: i32 = -96;
/// Connection reset by peer
pub const NEG_ECONNRESET: i32 = -104;
/// No buffer space available
pub const NEG_ENOBUFS: i32 = -105;
/// ess family is not supported by protocol family
pub const NEG_EAFNOSUPPORT: i32 = -106;
/// Protocol wrong type for socket
pub const NEG_EPROTOTYPE: i32 = -107;
/// Socket operation on non-socket
pub const NEG_ENOTSOCK: i32 = -108;
/// Protocol not available
pub const NEG_ENOPROTOOPT: i32 = -109;
/// Can't send after socket shutdown
pub const NEG_ESHUTDOWN: i32 = -110;
/// Connection refused
pub const NEG_ECONNREFUSED: i32 = -111;
/// Address already in use
pub const NEG_EADDRINUSE: i32 = -112;
/// Connection aborted
pub const NEG_ECONNABORTED: i32 = -113;
/// Network is unreachable
pub const NEG_ENETUNREACH: i32 = -114;
/// Network interface is not configured
pub const NEG_ENETDOWN: i32 = -115;
/// Connection timed out
pub const NEG_ETIMEDOUT: i32 = -116;
/// Host is down
pub const NEG_EHOSTDOWN: i32 = -117;
/// Host is unreachable
pub const NEG_EHOSTUNREACH: i32 = -118;
/// Connection already in progress
pub const NEG_EINPROGRESS: i32 = -119;
/// Socket already connected
pub const NEG_EALREADY: i32 = -120;
/// Destination address required
pub const NEG_EDESTADDRREQ: i32 = -121;
/// Message too long
pub const NEG_EMSGSIZE: i32 = -122;
/// Unknown protocol
pub const NEG_EPROTONOSUPPORT: i32 = -123;
/// Socket type is not supported
pub const NEG_ESOCKTNOSUPPORT: i32 = -124;
/// Address not available
pub const NEG_EADDRNOTAVAIL: i32 = -125;
/// Network dropped connection on reset
pub const NEG_ENETRESET: i32 = -126;
/// Socket is already connected
pub const NEG_EISCONN: i32 = -127;
/// Socket is not connected
pub const NEG_ENOTCONN: i32 = -128;
/// This error can occur for `sendmsg(2)` when sending a file descriptor as ancillary data over a
/// UNIX domain socket.
///
/// It occurs if the number of "in-flight" file descriptors exceeds the `RLIMIT_NOFILE` resource
/// limit and the caller does not have the `CAP_SYS_RESOURCE` capability. An in-flight file
/// descriptor is one that has been sent using `sendmsg(2)` but has not yet been accepted in the
/// recipient process using `recvmsg(2)`.
///
/// This error has been diagnosed since mainline Linux 4.5 (and in some earlier kernel versions
/// where the fix has been backported).  In earlier kernel versions, it was possible to place an
/// unlimited number of file descriptors in flight by sending each file descriptor with
/// `sendmsg(2)` and then closing the file descriptor so that it was not accounted against the
/// `RLIMIT_NOFILE` resource limit.
pub const NEG_ETOOMANYREFS: i32 = -129;
/// The per-user limit on the new process would be exceeded by an attempted fork.
pub const NEG_EPROCLIM: i32 = -130;
/// The file quota system is confused because there are too many users.
pub const NEG_EUSERS: i32 = -131;
/// The user's disk quota was exceeded.
pub const NEG_EDQUOT: i32 = -132;
/// Stale NFS file handle.
///
/// This indicates an internal confusion in the NFS system, which is due to file system
/// rearrangements on the server host.
/// Repairing this condition usually requires unmounting and remounting the NFS file system on the
/// local host.
pub const NEG_ESTALE: i32 = -133;
/// Not supported
pub const NEG_ENOTSUP: i32 = -134;
/// No medium (in tape drive)
pub const NEG_ENOMEDIUM: i32 = -135;
/// No such host or network path
pub const NEG_ENOSHARE: i32 = -136;
/// Filename exists with different case
pub const NEG_ECASECLASH: i32 = -137;
/// While decoding a multibyte character the function came along an invalid or an incomplete
/// sequence of bytes or the given wide character is invalid.
pub const NEG_EILSEQ: i32 = -138;
/// Value too large for defined data type
pub const NEG_EOVERFLOW: i32 = -139;

/// Standard errno values
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[repr(i32)]
pub enum StandardErrno {
    /// No error.  Successful operation.
    #[error("No error.  Successful operation.")]
    Success = SUCCESS,
    /// Operation not permitted
    #[error("Operation not permitted")]
    PermissionDenied = EPERM,
    /// No such file or directory
    #[error("No such file or directory")]
    NoSuchFileOrDirectory = ENOENT,
    /// No such process
    #[error("No such process")]
    NoSuchProcess = ESRCH,
    /// Interrupted system call
    #[error("Interrupted system call")]
    Interrupted = EINTR,
    /// I/O error
    #[error("I/O error")]
    Io = EIO,
    /// No such device or address
    #[error("No such device or address")]
    NoSuchDeviceOrAddress = ENXIO,
    /// Argument list too long
    #[error("Argument list too long")]
    TooBig = E2BIG,
    /// Exec format error
    #[error("Exec format error")]
    ExecFormat = ENOEXEC,
    /// Bad file number
    #[error("Bad file number")]
    BadFileNumber = EBADF,
    /// No child processes
    #[error("No child processes")]
    NoChildProcesses = ECHILD,
    /// Try again
    #[error("Try again")]
    TryAgain = EAGAIN,
    /// No memory available
    #[error("No memory available")]
    NoMemory = ENOMEM,
    /// Access denied
    #[error("Access denied")]
    AccessDenied = EACCES,
    /// Bad address
    #[error("Bad address")]
    BadAddress = EFAULT,
    /// Block device required
    #[error("Block device required")]
    BlockDeviceRequired = ENOTBLK,
    /// Device or resource busy
    #[error("Device or resource busy")]
    Busy = EBUSY,
    /// File exists
    #[error("File exists")]
    FileExists = EEXIST,
    /// Cross-device link
    #[error("Cross-device link")]
    CrossDeviceLink = EXDEV,
    /// No such device
    #[error("No such device")]
    NoSuchDevice = ENODEV,
    /// Not a directory
    #[error("Not a directory")]
    NotADirectory = ENOTDIR,
    /// Is a directory
    #[error("Is a directory")]
    IsADirectory = EISDIR,
    /// Invalid argument
    #[error("Invalid argument")]
    InvalidArgument = EINVAL,
    /// File table overflow
    #[error("File table overflow")]
    FileTableOverflow = ENFILE,
    /// Too many open files
    #[error("Too many open files")]
    TooManyOpenFiles = EMFILE,
    /// Not a tty
    #[error("Not a tty")]
    NotATty = ENOTTY,
    /// Text file busy
    #[error("Text file busy")]
    TextFileBusy = ETXTBSY,
    /// File too large
    #[error("File too large")]
    FileTooLarge = EFBIG,
    /// No space left on a device
    #[error("No space left on device")]
    NoSpaceLeftOnDevice = ENOSPC,
    /// Illegal seek
    #[error("Illegal seek")]
    IllegalSeek = ESPIPE,
    /// Read-only file system
    #[error("Read-only file system")]
    ReadOnlyFileSystem = EROFS,
    /// Too many links
    #[error("Too many links")]
    TooManyLinks = EMLINK,
    /// Broken pipe
    #[error("Broken pipe")]
    BrokenPipe = EPIPE,
    /// Numerical argument out of domain
    #[error("Numerical argument out of domain")]
    NumberOutOfDomain = EDOM,
    /// Result too large
    #[error("Result too large")]
    ResultTooLarge = ERANGE,
    /// No message of desired type
    #[error("No message of desired type")]
    NoMessage = ENOMSG,
    /// Identifier removed
    #[error("Identifier removed")]
    IdentifierRemoved = EIDRM,
    /// Channel number out of range
    #[error("Channel number out of range")]
    ChannelNumberOutOfRange = ECHRNG,
    /// Level 2 not synchronized
    #[error("Level 2 not synchronized")]
    Level2NotSynchronized = EL2NSYNC,
    /// Level 3 halted
    #[error("Level 3 halted")]
    Level3Halted = EL3HLT,
    /// Level 3 reset
    #[error("Level 3 reset")]
    Level3Reset = EL3RST,
    /// Link number out of range
    #[error("Link number out of range")]
    LinkNumberOutOfRange = ELNRNG,
    /// Protocol driver not attached
    #[error("Protocol driver not attached")]
    ProtocolDriverNotAttached = EUNATCH,
    /// No CSI structure available
    #[error("No CSI structure available")]
    NoCsiStructureAvailable = ENOCSI,
    /// Level 2 halted
    #[error("Level 2 halted")]
    Level2Halted = EL2HLT,
    /// Deadlock condition
    #[error("Deadlock condition")]
    Deadlock = EDEADLK,
    /// No record locks available
    #[error("No record locks available")]
    NoRecordLocksAvailable = ENOLCK,
    /// Invalid exchange
    #[error("Invalid exchange")]
    InvalidExchange = EBADE,
    /// Invalid request descriptor
    #[error("Invalid request descriptor")]
    InvalidRequestDescriptor = EBADR,
    /// Exchange full
    #[error("Exchange full")]
    ExchangeFull = EXFULL,
    /// No anode
    #[error("No anode")]
    NoAnode = ENOANO,
    /// Invalid request code
    #[error("Invalid request code")]
    InvalidRequestCode = EBADRQC,
    /// Invalid slot
    #[error("Invalid slot")]
    InvalidSlot = EBADSLT,
    /// File locking deadlock error
    #[error("File locking deadlock error")]
    FileLockingDeadlock = EDEADLOCK,
    /// Bad font file format
    #[error("Bad font file format")]
    BadFontFileFormat = EBFONT,
    /// Device not a stream
    #[error("Device not a stream")]
    DeviceNotAStream = ENOSTR,
    /// No data available
    #[error("No data available")]
    NoDataAvailable = ENODATA,
    /// Timer expired
    #[error("Timer expired")]
    TimerExpired = ETIME,
    /// Out of streams resources
    #[error("Out of streams resources")]
    OutOfStreamsResources = ENOSR,
    /// Machine is not on the network
    #[error("Machine is not on the network")]
    MachineNotOnTheNetwork = ENONET,
    /// Package not installed
    #[error("Package not installed")]
    PackageNotInstalled = ENOPKG,
    /// The object is remote
    #[error("The object is remote")]
    ObjectIsRemote = EREMOTE,
    /// The link has been severed
    #[error("The link has been severed")]
    LinkSevered = ENOLINK,
    /// Advertise error
    #[error("Advertise error")]
    AdvertiseError = EADV,
    /// Srmount error
    #[error("Srmount error")]
    SrmountError = ESRMNT,
    /// Communication error on send
    #[error("Communication error on send")]
    CommunicationErrorOnSend = ECOMM,
    /// Protocol error
    #[error("Protocol error")]
    ProtocolError = EPROTO,
    /// Multihop attempted
    #[error("Multihop attempted")]
    MultihopAttempted = EMULTIHOP,
    /// Inode is remote (not really error)
    #[error("Inode is remote (not really error)")]
    InodeIsRemote = ELBIN,
    /// Cross-mount point (not really error)
    #[error("Cross mount point (not really error)")]
    CrossMountPoint = EDOTDOT,
    /// Trying to read an unreadable message
    #[error("Trying to read unreadable message")]
    TryingToReadUnreadableMessage = EBADMSG,
    /// Inappropriate file type or format
    #[error("Inappropriate file type or format")]
    InappropriateFileTypeOrFormat = EFTYPE,
    /// Given log name not unique
    #[error("Given log name not unique")]
    GivenLogNameNotUnique = ENOTUNIQ,
    /// f.d. invalid for this operation
    #[error("f.d. invalid for this operation")]
    FdInvalidForThisOperation = EBADFD,
    /// Remote address changed
    #[error("Remote address changed")]
    RemoteAddressChanged = EREMCHG,
    /// Can't access a necessary shared library
    #[error("Can't access a needed shared library")]
    CantAccessNeededSharedLibrary = ELIBACC,
    /// Accessing a corrupted shared library
    #[error("Accessing a corrupted shared library")]
    AccessingCorruptedSharedLibrary = ELIBBAD,
    /// .lib section in a.out corrupted
    #[error(".lib section in a.out corrupted")]
    LibSectionInAOutCorrupted = ELIBSCN,
    /// Attempting to link in too many libs
    #[error("Attempting to link in too many libs")]
    AttemptingToLinkInTooManyLibs = ELIBMAX,
    /// Attempting to exec a shared library
    #[error("Attempting to exec a shared library")]
    AttemptingToExecASharedLibrary = ELIBEXEC,
    /// Function is not implemented
    #[error("Function not implemented")]
    FunctionNotImplemented = ENOSYS,
    /// No more files
    #[error("No more files")]
    NoMoreFiles = ENMFILE,
    /// Directory is not empty
    #[error("Directory not empty")]
    DirectoryNotEmpty = ENOTEMPTY,
    /// File or path name too long
    #[error("File or path name too long")]
    FileOrPathNameTooLong = ENAMETOOLONG,
    /// Too many symbolic links
    #[error("Too many symbolic links")]
    TooManySymbolicLinks = ELOOP,
    /// Operation not supported on transport endpoint
    #[error("Operation not supported on transport endpoint")]
    OperationNotSupportedOnTransportEndpoint = EOPNOTSUPP,
    /// Protocol family is not supported
    #[error("Protocol family not supported")]
    ProtocolFamilyNotSupported = EPFNOSUPPORT,
    /// Connection reset by peer
    #[error("Connection reset by peer")]
    ConnectionResetByPeer = ECONNRESET,
    /// No buffer space available
    #[error("No buffer space available")]
    NoBufferSpaceAvailable = ENOBUFS,
    /// Address family not supported by protocol family
    #[error("Address family not supported by protocol family")]
    AddressFamilyNotSupportedByProtocolFamily = EAFNOSUPPORT,
    /// Protocol wrong type for socket
    #[error("Protocol wrong type for socket")]
    ProtocolWrongTypeForSocket = EPROTOTYPE,
    /// Socket operation on non-socket
    #[error("Socket operation on non-socket")]
    SocketOperationOnNonSocket = ENOTSOCK,
    /// Protocol not available
    #[error("Protocol not available")]
    ProtocolNotAvailable = ENOPROTOOPT,
    /// Can't send after socket shutdown
    #[error("Can't send after socket shutdown")]
    CantSendAfterSocketShutdown = ESHUTDOWN,
    /// Connection refused
    #[error("Connection refused")]
    ConnectionRefused = ECONNREFUSED,
    /// Address already in use
    #[error("Address already in use")]
    AddressAlreadyInUse = EADDRINUSE,
    /// Connection aborted
    #[error("Connection aborted")]
    ConnectionAborted = ECONNABORTED,
    /// Network is unreachable
    #[error("Network is unreachable")]
    NetworkIsUnreachable = ENETUNREACH,
    /// Network interface is not configured
    #[error("Network interface is not configured")]
    NetworkInterfaceNotConfigured = ENETDOWN,
    /// Connection timed out
    #[error("Connection timed out")]
    ConnectionTimedOut = ETIMEDOUT,
    /// Host is down
    #[error("Host is down")]
    HostIsDown = EHOSTDOWN,
    /// Host is unreachable
    #[error("Host is unreachable")]
    HostIsUnreachable = EHOSTUNREACH,
    /// Connection already in progress
    #[error("Connection already in progress")]
    ConnectionAlreadyInProgress = EINPROGRESS,
    /// Socket already connected
    #[error("Socket already connected")]
    SocketAlreadyConnected = EALREADY,
    /// Destination address required
    #[error("Destination address required")]
    DestinationAddressRequired = EDESTADDRREQ,
    /// Message too long
    #[error("Message too long")]
    MessageTooLong = EMSGSIZE,
    /// Unknown protocol
    #[error("Unknown protocol")]
    UnknownProtocol = EPROTONOSUPPORT,
    /// Socket type is not supported
    #[error("Socket type not supported")]
    SocketTypeNotSupported = ESOCKTNOSUPPORT,
    /// Address not available
    #[error("Address not available")]
    AddressNotAvailable = EADDRNOTAVAIL,
    /// Network dropped connection on reset
    #[error("Network dropped connection on reset")]
    NetworkDroppedConnectionOnReset = ENETRESET,
    /// Socket is already connected
    #[error("Socket is already connected")]
    SocketIsAlreadyConnected = EISCONN,
    /// Socket is not connected
    #[error("Socket is not connected")]
    SocketIsNotConnected = ENOTCONN,
    /// Too many references: cannot splice
    #[error("Too many references: cannot splice")]
    TooManyReferences = ETOOMANYREFS,
    /// The per-user limit on the new process would be exceeded by an attempted fork.
    #[error("The per-user limit on new process would be exceeded by an attempted fork.")]
    ProcessLimitExceeded = EPROCLIM,
    /// The file quota system is confused because there are too many users.
    #[error("The file quota system is confused because there are too many users.")]
    TooManyUsers = EUSERS,
    /// The user's disk quota was exceeded.
    #[error("The user's disk quota was exceeded.")]
    DiskQuotaExceeded = EDQUOT,
    /// Stale NFS file handle
    #[error("Stale NFS file handle")]
    StaleNfsFileHandle = ESTALE,
    /// Not supported
    #[error("Not supported")]
    NotSupported = ENOTSUP,
    /// No medium (in tape drive)
    #[error("No medium (in tape drive)")]
    NoMedium = ENOMEDIUM,
    /// No such host or network path
    #[error("No such host or network path")]
    NoShare = ENOSHARE,
    /// Filename exists with different case
    #[error("Filename exists with different case")]
    CaseClash = ECASECLASH,
    /// While decoding a multibyte character the function came along an invalid or an incomplete
    /// sequence of bytes or the given wide character is invalid.
    #[error("While decoding a multibyte character the function came along an invalid or an incomplete sequence of bytes or the given wide character is invalid.")]
    IllegalSequence = EILSEQ,
    /// Value too large for defined data type
    #[error("Value too large for defined data type")]
    Overflow = EOVERFLOW,
}

impl StandardErrno {
    /// Get the `i32` value of a standard errno.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    #[allow(clippy::too_many_lines)]
    /// Parse an `i32` value into a `StandardErrno`.
    ///
    /// # Errors
    ///
    /// Returns the original `i32` value if it does not correspond to a standard errno.
    pub const fn parse_i32(value: i32) -> Result<StandardErrno, i32> {
        match value {
            SUCCESS => Ok(Self::Success),
            EPERM => Ok(Self::PermissionDenied),
            ENOENT => Ok(Self::NoSuchFileOrDirectory),
            ESRCH => Ok(Self::NoSuchProcess),
            EINTR => Ok(Self::Interrupted),
            EIO => Ok(Self::Io),
            ENXIO => Ok(Self::NoSuchDeviceOrAddress),
            E2BIG => Ok(Self::TooBig),
            ENOEXEC => Ok(Self::ExecFormat),
            EBADF => Ok(Self::BadFileNumber),
            ECHILD => Ok(Self::NoChildProcesses),
            EAGAIN => Ok(Self::TryAgain),
            ENOMEM => Ok(Self::NoMemory),
            EACCES => Ok(Self::AccessDenied),
            EFAULT => Ok(Self::BadAddress),
            ENOTBLK => Ok(Self::BlockDeviceRequired),
            EBUSY => Ok(Self::Busy),
            EEXIST => Ok(Self::FileExists),
            EXDEV => Ok(Self::CrossDeviceLink),
            ENODEV => Ok(Self::NoSuchDevice),
            ENOTDIR => Ok(Self::NotADirectory),
            EISDIR => Ok(Self::IsADirectory),
            EINVAL => Ok(Self::InvalidArgument),
            ENFILE => Ok(Self::FileTableOverflow),
            EMFILE => Ok(Self::TooManyOpenFiles),
            ENOTTY => Ok(Self::NotATty),
            ETXTBSY => Ok(Self::TextFileBusy),
            EFBIG => Ok(Self::FileTooLarge),
            ENOSPC => Ok(Self::NoSpaceLeftOnDevice),
            ESPIPE => Ok(Self::IllegalSeek),
            EROFS => Ok(Self::ReadOnlyFileSystem),
            EMLINK => Ok(Self::TooManyLinks),
            EPIPE => Ok(Self::BrokenPipe),
            EDOM => Ok(Self::NumberOutOfDomain),
            ERANGE => Ok(Self::ResultTooLarge),
            ENOMSG => Ok(Self::NoMessage),
            EIDRM => Ok(Self::IdentifierRemoved),
            ECHRNG => Ok(Self::ChannelNumberOutOfRange),
            EL2NSYNC => Ok(Self::Level2NotSynchronized),
            EL3HLT => Ok(Self::Level3Halted),
            EL3RST => Ok(Self::Level3Reset),
            ELNRNG => Ok(Self::LinkNumberOutOfRange),
            EUNATCH => Ok(Self::ProtocolDriverNotAttached),
            ENOCSI => Ok(Self::NoCsiStructureAvailable),
            EL2HLT => Ok(Self::Level2Halted),
            EDEADLK => Ok(Self::Deadlock),
            ENOLCK => Ok(Self::NoRecordLocksAvailable),
            EBADE => Ok(Self::InvalidExchange),
            EBADR => Ok(Self::InvalidRequestDescriptor),
            EXFULL => Ok(Self::ExchangeFull),
            ENOANO => Ok(Self::NoAnode),
            EBADRQC => Ok(Self::InvalidRequestCode),
            EBADSLT => Ok(Self::InvalidSlot),
            EDEADLOCK => Ok(Self::FileLockingDeadlock),
            EBFONT => Ok(Self::BadFontFileFormat),
            ENOSTR => Ok(Self::DeviceNotAStream),
            ENODATA => Ok(Self::NoDataAvailable),
            ETIME => Ok(Self::TimerExpired),
            ENOSR => Ok(Self::OutOfStreamsResources),
            ENONET => Ok(Self::MachineNotOnTheNetwork),
            ENOPKG => Ok(Self::PackageNotInstalled),
            EREMOTE => Ok(Self::ObjectIsRemote),
            ENOLINK => Ok(Self::LinkSevered),
            EADV => Ok(Self::AdvertiseError),
            ESRMNT => Ok(Self::SrmountError),
            ECOMM => Ok(Self::CommunicationErrorOnSend),
            EPROTO => Ok(Self::ProtocolError),
            EMULTIHOP => Ok(Self::MultihopAttempted),
            ELBIN => Ok(Self::InodeIsRemote),
            EDOTDOT => Ok(Self::CrossMountPoint),
            EBADMSG => Ok(Self::TryingToReadUnreadableMessage),
            EFTYPE => Ok(Self::InappropriateFileTypeOrFormat),
            ENOTUNIQ => Ok(Self::GivenLogNameNotUnique),
            EBADFD => Ok(Self::FdInvalidForThisOperation),
            EREMCHG => Ok(Self::RemoteAddressChanged),
            ELIBACC => Ok(Self::CantAccessNeededSharedLibrary),
            ELIBBAD => Ok(Self::AccessingCorruptedSharedLibrary),
            ELIBSCN => Ok(Self::LibSectionInAOutCorrupted),
            ELIBMAX => Ok(Self::AttemptingToLinkInTooManyLibs),
            ELIBEXEC => Ok(Self::AttemptingToExecASharedLibrary),
            ENOSYS => Ok(Self::FunctionNotImplemented),
            ENMFILE => Ok(Self::NoMoreFiles),
            ENOTEMPTY => Ok(Self::DirectoryNotEmpty),
            ENAMETOOLONG => Ok(Self::FileOrPathNameTooLong),
            ELOOP => Ok(Self::TooManySymbolicLinks),
            EOPNOTSUPP => Ok(Self::OperationNotSupportedOnTransportEndpoint),
            EPFNOSUPPORT => Ok(Self::ProtocolFamilyNotSupported),
            ECONNRESET => Ok(Self::ConnectionResetByPeer),
            ENOBUFS => Ok(Self::NoBufferSpaceAvailable),
            EAFNOSUPPORT => Ok(Self::AddressFamilyNotSupportedByProtocolFamily),
            EPROTOTYPE => Ok(Self::ProtocolWrongTypeForSocket),
            ENOTSOCK => Ok(Self::SocketOperationOnNonSocket),
            ENOPROTOOPT => Ok(Self::ProtocolNotAvailable),
            ESHUTDOWN => Ok(Self::CantSendAfterSocketShutdown),
            ECONNREFUSED => Ok(Self::ConnectionRefused),
            EADDRINUSE => Ok(Self::AddressAlreadyInUse),
            ECONNABORTED => Ok(Self::ConnectionAborted),
            ENETUNREACH => Ok(Self::NetworkIsUnreachable),
            ENETDOWN => Ok(Self::NetworkInterfaceNotConfigured),
            ETIMEDOUT => Ok(Self::ConnectionTimedOut),
            EHOSTDOWN => Ok(Self::HostIsDown),
            EHOSTUNREACH => Ok(Self::HostIsUnreachable),
            EINPROGRESS => Ok(Self::ConnectionAlreadyInProgress),
            EALREADY => Ok(Self::SocketAlreadyConnected),
            EDESTADDRREQ => Ok(Self::DestinationAddressRequired),
            EMSGSIZE => Ok(Self::MessageTooLong),
            EPROTONOSUPPORT => Ok(Self::UnknownProtocol),
            ESOCKTNOSUPPORT => Ok(Self::SocketTypeNotSupported),
            EADDRNOTAVAIL => Ok(Self::AddressNotAvailable),
            ENETRESET => Ok(Self::NetworkDroppedConnectionOnReset),
            EISCONN => Ok(Self::SocketIsAlreadyConnected),
            ENOTCONN => Ok(Self::SocketIsNotConnected),
            ETOOMANYREFS => Ok(Self::TooManyReferences),
            EPROCLIM => Ok(Self::ProcessLimitExceeded),
            EUSERS => Ok(Self::TooManyUsers),
            EDQUOT => Ok(Self::DiskQuotaExceeded),
            ESTALE => Ok(Self::StaleNfsFileHandle),
            ENOTSUP => Ok(Self::NotSupported),
            ENOMEDIUM => Ok(Self::NoMedium),
            ENOSHARE => Ok(Self::NoShare),
            ECASECLASH => Ok(Self::CaseClash),
            EILSEQ => Ok(Self::IllegalSequence),
            EOVERFLOW => Ok(Self::Overflow),
            _ => Err(value),
        }
    }
}

/// Newtype wrapper around an errno value.
///
/// These are basically just `i32` values, but this type is used to make it clear that the value is
/// an errno.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Errno(pub i32);

impl From<i32> for Errno {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<Errno> for i32 {
    fn from(value: Errno) -> i32 {
        value.0
    }
}

impl TryFrom<Errno> for StandardErrno {
    type Error = i32;

    fn try_from(value: Errno) -> Result<Self, Self::Error> {
        StandardErrno::parse_i32(value.0)
    }
}

impl From<StandardErrno> for Errno {
    fn from(value: StandardErrno) -> Self {
        Self(value as i32)
    }
}

impl TryFrom<Errno> for NegStandardErrno {
    type Error = i32;

    fn try_from(value: Errno) -> Result<Self, Self::Error> {
        Ok(StandardErrno::parse_i32(-value.0)?.neg())
    }
}

/// Standard errno values negated
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[error(transparent)]
pub struct NegStandardErrno(StandardErrno);

impl StandardErrno {
    /// Negate the errno value.
    #[must_use]
    pub const fn neg(self) -> NegStandardErrno {
        NegStandardErrno(self)
    }
}

impl NegStandardErrno {
    /// Negate the errno value.
    #[must_use]
    pub const fn neg(self) -> StandardErrno {
        self.0
    }

    /// Parse an `i32` value into a `StandardErrno`.
    ///
    /// # Errors
    ///
    /// Returns the original `i32` value if it does not correspond to a standard errno.
    pub const fn parse_i32(value: i32) -> Result<Self, i32> {
        match StandardErrno::parse_i32(-value) {
            Ok(standard) => Ok(standard.neg()),
            Err(_) => Err(value),
        }
    }
}

impl core::ops::Neg for StandardErrno {
    type Output = NegStandardErrno;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl core::ops::Neg for NegStandardErrno {
    type Output = StandardErrno;

    #[must_use]
    fn neg(self) -> Self::Output {
        self.neg()
    }
}

/// An "errno" error
///
/// This enum attempts to map `i32` values to standard (both positive and negative) values as
/// defined in [`errno.h`].
///
/// The negative versions of the errors are commonly found in `C` code and often (but don't always)
/// map to the meaning of their positive counterparts.
/// Thus positive and negative values are kept in different arms of this enum.
///
/// [`errno.h`]: https://man7.org/linux/man-pages/man3/errno.3.html
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[must_use]
pub enum ErrorCode {
    /// A standard errno value
    #[error(transparent)]
    Standard(StandardErrno),
    /// A negated standard errno value
    #[error(transparent)]
    NegStandard(NegStandardErrno),
    /// Any `i32` which does not map to a standard (positive or negative) Errno value
    #[error("Unknown (non-standard) errno: {0:?}")]
    Other(Errno),
}

impl ErrorCode {
    /// Parse an `i32` value into an `errno::Error`.
    pub const fn parse_i32(val: i32) -> ErrorCode {
        match StandardErrno::parse_i32(val) {
            Ok(standard) => ErrorCode::Standard(standard),
            Err(_) => match NegStandardErrno::parse_i32(val) {
                Ok(neg_standard) => ErrorCode::NegStandard(neg_standard),
                Err(_) => ErrorCode::Other(Errno(val)),
            },
        }
    }

    /// Parse an `Errno` value into an `errno::Error`.
    pub const fn parse_errno(val: Errno) -> ErrorCode {
        Self::parse_i32(val.0)
    }

    /// Parse a `T` value into an `errno::Error` where `T` is `Into<i32>`.
    ///
    /// Sadly this function can't currently be `const`.
    pub fn parse<T>(val: T) -> ErrorCode
    where
        T: Into<i32>,
    {
        Self::parse_i32(val.into())
    }
}

/// Standard errno values
#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
#[repr(i32)]
pub enum StandardErrnoAgain {
    /// No error.  Successful operation.
    #[error("No error.  Successful operation.")]
    Success(u8) = SUCCESS,
    /// Operation not permitted
    #[error("Operation not permitted")]
    PermissionDenied = EPERM,
    /// No such file or directory
    #[error("No such file or directory")]
    NoSuchFileOrDirectory = ENOENT,
    /// No such process
    #[error("No such process")]
    NoSuchProcess = ESRCH,
    /// Interrupted system call
    #[error("Interrupted system call")]
    Interrupted = EINTR,
    /// I/O error
    #[error("I/O error")]
    Io = EIO,
    /// No such device or address
    #[error("No such device or address")]
    NoSuchDeviceOrAddress = ENXIO,
    /// Argument list too long
    #[error("Argument list too long")]
    TooBig = E2BIG,
    /// Exec format error
    #[error("Exec format error")]
    ExecFormat = ENOEXEC,
    /// Bad file number
    #[error("Bad file number")]
    BadFileNumber = EBADF,
    /// No child processes
    #[error("No child processes")]
    NoChildProcesses = ECHILD,
    /// Try again
    #[error("Try again")]
    TryAgain = EAGAIN,
    /// No memory available
    #[error("No memory available")]
    NoMemory = ENOMEM,
    /// Access denied
    #[error("Access denied")]
    AccessDenied = EACCES,
    /// Bad address
    #[error("Bad address")]
    BadAddress = EFAULT,
    /// Block device required
    #[error("Block device required")]
    BlockDeviceRequired = ENOTBLK,
    /// Device or resource busy
    #[error("Device or resource busy")]
    Busy = EBUSY,
    /// File exists
    #[error("File exists")]
    FileExists = EEXIST,
    /// Cross-device link
    #[error("Cross-device link")]
    CrossDeviceLink = EXDEV,
    /// No such device
    #[error("No such device")]
    NoSuchDevice = ENODEV,
    /// Not a directory
    #[error("Not a directory")]
    NotADirectory = ENOTDIR,
    /// Is a directory
    #[error("Is a directory")]
    IsADirectory = EISDIR,
    /// Invalid argument
    #[error("Invalid argument")]
    InvalidArgument = EINVAL,
    /// File table overflow
    #[error("File table overflow")]
    FileTableOverflow = ENFILE,
    /// Too many open files
    #[error("Too many open files")]
    TooManyOpenFiles = EMFILE,
    /// Not a tty
    #[error("Not a tty")]
    NotATty = ENOTTY,
    /// Text file busy
    #[error("Text file busy")]
    TextFileBusy = ETXTBSY,
    /// File too large
    #[error("File too large")]
    FileTooLarge = EFBIG,
    /// No space left on a device
    #[error("No space left on device")]
    NoSpaceLeftOnDevice = ENOSPC,
    /// Illegal seek
    #[error("Illegal seek")]
    IllegalSeek = ESPIPE,
    /// Read-only file system
    #[error("Read-only file system")]
    ReadOnlyFileSystem = EROFS,
    /// Too many links
    #[error("Too many links")]
    TooManyLinks = EMLINK,
    /// Broken pipe
    #[error("Broken pipe")]
    BrokenPipe = EPIPE,
    /// Numerical argument out of domain
    #[error("Numerical argument out of domain")]
    NumberOutOfDomain = EDOM,
    /// Result too large
    #[error("Result too large")]
    ResultTooLarge = ERANGE,
    /// No message of desired type
    #[error("No message of desired type")]
    NoMessage = ENOMSG,
    /// Identifier removed
    #[error("Identifier removed")]
    IdentifierRemoved = EIDRM,
    /// Channel number out of range
    #[error("Channel number out of range")]
    ChannelNumberOutOfRange = ECHRNG,
    /// Level 2 not synchronized
    #[error("Level 2 not synchronized")]
    Level2NotSynchronized = EL2NSYNC,
    /// Level 3 halted
    #[error("Level 3 halted")]
    Level3Halted = EL3HLT,
    /// Level 3 reset
    #[error("Level 3 reset")]
    Level3Reset = EL3RST,
    /// Link number out of range
    #[error("Link number out of range")]
    LinkNumberOutOfRange = ELNRNG,
    /// Protocol driver not attached
    #[error("Protocol driver not attached")]
    ProtocolDriverNotAttached = EUNATCH,
    /// No CSI structure available
    #[error("No CSI structure available")]
    NoCsiStructureAvailable = ENOCSI,
    /// Level 2 halted
    #[error("Level 2 halted")]
    Level2Halted = EL2HLT,
    /// Deadlock condition
    #[error("Deadlock condition")]
    Deadlock = EDEADLK,
    /// No record locks available
    #[error("No record locks available")]
    NoRecordLocksAvailable = ENOLCK,
    /// Invalid exchange
    #[error("Invalid exchange")]
    InvalidExchange = EBADE,
    /// Invalid request descriptor
    #[error("Invalid request descriptor")]
    InvalidRequestDescriptor = EBADR,
    /// Exchange full
    #[error("Exchange full")]
    ExchangeFull = EXFULL,
    /// No anode
    #[error("No anode")]
    NoAnode = ENOANO,
    /// Invalid request code
    #[error("Invalid request code")]
    InvalidRequestCode = EBADRQC,
    /// Invalid slot
    #[error("Invalid slot")]
    InvalidSlot = EBADSLT,
    /// File locking deadlock error
    #[error("File locking deadlock error")]
    FileLockingDeadlock = EDEADLOCK,
    /// Bad font file format
    #[error("Bad font file format")]
    BadFontFileFormat = EBFONT,
    /// Device not a stream
    #[error("Device not a stream")]
    DeviceNotAStream = ENOSTR,
    /// No data available
    #[error("No data available")]
    NoDataAvailable = ENODATA,
    /// Timer expired
    #[error("Timer expired")]
    TimerExpired = ETIME,
    /// Out of streams resources
    #[error("Out of streams resources")]
    OutOfStreamsResources = ENOSR,
    /// Machine is not on the network
    #[error("Machine is not on the network")]
    MachineNotOnTheNetwork = ENONET,
    /// Package not installed
    #[error("Package not installed")]
    PackageNotInstalled = ENOPKG,
    /// The object is remote
    #[error("The object is remote")]
    ObjectIsRemote = EREMOTE,
    /// The link has been severed
    #[error("The link has been severed")]
    LinkSevered = ENOLINK,
    /// Advertise error
    #[error("Advertise error")]
    AdvertiseError = EADV,
    /// Srmount error
    #[error("Srmount error")]
    SrmountError = ESRMNT,
    /// Communication error on send
    #[error("Communication error on send")]
    CommunicationErrorOnSend = ECOMM,
    /// Protocol error
    #[error("Protocol error")]
    ProtocolError = EPROTO,
    /// Multihop attempted
    #[error("Multihop attempted")]
    MultihopAttempted = EMULTIHOP,
    /// Inode is remote (not really error)
    #[error("Inode is remote (not really error)")]
    InodeIsRemote = ELBIN,
    /// Cross-mount point (not really error)
    #[error("Cross mount point (not really error)")]
    CrossMountPoint = EDOTDOT,
    /// Trying to read an unreadable message
    #[error("Trying to read unreadable message")]
    TryingToReadUnreadableMessage = EBADMSG,
    /// Inappropriate file type or format
    #[error("Inappropriate file type or format")]
    InappropriateFileTypeOrFormat = EFTYPE,
    /// Given log name not unique
    #[error("Given log name not unique")]
    GivenLogNameNotUnique = ENOTUNIQ,
    /// f.d. invalid for this operation
    #[error("f.d. invalid for this operation")]
    FdInvalidForThisOperation = EBADFD,
    /// Remote address changed
    #[error("Remote address changed")]
    RemoteAddressChanged = EREMCHG,
    /// Can't access a necessary shared library
    #[error("Can't access a needed shared library")]
    CantAccessNeededSharedLibrary = ELIBACC,
    /// Accessing a corrupted shared library
    #[error("Accessing a corrupted shared library")]
    AccessingCorruptedSharedLibrary = ELIBBAD,
    /// .lib section in a.out corrupted
    #[error(".lib section in a.out corrupted")]
    LibSectionInAOutCorrupted = ELIBSCN,
    /// Attempting to link in too many libs
    #[error("Attempting to link in too many libs")]
    AttemptingToLinkInTooManyLibs = ELIBMAX,
    /// Attempting to exec a shared library
    #[error("Attempting to exec a shared library")]
    AttemptingToExecASharedLibrary = ELIBEXEC,
    /// Function is not implemented
    #[error("Function not implemented")]
    FunctionNotImplemented = ENOSYS,
    /// No more files
    #[error("No more files")]
    NoMoreFiles = ENMFILE,
    /// Directory is not empty
    #[error("Directory not empty")]
    DirectoryNotEmpty = ENOTEMPTY,
    /// File or path name too long
    #[error("File or path name too long")]
    FileOrPathNameTooLong = ENAMETOOLONG,
    /// Too many symbolic links
    #[error("Too many symbolic links")]
    TooManySymbolicLinks = ELOOP,
    /// Operation not supported on transport endpoint
    #[error("Operation not supported on transport endpoint")]
    OperationNotSupportedOnTransportEndpoint = EOPNOTSUPP,
    /// Protocol family is not supported
    #[error("Protocol family not supported")]
    ProtocolFamilyNotSupported = EPFNOSUPPORT,
    /// Connection reset by peer
    #[error("Connection reset by peer")]
    ConnectionResetByPeer = ECONNRESET,
    /// No buffer space available
    #[error("No buffer space available")]
    NoBufferSpaceAvailable = ENOBUFS,
    /// Address family not supported by protocol family
    #[error("Address family not supported by protocol family")]
    AddressFamilyNotSupportedByProtocolFamily = EAFNOSUPPORT,
    /// Protocol wrong type for socket
    #[error("Protocol wrong type for socket")]
    ProtocolWrongTypeForSocket = EPROTOTYPE,
    /// Socket operation on non-socket
    #[error("Socket operation on non-socket")]
    SocketOperationOnNonSocket = ENOTSOCK,
    /// Protocol not available
    #[error("Protocol not available")]
    ProtocolNotAvailable = ENOPROTOOPT,
    /// Can't send after socket shutdown
    #[error("Can't send after socket shutdown")]
    CantSendAfterSocketShutdown = ESHUTDOWN,
    /// Connection refused
    #[error("Connection refused")]
    ConnectionRefused = ECONNREFUSED,
    /// Address already in use
    #[error("Address already in use")]
    AddressAlreadyInUse = EADDRINUSE,
    /// Connection aborted
    #[error("Connection aborted")]
    ConnectionAborted = ECONNABORTED,
    /// Network is unreachable
    #[error("Network is unreachable")]
    NetworkIsUnreachable = ENETUNREACH,
    /// Network interface is not configured
    #[error("Network interface is not configured")]
    NetworkInterfaceNotConfigured = ENETDOWN,
    /// Connection timed out
    #[error("Connection timed out")]
    ConnectionTimedOut = ETIMEDOUT,
    /// Host is down
    #[error("Host is down")]
    HostIsDown = EHOSTDOWN,
    /// Host is unreachable
    #[error("Host is unreachable")]
    HostIsUnreachable = EHOSTUNREACH,
    /// Connection already in progress
    #[error("Connection already in progress")]
    ConnectionAlreadyInProgress = EINPROGRESS,
    /// Socket already connected
    #[error("Socket already connected")]
    SocketAlreadyConnected = EALREADY,
    /// Destination address required
    #[error("Destination address required")]
    DestinationAddressRequired = EDESTADDRREQ,
    /// Message too long
    #[error("Message too long")]
    MessageTooLong = EMSGSIZE,
    /// Unknown protocol
    #[error("Unknown protocol")]
    UnknownProtocol = EPROTONOSUPPORT,
    /// Socket type is not supported
    #[error("Socket type not supported")]
    SocketTypeNotSupported = ESOCKTNOSUPPORT,
    /// Address not available
    #[error("Address not available")]
    AddressNotAvailable = EADDRNOTAVAIL,
    /// Network dropped connection on reset
    #[error("Network dropped connection on reset")]
    NetworkDroppedConnectionOnReset = ENETRESET,
    /// Socket is already connected
    #[error("Socket is already connected")]
    SocketIsAlreadyConnected = EISCONN,
    /// Socket is not connected
    #[error("Socket is not connected")]
    SocketIsNotConnected = ENOTCONN,
    /// Too many references: cannot splice
    #[error("Too many references: cannot splice")]
    TooManyReferences = ETOOMANYREFS,
    /// The per-user limit on the new process would be exceeded by an attempted fork.
    #[error("The per-user limit on new process would be exceeded by an attempted fork.")]
    ProcessLimitExceeded = EPROCLIM,
    /// The file quota system is confused because there are too many users.
    #[error("The file quota system is confused because there are too many users.")]
    TooManyUsers = EUSERS,
    /// The user's disk quota was exceeded.
    #[error("The user's disk quota was exceeded.")]
    DiskQuotaExceeded = EDQUOT,
    /// Stale NFS file handle
    #[error("Stale NFS file handle")]
    StaleNfsFileHandle = ESTALE,
    /// Not supported
    #[error("Not supported")]
    NotSupported = ENOTSUP,
    /// No medium (in tape drive)
    #[error("No medium (in tape drive)")]
    NoMedium = ENOMEDIUM,
    /// No such host or network path
    #[error("No such host or network path")]
    NoShare = ENOSHARE,
    /// Filename exists with different case
    #[error("Filename exists with different case")]
    CaseClash = ECASECLASH,
    /// While decoding a multibyte character the function came along an invalid or an incomplete
    /// sequence of bytes or the given wide character is invalid.
    #[error("While decoding a multibyte character the function came along an invalid or an incomplete sequence of bytes or the given wide character is invalid.")]
    IllegalSequence = EILSEQ,
    /// Value too large for defined data type
    #[error("Value too large for defined data type")]
    Overflow = EOVERFLOW,
}
