// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK memory management wrappers.

use crate::eal::{Eal, EalErrno};
use crate::socket::SocketId;
use alloc::format;
use alloc::string::String;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::ffi::c_uint;
use core::ffi::{CStr, c_int};
use core::fmt::{Debug, Display};
use core::marker::PhantomData;
use core::mem::transmute;
use core::ptr::NonNull;
use core::ptr::null;
use core::ptr::null_mut;
use core::slice::from_raw_parts_mut;
use errno::Errno;
use tracing::{error, info, warn};

use dpdk_sys::{
    rte_pktmbuf_adj, rte_pktmbuf_append, rte_pktmbuf_headroom, rte_pktmbuf_prepend,
    rte_pktmbuf_tailroom, rte_pktmbuf_trim,
};
// unfortunately, we need the standard library to swap allocators
use net::buffer::{Append, Headroom, Prepend, Tailroom, TrimFromEnd, TrimFromStart};
use std::alloc::System;
use std::ffi::CString;

/// DPDK memory manager
#[repr(transparent)]
#[derive(Debug)]
#[non_exhaustive]
pub struct Manager;

impl Manager {
    pub(crate) fn init() -> Manager {
        Manager
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        info!("Closing DPDK memory manager");
    }
}

/// Safe wrapper around a DPDK memory pool
///
/// <div class="warning">
///
/// # Note:
///
/// I am not completely sure this implementation is thread safe.
/// It may need a refactor.
///
/// </div>
#[repr(transparent)]
#[derive(Debug)]
pub struct Pool(PoolInner);

impl PartialEq for Pool {
    fn eq(&self, other: &Self) -> bool {
        self.inner() == other.inner()
    }
}

impl Eq for Pool {}

impl PartialEq for PoolInner {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && core::ptr::from_ref(unsafe { self.as_ref() })
                == core::ptr::from_ref(unsafe { other.as_ref() })
    }
}

impl Eq for PoolInner {}

impl Display for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Pool({})", self.name())
    }
}

impl Pool {
    pub(crate) fn inner(&self) -> &PoolInner {
        &self.0
    }

    /// Create a new packet memory pool.
    #[tracing::instrument(level = "debug")]
    pub fn new_pkt_pool(config: PoolConfig) -> Result<Pool, InvalidMemPoolConfig> {
        let pool = unsafe {
            dpdk_sys::rte_pktmbuf_pool_create(
                config.name.as_ptr(),
                config.params.size,
                config.params.cache_size,
                config.params.private_size,
                config.params.data_size,
                // So many sign and bit-width errors in the DPDK API :/
                config.params.socket_id.as_c_uint() as c_int,
            )
        };

        let pool = match NonNull::new(pool) {
            None => {
                let errno = unsafe { dpdk_sys::rte_errno_get() };
                let c_err_str = unsafe { dpdk_sys::rte_strerror(errno) };
                let err_str = unsafe { CStr::from_ptr(c_err_str) };
                // SAFETY:
                // This `expect` is safe because the error string is guaranteed to be valid
                // null-terminated ASCII.
                #[allow(clippy::expect_used)]
                let err_str = err_str.to_str().expect("invalid UTF-8");
                let err_msg = format!("Failed to create mbuf pool: {err_str}; (errno: {errno})");
                error!("{err_msg}");
                return Err(InvalidMemPoolConfig::InvalidParams(
                    Errno::from(errno),
                    err_msg,
                ));
            }
            Some(pool) => pool,
        };

        Ok(Pool(PoolInner { config, pool }))
    }

    /// Get the name of the memory pool.
    #[must_use]
    pub fn name(&self) -> &str {
        self.config().name()
    }

    /// Get the configuration of the memory pool.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.0.config
    }

    #[must_use]
    pub fn alloc_bulk(&self, num: usize) -> Vec<Mbuf> {
        // SAFETY: we should never have any null ptrs come back if ret passes check
        let mut mbufs: Vec<Mbuf> = (0..num)
            .map(|_| unsafe { transmute(null_mut::<dpdk_sys::rte_mbuf>()) })
            .collect();
        let ret = unsafe {
            dpdk_sys::rte_pktmbuf_alloc_bulk_w(
                self.0.as_mut_ptr(),
                transmute::<*mut Mbuf, *mut *mut dpdk_sys::rte_mbuf>(mbufs.as_mut_ptr()),
                num as c_uint,
            )
        };
        EalErrno::assert(ret);
        mbufs
    }
}

/// This value is RAII-managed and must never implement `Copy` and can likely never implement
/// `Clone` unless the internal representation is changed to use a reference-counted pointer.
#[non_exhaustive]
#[derive(Debug)]
pub(crate) struct PoolInner {
    pub(crate) config: PoolConfig,
    pub(crate) pool: NonNull<dpdk_sys::rte_mempool>,
}

impl PoolInner {
    /// Get an immutable reference to the raw DPDK [`rte_mempool`].
    ///
    /// # Safety
    ///
    /// <div class="warning">
    ///
    /// See the safety note on [`PoolInner::as_mut_ptr`].
    ///
    /// </div>
    pub(crate) unsafe fn as_ref(&self) -> &dpdk_sys::rte_mempool {
        unsafe { self.pool.as_ref() }
    }

    /// Get a mutable pointer to the raw DPDK [`rte_mempool`].
    ///
    /// # Safety
    ///
    /// <div class="warning">
    /// This function is very easy to use unsoundly!
    ///
    /// You need to be careful when handing the return value to a [`dpdk_sys`] function or data
    /// structure.
    /// In all cases you need to associate any copy of `*mut rte_mempool` back to the [`Pool`]
    /// object's reference count.
    /// Failing that risks [`Drop`] ([RAII]) tearing down the [`Pool`] while it is still in use.
    ///
    /// If you duplicate the pointer and fail to associate it back with the outer [`Pool`] object's
    /// reference count, you will risk tearing down the memory pool while it is still in use.
    ///
    /// </div>
    ///
    /// [RAII]: https://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization
    pub(crate) unsafe fn as_mut_ptr(&self) -> *mut dpdk_sys::rte_mempool {
        self.pool.as_ptr()
    }
}

unsafe impl Send for PoolInner {}
unsafe impl Sync for PoolInner {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// As yet unchecked parameters for a memory pool.
///
/// TODO: implement validity checking logic.
/// TODO: attach units to fields as helpful.
pub struct PoolParams {
    /// The number of elements in the mbuf pool.
    /// The optimum size (in terms of memory usage) for a mempool is when n is a power of two minus
    /// one: <var>n = 2<sup>q</sup> - 1
    pub size: u32,
    /// Size of the per-core object cache.
    pub cache_size: u32,
    /// Size of application private data between the rte_mbuf structure and the data buffer.
    /// This value must be a natural number multiple of `RTE_MBUF_PRIV_ALIGN` (usually 8).
    pub private_size: u16,
    /// Size of data buffer in each mbuf, including `RTE_PKTMBUF_HEADROOM` (usually 128).
    pub data_size: u16,
    /// The `SocketId` on which to allocate the pool.
    pub socket_id: SocketId,
}

impl Default for PoolParams {
    // TODO: not sure if these defaults are sensible.
    fn default() -> PoolParams {
        PoolParams {
            size: (1 << 15) - 1,
            cache_size: 256,
            private_size: 256,
            data_size: 2048,
            socket_id: SocketId::current(),
        }
    }
}

/// Memory pool config
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolConfig {
    name: CString,
    params: PoolParams,
}

/// Ways in which a memory pool name can be invalid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidMemPoolName {
    /// The name is not valid ASCII.
    NotAscii(String),
    /// The name is too long.
    TooLong(String),
    /// The name is empty.
    Empty(String),
    /// The name does not start with an ASCII letter.
    DoesNotStartWithAsciiLetter(String),
    /// Contains null bytes.
    ContainsNullBytes(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Ways in which a memory pool config can be invalid.
pub enum InvalidMemPoolConfig {
    /// The name of the pool is illegal.
    InvalidName(InvalidMemPoolName),
    /// The parameters of the pool are illegal.
    ///
    /// TODO: this should be a more detailed error.
    InvalidParams(Errno, String),
}

impl PoolConfig {
    /// The maximum length of a memory pool name.
    pub const MAX_NAME_LEN: usize = 25;

    /// Validate a memory pool name.
    #[cold]
    #[tracing::instrument(level = "debug")]
    fn validate_name(name: &str) -> Result<CString, InvalidMemPoolName> {
        if !name.is_ascii() {
            return Err(InvalidMemPoolName::NotAscii(format!(
                "Name must be valid ASCII: {name} is not ASCII."
            )));
        }

        if name.len() > PoolConfig::MAX_NAME_LEN {
            return Err(InvalidMemPoolName::TooLong(format!(
                "Memory pool name must be at most {max} characters of valid ASCII: {name} is too long ({len} > {max}).",
                max = PoolConfig::MAX_NAME_LEN,
                len = name.len()
            )));
        }

        if name.is_empty() {
            return Err(InvalidMemPoolName::Empty(format!(
                "Memory pool name must be at least 1 character of valid ASCII: {name} is too short ({len} == 0).",
                len = name.len()
            )));
        }

        const ASCII_LETTERS: [char; 26 * 2] = [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
            'Z',
        ];

        if !name.starts_with(ASCII_LETTERS) {
            return Err(InvalidMemPoolName::DoesNotStartWithAsciiLetter(format!(
                "Memory pool name must start with a letter: {name} does not start with a letter."
            )));
        }

        let name = CString::new(name).map_err(|_| {
            InvalidMemPoolName::ContainsNullBytes(
                "Memory pool name must not contain null bytes".to_string(),
            )
        })?;

        Ok(name)
    }

    /// Create a new memory pool config.
    ///
    /// TODO: validate the pool parameters.
    #[cold]
    #[tracing::instrument(level = "debug", ret)]
    pub fn new<T: Debug + AsRef<str>>(
        name: T,
        params: PoolParams,
    ) -> Result<PoolConfig, InvalidMemPoolConfig> {
        PoolConfig::new_internal(name.as_ref(), params)
    }

    /// Create a new memory pool config (de-generic)
    ///
    /// TODO: validate the pool parameters.
    #[cold]
    #[tracing::instrument(level = "debug", ret)]
    fn new_internal(name: &str, params: PoolParams) -> Result<PoolConfig, InvalidMemPoolConfig> {
        info!("Creating memory pool config: {name}, {params:?}",);
        let name = match PoolConfig::validate_name(name) {
            Ok(name) => name,
            Err(e) => return Err(InvalidMemPoolConfig::InvalidName(e)),
        };
        Ok(PoolConfig { name, params })
    }

    /// Get the name of the memory pool.
    ///
    /// # Panics
    ///
    /// This function should never panic unless the config has been externally modified.
    /// Don't do that.
    #[cold]
    #[tracing::instrument(level = "trace")]
    pub fn name(&self) -> &str {
        #[allow(clippy::expect_used)]
        // This `expect` is safe because the name is validated at creation time to be a valid,
        // null terminated ASCII string.
        unsafe { CStr::from_ptr(self.name.as_ptr()) }
            .to_str()
            .expect("Pool name is not valid UTF-8")
    }
}

impl Drop for PoolInner {
    #[tracing::instrument(level = "debug")]
    fn drop(&mut self) {
        info!("Freeing memory pool {}", self.config.name());
        unsafe { dpdk_sys::rte_mempool_free(self.as_mut_ptr()) }
    }
}

/// A DPDK Mbuf (memory buffer)
///
/// Usually used to hold an ethernet frame.
///
/// # Note
///
/// This is a 0-cost transparent wrapper around an [`rte_mbuf`] pointer.
/// It can be "safely" transmuted _to_ an `*mut rte_mbuf` under the assumption that
/// standard borrowing rules are observed.
#[repr(transparent)]
#[derive(Debug)]
pub struct Mbuf {
    pub(crate) raw: NonNull<dpdk_sys::rte_mbuf>,
    marker: PhantomData<dpdk_sys::rte_mbuf>,
}

/// TODO: this is possibly poor optimization, we should try bulk dealloc if this slows us down
/// TODO: we need to ensure that we don't call drop on Mbuf when they have been transmitted.
///       The transmit function automatically drops such mbufs and we don't want to double free.
impl Drop for Mbuf {
    fn drop(&mut self) {
        unsafe {
            dpdk_sys::rte_pktmbuf_free_w(self.raw.as_ptr());
        }
    }
}

impl AsRef<[u8]> for Mbuf {
    fn as_ref(&self) -> &[u8] {
        self.raw_data()
    }
}

impl AsMut<[u8]> for Mbuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.raw_data_mut()
    }
}

impl Headroom for Mbuf {
    fn headroom(&self) -> u16 {
        unsafe { rte_pktmbuf_headroom(self.raw.as_ptr()) }
    }
}

impl Tailroom for Mbuf {
    fn tailroom(&self) -> u16 {
        unsafe { rte_pktmbuf_tailroom(self.raw.as_ptr()) }
    }
}

impl Prepend for Mbuf {
    type Error = NotEnoughHeadRoom;

    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        self.prepend_to_headroom(len)
    }
}

impl Append for Mbuf {
    type Error = NotEnoughTailRoom;

    fn append(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        self.append_to_tailroom(len)
    }
}

impl TrimFromStart for Mbuf {
    type Error = MemoryBufferNotLongEnough;

    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        match NonNull::new(unsafe { rte_pktmbuf_adj(self.raw.as_ptr(), len) }) {
            None => Err(MemoryBufferNotLongEnough),
            Some(_) => Ok(self.raw_data_mut()),
        }
    }
}

impl TrimFromEnd for Mbuf {
    type Error = MbufManipulationError;

    fn trim_from_end(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        match unsafe { rte_pktmbuf_trim(self.raw.as_ptr(), len) } {
            0 => Ok(self.raw_data_mut()),
            -1 => Err(MbufManipulationError::NotLongEnough),
            // TODO: this only happens when DPDK has a programmer error (deviation from docs)
            ret => {
                let err = MbufManipulationError::Unknown(ret);
                warn!("DPDK logic error: {err}");
                Err(err)
            }
        }
    }
}

impl Mbuf {
    /// Create a new mbuf from an existing rte_mbuf pointer.
    ///
    /// # Note:
    ///
    /// This function assumes ownership of the data pointed to it.
    ///
    /// # Safety
    ///
    /// This function is unsound if passed an invalid pointer.
    ///
    /// The only defense made against invalid pointers is to check that the pointer is non-null.
    #[must_use]
    #[tracing::instrument(level = "trace", ret)]
    pub(crate) fn new_from_raw(raw: *mut dpdk_sys::rte_mbuf) -> Option<Mbuf> {
        let raw = match NonNull::new(raw) {
            None => {
                debug_assert!(false, "Attempted to create Mbuf from null pointer");
                error!("Attempted to create Mbuf from null pointer");
                return None;
            }
            Some(raw) => raw,
        };

        Some(Mbuf {
            raw,
            marker: PhantomData,
        })
    }

    /// Create a new mbuf from an existing rte_mbuf pointer.
    ///
    /// # Note
    ///
    /// This function assumes ownership of the data pointed to it.
    ///
    /// # Safety
    ///
    /// This function is unsound if passed an invalid pointer.
    #[must_use]
    #[tracing::instrument(level = "trace", ret)]
    pub(crate) unsafe fn new_from_raw_unchecked(raw: *mut dpdk_sys::rte_mbuf) -> Mbuf {
        let raw = unsafe { NonNull::new_unchecked(raw) };
        Mbuf {
            raw,
            marker: PhantomData,
        }
    }

    /// Get an immutable ref to the raw data of an Mbuf
    ///
    /// TODO: deal with multi segment packets
    #[must_use]
    #[tracing::instrument(level = "trace")]
    pub fn raw_data(&self) -> &[u8] {
        debug_assert!(
            unsafe { self.raw.as_ref().annon1.annon1.nb_segs } == 1,
            "multi seg packets not properly supported yet"
        );
        let pkt_data_start = unsafe {
            (self.raw.as_ref().buf_addr as *const u8)
                .offset(self.raw.as_ref().annon1.annon1.data_off as isize)
        };
        unsafe {
            core::slice::from_raw_parts(
                pkt_data_start,
                self.raw.as_ref().annon2.annon1.data_len as usize,
            )
        }
    }

    // TODO: deal with multi seg packets
    /// Get a mutable ref to the raw data of an Mbuf (usually the binary contents of a packet).
    #[must_use]
    #[tracing::instrument(level = "trace")]
    pub fn raw_data_mut(&mut self) -> &mut [u8] {
        unsafe {
            if self.raw.as_ref().annon1.annon1.nb_segs > 1 {
                error!("multi seg packets not supported yet");
            }
            let data_start = self
                .raw
                .as_mut()
                .buf_addr
                .offset(self.raw.as_ref().annon1.annon1.data_off as isize)
                .cast::<u8>();
            from_raw_parts_mut(
                data_start,
                self.raw.as_ref().annon2.annon1.data_len as usize,
            )
        }
    }

    #[tracing::instrument(level = "trace")]
    fn prepend_to_headroom(&mut self, len: u16) -> Result<&mut [u8], NotEnoughHeadRoom> {
        let val = unsafe { rte_pktmbuf_prepend(self.raw.as_mut(), len) };
        match NonNull::new(val) {
            None => Err(NotEnoughHeadRoom),
            Some(_) => Ok(self.raw_data_mut()),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn append_to_tailroom(&mut self, len: u16) -> Result<&mut [u8], NotEnoughTailRoom> {
        let val = unsafe { rte_pktmbuf_append(self.raw.as_mut(), len) };
        match NonNull::new(val) {
            None => Err(NotEnoughTailRoom),
            Some(_) => Ok(self.raw_data_mut()),
        }
    }
}

#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("Not enough head room in memory buffer")]
pub struct NotEnoughHeadRoom;

#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("Not enough tail room in memory buffer")]
pub struct NotEnoughTailRoom;

#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("buffer not long enough")]
pub struct MemoryBufferNotLongEnough;

#[derive(Debug, thiserror::Error)]
pub enum MbufManipulationError {
    #[error("buffer not long enough")]
    NotLongEnough,
    #[error("Undocumented DPDK error: {0}")]
    Unknown(c_int),
}

/// A global memory allocator for DPDK
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct RteAllocator;

unsafe impl Sync for RteAllocator {}

impl RteAllocator {
    /// Create a new, uninitialized [`RteAllocator`].
    pub const fn new_uninitialized() -> Self {
        RteAllocator
    }
}

#[repr(transparent)]
struct RteInit(Cell<bool>);
unsafe impl Sync for RteInit {}
static RTE_INIT: RteInit = const { RteInit(Cell::new(false)) };

thread_local! {
    static RTE_SOCKET: Cell<SocketId> = const { Cell::new(SocketId::ANY) };
    static SWITCHED: Cell<bool> = const { Cell::new(false) };
}

impl RteAllocator {
    pub(crate) fn mark_initialized() {
        if RTE_INIT.0.get() {
            Eal::fatal_error("RTE already initialized");
        }
        RTE_SOCKET.set(SocketId::current());
        RTE_INIT.0.set(true);
        SWITCHED.set(true);
    }

    pub fn assert_initialized() {
        if !RTE_INIT.0.get() {
            Eal::fatal_error("RTE not initialized");
        }
        RTE_SOCKET.set(SocketId::current());
        SWITCHED.set(true);
    }
}

unsafe impl GlobalAlloc for RteAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if SWITCHED.get() {
            unsafe {
                dpdk_sys::rte_malloc_socket(
                    null(),
                    layout.size(),
                    layout.align() as _,
                    RTE_SOCKET.get().0 as _,
                ) as _
            }
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if SWITCHED.get() {
            unsafe {
                dpdk_sys::rte_free(ptr as _);
            }
        } else {
            unsafe {
                System.dealloc(ptr, layout);
            }
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if SWITCHED.get() {
            unsafe {
                dpdk_sys::rte_zmalloc_socket(
                    null(),
                    layout.size(),
                    layout.align() as _,
                    RTE_SOCKET.get().0 as _,
                ) as _
            }
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if SWITCHED.get() {
            unsafe {
                dpdk_sys::rte_realloc_socket(
                    ptr as _,
                    new_size,
                    layout.align() as _,
                    RTE_SOCKET.get().0 as _,
                ) as _
            }
        } else {
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }
}
