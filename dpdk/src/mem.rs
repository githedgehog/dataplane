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
use core::ffi::{c_int, CStr};
use core::fmt::{Debug, Display};
use core::intrinsics::transmute;
use core::marker::PhantomData;
use core::ptr::null;
use core::ptr::null_mut;
use core::ptr::NonNull;
use core::slice::from_raw_parts_mut;
use dpdk_sys::*;
use errno::Errno;
use tracing::{error, info, warn};

use crate::lcore::LCoreId;
// unfortunately, we need the standard library to swap allocators
use allocator_api2::alloc::AllocError;
use allocator_api2::alloc::Allocator;
use std::alloc::System;
use std::cell::UnsafeCell;
use std::ffi::CString;
use std::marker::PhantomPinned;

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
            rte_pktmbuf_pool_create(
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
                let errno = unsafe { wrte_errno() };
                let c_err_str = unsafe { rte_strerror(errno) };
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
            .map(|_| unsafe { transmute(null_mut::<rte_mbuf>()) })
            .collect();
        let ret = unsafe {
            rte_pktmbuf_alloc_bulk(
                self.0.as_mut_ptr(),
                transmute::<*mut Mbuf, *mut *mut rte_mbuf>(mbufs.as_mut_ptr()),
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
    pub(crate) pool: NonNull<rte_mempool>,
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
    pub(crate) unsafe fn as_ref(&self) -> &rte_mempool {
        self.pool.as_ref()
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
    pub(crate) unsafe fn as_mut_ptr(&self) -> *mut rte_mempool {
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
    /// The size of the memory pool.
    pub size: u32,
    /// The size of the memory pool cache.
    pub cache_size: u32,
    /// The size of the private data in each memory pool object.
    pub private_size: u16,
    /// The size of the data in each memory pool object.
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Memory pool config
pub struct PoolConfig {
    name: CString,
    params: PoolParams,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Ways in which a memory pool name can be invalid.
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
            return Err(InvalidMemPoolName::TooLong(
                format!(
                    "Memory pool name must be at most {max} characters of valid ASCII: {name} is too long ({len} > {max}).",
                    max = PoolConfig::MAX_NAME_LEN,
                    len = name.len()
                )
            ));
        }

        if name.is_empty() {
            return Err(InvalidMemPoolName::Empty(
                format!("Memory pool name must be at least 1 character of valid ASCII: {name} is too short ({len} == 0).", len = name.len()))
            );
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
        unsafe { rte_mempool_free(self.as_mut_ptr()) }
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
    pub(crate) raw: NonNull<rte_mbuf>,
    marker: PhantomData<rte_mbuf>,
}

/// TODO: this is possibly poor optimization, we should try bulk dealloc if this slows us down
/// TODO: we need to ensure that we don't call drop on Mbuf when they have been transmitted.
///       The transmit function automatically drops such mbufs and we don't want to double free.
impl Drop for Mbuf {
    fn drop(&mut self) {
        unsafe {
            rte_pktmbuf_free(self.raw.as_ptr());
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
    pub(crate) fn new_from_raw(raw: *mut rte_mbuf) -> Option<Mbuf> {
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
    pub(crate) unsafe fn new_from_raw_unchecked(raw: *mut rte_mbuf) -> Mbuf {
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
}

#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, Copy, Clone)]
pub struct RteAllocator;

unsafe impl Sync for RteAllocator {}

impl RteAllocator {
    pub const fn uninit() -> Self {
        RteAllocator
    }
}

pub enum Pending {}
pub enum Activated {}

pub trait AllocatorState {}

impl AllocatorState for Pending {}
impl AllocatorState for Activated {}

impl<T: AllocatorState + 'static> AllocatorState for PhantomData<T> {}

#[repr(transparent)]
struct RteInit(Cell<bool>);

unsafe impl Sync for RteInit {}

static RTE_INIT: RteInit = const { RteInit(Cell::new(false)) };

thread_local! {
    static RTE_SOCKET: Cell<SocketId> = const { Cell::new(SocketId::ANY) };
}

impl RteAllocator {
    #[tracing::instrument(level = "info")]
    pub(crate) fn mark_initialized() {
        if RTE_INIT.0.get() {
            Eal::fatal_error("RTE already initialized");
        }
        RTE_SOCKET.set(SocketId::current());
        RTE_INIT.0.set(true);
    }

    #[tracing::instrument(level = "debug")]
    pub fn assert_initialized() {
        if !RTE_INIT.0.get() {
            Eal::fatal_error("RTE not initialized");
        }
        RTE_SOCKET.set(SocketId::current());
    }
}

unsafe impl GlobalAlloc for RteAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if RTE_INIT.0.get() {
            rte_malloc_socket(
                null(),
                layout.size(),
                layout.align() as _,
                RTE_SOCKET.get().0 as _,
            ) as _
        } else {
            System.alloc(layout)
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if RTE_INIT.0.get() {
            rte_free(ptr as _);
        } else {
            System.dealloc(ptr, layout);
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if RTE_INIT.0.get() {
            rte_zmalloc_socket(
                null(),
                layout.size(),
                layout.align() as _,
                RTE_SOCKET.get().0 as _,
            ) as _
        } else {
            System.alloc_zeroed(layout)
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if RTE_INIT.0.get() {
            rte_realloc_socket(
                ptr as _,
                new_size,
                layout.align() as _,
                RTE_SOCKET.get().0 as _,
            ) as _
        } else {
            System.realloc(ptr, layout, new_size)
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
#[repr(transparent)]
pub(crate) struct SystemAllocator;

unsafe impl Allocator for SystemAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match NonNull::new(unsafe { System.alloc(layout) }) {
            None => Err(AllocError),
            Some(ptr) => Ok(unsafe {
                NonNull::new_unchecked(from_raw_parts_mut(ptr.as_ptr(), layout.size()))
            }),
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        System.dealloc(ptr.as_ptr(), layout);
    }
}
