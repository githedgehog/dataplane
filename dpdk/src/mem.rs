//! DPDK memory management wrappers.

use alloc::format;
use alloc::string::String;
use crate::socket::SocketId;
use dpdk_sys::*;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, CStr};
use core::fmt::{Debug, Display};
use core::marker::PhantomData;
use core::ptr::NonNull;
use tracing::{debug, error, warn};

use alloc::sync::Arc;

#[repr(transparent)]
#[derive(Debug)]
/// DPDK memory manager
pub struct Manager {
    _private: PhantomData<()>,
}

impl Manager {
    #[tracing::instrument(level = "debug")]
    pub(crate) fn init() -> Manager {
        debug!("Initializing DPDK memory manager");
        Manager {
            _private: PhantomData,
        }
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        debug!("Closing DPDK memory manager");
    }
}

#[repr(transparent)]
#[derive(Debug, Clone)]
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
pub struct PoolHandle(Arc<PoolInner>);

impl PartialEq for PoolHandle {
    fn eq(&self, other: &Self) -> bool {
        self.inner() == other.inner()
    }
}

impl Eq for PoolHandle {}

impl PartialEq for PoolInner {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
            && core::ptr::from_ref(unsafe { self.as_ref() })
                == core::ptr::from_ref(unsafe { other.as_ref() })
    }
}

impl Eq for PoolInner {}

impl Display for PoolHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Pool({})", self.name())
    }
}

impl PoolHandle {
    pub(crate) fn inner(&self) -> &PoolInner {
        &self.0
    }

    #[tracing::instrument(level = "debug")]
    /// Create a new packet memory pool.
    pub fn new_pkt_pool(config: PoolConfig) -> Result<PoolHandle, InvalidMemPoolConfig> {
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
                #[allow(clippy::expect_used)]
                // This `expect` is safe because the error string is guaranteed to be valid
                // null-terminated ASCII,
                let err_str = err_str.to_str().expect("valid UTF-8");
                let err_msg = format!("Failed to create mbuf pool: {err_str}; (errno: {errno})");
                error!("{err_msg}");
                return Err(InvalidMemPoolConfig::InvalidParams(errno, err_msg));
            }
            Some(pool) => pool,
        };

        Ok(PoolHandle(Arc::new(PoolInner {
            config,
            pool: UnsafeCell::new(pool),
            _marker: PhantomData,
        })))
    }

    /// Get the name of the memory pool.
    pub fn name(&self) -> &str {
        self.config().name()
    }

    /// Get the configuration of the memory pool.
    pub fn config(&self) -> &PoolConfig {
        &self.0.config
    }
}

/// This value is RAII-managed and must never implement `Copy` and can likely never implement
/// `Clone` unless the internal representation is changed to use a reference-counted pointer.
#[derive(Debug)]
pub(crate) struct PoolInner {
    pub(crate) config: PoolConfig,
    pub(crate) pool: UnsafeCell<NonNull<rte_mempool>>,
    _marker: PhantomData<rte_mempool>,
}

impl PoolInner {
    /// Get an immutable reference to the raw DPDK [`rte_mempool`].
    ///
    /// # Safety
    ///
    /// <div class="warning">
    ///
    /// See the safety note on [`PoolInner::as_ptr`].
    ///
    /// </div>
    pub(crate) unsafe fn as_ref(&self) -> &rte_mempool {
        (*self.pool.get()).as_ref()
    }

    /// Get a mutable pointer to the raw DPDK [`rte_mempool`].
    ///
    /// # Safety
    ///
    /// <div class="warning">
    /// This function is very easy to use in an unsound way!
    ///
    /// You need to be careful when handing the return value to a [`dpdk_sys`] function or data
    /// structure.
    /// In all cases you need to associate any copy of `*mut rte_mempool` back to the [`PoolHandle`]
    /// object's reference count.
    /// Failing that risks [`Drop`] ([RAII]) tearing down the [`PoolHandle`] while it is still in use.
    ///
    /// If you duplicate the pointer and fail to associate it back with the outer [`PoolHandle`] object's
    /// reference count, you will risk tearing down the memory pool while it is still in use.
    ///
    /// </div>
    ///
    /// [RAII]: https://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization
    pub(crate) unsafe fn as_ptr(&self) -> *mut rte_mempool {
        (*self.pool.get()).as_ptr()
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
            size: (1 << 13) - 1,
            cache_size: 512,
            private_size: 0,
            data_size: 2048,
            socket_id: SocketId::current(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Memory pool config
pub struct PoolConfig {
    name: [c_char; PoolConfig::MAX_NAME_LEN + 1],
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Ways in which a memory pool config can be invalid.
pub enum InvalidMemPoolConfig {
    /// The name of the pool is illegal.
    InvalidName(InvalidMemPoolName),
    /// The parameters of the pool are illegal.
    ///
    /// TODO: this should be a more detailed error.
    InvalidParams(i32, String),
}

impl PoolConfig {
    /// The maximum length of a memory pool name.
    pub const MAX_NAME_LEN: usize = 25;

    #[tracing::instrument(level = "trace")]
    /// Validate a memory pool name.
    fn validate_name<Name: Debug + AsRef<str>>(
        name: Name,
    ) -> Result<[c_char; PoolConfig::MAX_NAME_LEN + 1], InvalidMemPoolName> {
        let name_ref = name.as_ref();
        if !name_ref.is_ascii() {
            return Err(InvalidMemPoolName::NotAscii(format!(
                "Name must be valid ASCII: {name_ref} is not ASCII."
            )));
        }

        if name_ref.len() > PoolConfig::MAX_NAME_LEN {
            return Err(InvalidMemPoolName::TooLong(
                format!(
                    "Memory pool name must be at most {max} characters of valid ASCII: {name_ref} is too long ({len} > {max}).",
                    max = PoolConfig::MAX_NAME_LEN,
                    len=name_ref.len()
                )
            ));
        }

        if name_ref.is_empty() {
            return Err(InvalidMemPoolName::Empty(
                format!("Memory pool name must be at least 1 character of valid ASCII: {name_ref} is too short ({len} == 0).", len=name_ref.len()))
            );
        }

        const ASCII_LETTERS: [char; 26 * 2] = [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
            'Z',
        ];

        if !name_ref.starts_with(ASCII_LETTERS) {
            return Err(InvalidMemPoolName::DoesNotStartWithAsciiLetter(
                format!("Memory pool name must start with a letter: {name_ref} does not start with a letter."))
            );
        }

        if name_ref.contains('\0') {
            return Err(InvalidMemPoolName::ContainsNullBytes(format!(
                "Memory pool name must not contain null bytes: {name_ref} contains a null byte."
            )));
        }

        let mut name_chars = [0 as c_char; PoolConfig::MAX_NAME_LEN + 1];
        for (i, c) in name_ref.chars().enumerate() {
            name_chars[i] = c as c_char;
        }
        Ok(name_chars)
    }

    /// Create a new memory pool config.
    ///
    /// TODO: validate the pool parameters.
    #[tracing::instrument(level = "debug")]
    pub fn new<T: Debug + AsRef<str>>(
        name: T,
        params: PoolParams,
    ) -> Result<PoolConfig, InvalidMemPoolConfig> {
        debug!(
            "Creating memory pool config: {name}, {params:?}",
            name = name.as_ref()
        );
        let name = match PoolConfig::validate_name(name.as_ref()) {
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
    #[tracing::instrument(level = "trace")]
    pub fn name(&self) -> &str {
        #[allow(clippy::expect_used)]
        // This `expect` is safe because the name is validated at creation time to be valid a valid,
        // null terminated ASCII string.
        unsafe { CStr::from_ptr(self.name.as_ptr()) }
            .to_str()
            .expect("Pool name is not valid UTF-8")
    }
}

impl Drop for PoolInner {
    #[tracing::instrument(level = "debug")]
    fn drop(&mut self) {
        debug!("Freeing memory pool {}", self.config.name());
        unsafe { rte_mempool_free(self.as_ptr()) }
    }
}

/// A DPDK Mbuf (memory buffer)
/// 
/// Usually used to hold an ethernet frame.
#[repr(transparent)]
pub struct Mbuf {
    pub(crate) raw: NonNull<rte_mbuf>,
    _phantom: PhantomData<rte_mbuf>,
}

/// TODO: this is poor optimization and possibly unsafe
impl Drop for Mbuf {
    fn drop(&mut self) {
        unsafe {
            rte_pktmbuf_free_bulk(&mut self.raw.as_ptr(), 1);
        }
    }
}

impl Mbuf {
    /// Create a new mbuf from an existing rte_mbuf pointer.
    ///
    /// # Note, this function assumes ownership of the data pointed to by raw.
    ///
    /// # Safety
    ///
    /// This function is is unsafe if passed an invalid pointer.
    ///
    /// The only defense made against invalid pointers here is the use of `NonNull::new` to ensure
    /// the pointer is not null.
    ///
    ///
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new_from_raw(raw: *mut rte_mbuf) -> Option<Mbuf> {
        let raw = match NonNull::new(raw) {
            None => {
                warn!("Attempted to create Mbuf from null pointer");
                return None;
            }
            Some(raw) => raw,
        };

        Some(Mbuf {
            raw,
            _phantom: PhantomData,
        })
    }

    /// Get an immutable ref to the raw data of an Mbuf
    pub fn raw_data(&self) -> &[u8] {
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

    /// Get a mutable ref to the raw data of an Mbuf
    pub fn raw_data_mut(&mut self) -> &mut [u8] {
        unsafe {
            let data_start = self
                .raw
                .as_mut()
                .buf_addr
                .offset(self.raw.as_ref().annon1.annon1.data_off as isize)
                as *mut u8;
            core::slice::from_raw_parts_mut(
                data_start,
                self.raw.as_ref().annon2.annon1.data_len as usize,
            )
        }
    }
}
