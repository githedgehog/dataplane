// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK memory management wrappers.

use crate::socket::SocketId;
use alloc::format;
use alloc::string::String;
use arrayvec::ArrayVec;
use core::ffi::c_uint;
use core::ffi::{CStr, c_int};
use core::fmt::{Debug, Display};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::ptr::null_mut;
use core::slice::from_raw_parts_mut;
use errno::Errno;
use tracing::{error, info, warn};

use dpdk_sys::{
    rte_pktmbuf_adj, rte_pktmbuf_append, rte_pktmbuf_headroom, rte_pktmbuf_prepend,
    rte_pktmbuf_tailroom, rte_pktmbuf_trim,
};
use net::buffer::{
    Append, DeepCopy, Headroom, NotWritable, PacketLength, Prepend, Tailroom, TrimFromEnd,
    TrimFromStart, TryAsMut,
};
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
            && std::ptr::eq(
                core::ptr::from_ref(unsafe { self.as_ref() }),
                core::ptr::from_ref(unsafe { other.as_ref() }),
            )
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

    /// Allocate `num` mbufs from this pool as a single [`MbufArray`].
    ///
    /// # Errors
    ///
    /// Returns [`MbufAllocError::TooMany`] if `num` exceeds the [`MbufArray`] capacity
    /// ([`MBUF_BURST`]), or [`MbufAllocError::Exhausted`] if the pool does not currently have `num`
    /// free mbufs.  The DPDK bulk allocator is all-or-nothing: on failure no mbufs are allocated.
    pub fn alloc_bulk(&self, num: usize) -> Result<MbufArray, MbufAllocError> {
        if num > MBUF_BURST {
            return Err(MbufAllocError::TooMany {
                requested: num,
                capacity: MBUF_BURST,
            });
        }
        // Fill a raw, inline pointer array first and only wrap the pointers in `Mbuf`s once the
        // allocation has succeeded.  An `Mbuf` holds a `NonNull`, so materializing one from a
        // null placeholder (as the previous implementation did via `transmute`) is instant
        // undefined behavior; building from the post-success pointers avoids that entirely.
        let mut raw = [null_mut::<dpdk_sys::rte_mbuf>(); MBUF_BURST];
        let ret = unsafe {
            dpdk_sys::rte_pktmbuf_alloc_bulk(self.0.as_mut_ptr(), raw.as_mut_ptr(), num as c_uint)
        };
        if ret != 0 {
            // Per the DPDK contract this is `-ENOENT` with no mbufs retrieved; `raw` is still all
            // null and never becomes an `Mbuf`.
            return Err(MbufAllocError::Exhausted { requested: num });
        }
        // SAFETY: on success the first `num` entries are valid, non-null mbuf pointers owned by us,
        // and `num <= MBUF_BURST` is the array capacity.
        Ok(unsafe { MbufArray::from_raw_ptrs(&raw[..num]) })
    }
}

/// Failure to bulk-allocate mbufs from a [`Pool`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum MbufAllocError {
    /// The pool did not currently have enough free mbufs to satisfy the request.
    #[error("the pool could not supply {requested} mbufs (exhausted)")]
    Exhausted {
        /// The number of mbufs that were requested.
        requested: usize,
    },
    /// More mbufs were requested than an [`MbufArray`] can hold.
    #[error("requested {requested} mbufs but an MbufArray holds at most {capacity}")]
    TooMany {
        /// The number of mbufs that were requested.
        requested: usize,
        /// The maximum an [`MbufArray`] can hold ([`MBUF_BURST`]).
        capacity: usize,
    },
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
    /// one: <var>n</var> = 2<sup>q</sup> - 1
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
/// This is a 0-cost transparent wrapper around an [`dpdk_sys::rte_mbuf`] pointer.
/// It can be "safely" transmuted _to_ an `*mut rte_mbuf` under the assumption that
/// standard borrowing rules are observed.
#[repr(transparent)]
#[derive(Debug)]
pub struct Mbuf {
    pub(crate) raw: NonNull<dpdk_sys::rte_mbuf>,
    marker: PhantomData<dpdk_sys::rte_mbuf>,
}

// dpdk_sys::rte_mbuf is Send but not Sync since it is a plain C pointer
unsafe impl Send for Mbuf {}

/// Failure to deep-copy an [`Mbuf`] (the destination pool could not supply a fresh mbuf).
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("failed to deep-copy mbuf: source pool exhausted")]
pub struct MbufCopyError;

impl DeepCopy for Mbuf {
    type Error = MbufCopyError;

    /// Produce an independent deep copy of this mbuf (and its whole segment chain), allocated from
    /// the same pool the original came from.
    ///
    /// Unlike a shared/indirect clone, the copy aliases none of the original's data.
    fn deep_copy(&self) -> Result<Mbuf, MbufCopyError> {
        // SAFETY: `self.raw` is a live mbuf; reading its originating `pool` pointer is sound.
        let pool = unsafe { self.raw.as_ref().pool };
        // A length of `u32::MAX` copies from offset 0 through the end of the packet.
        let copy = unsafe { dpdk_sys::rte_pktmbuf_copy(self.raw.as_ptr(), pool, 0, u32::MAX) };
        match NonNull::new(copy) {
            // SAFETY: `rte_pktmbuf_copy` returned a freshly allocated mbuf chain that we now own.
            Some(_) => Ok(unsafe { Mbuf::new_from_raw_unchecked(copy) }),
            None => Err(MbufCopyError),
        }
    }
}

/// TODO: this is possibly poor optimization, we should try bulk dealloc if this slows us down
/// TODO: we need to ensure that we don't call drop on Mbuf when they have been transmitted.
///       The transmit function automatically drops such mbufs and we don't want to double free.
impl Drop for Mbuf {
    fn drop(&mut self) {
        unsafe {
            dpdk_sys::rte_pktmbuf_free(self.raw.as_ptr());
        }
    }
}

impl AsRef<[u8]> for Mbuf {
    fn as_ref(&self) -> &[u8] {
        self.raw_data()
    }
}

impl PacketLength for Mbuf {
    fn packet_len(&self) -> usize {
        // `pkt_len` is the total across all segments; `data_len` (what `as_ref` exposes) is only the
        // head segment.  For a single-segment mbuf the two are equal.
        // SAFETY: `self.raw` is a live mbuf for the lifetime of `&self`, and `pkt_len` is the
        // active member of the union (always valid to read on a pkt mbuf).
        unsafe { self.raw.as_ref().annon2.annon1.pkt_len as usize }
    }
}

impl TryAsMut for Mbuf {
    fn try_as_mut(&mut self) -> Result<&mut [u8], NotWritable> {
        if self.is_writable() {
            Ok(self.raw_data_mut())
        } else {
            Err(NotWritable)
        }
    }
}

impl Mbuf {
    /// Returns `true` if this mbuf may be mutated in place: it must be directly owned (neither an
    /// indirect nor an external-buffer mbuf) and have a reference count of exactly one.  A shared
    /// mbuf's data is aliased by other holders, so writing through it would corrupt them.
    #[must_use]
    fn is_writable(&self) -> bool {
        // SAFETY: `self.raw` is a live mbuf for the lifetime of `&self`.
        let attached = unsafe { self.raw.as_ref() }.ol_flags
            & (dpdk_sys::RTE_MBUF_F_INDIRECT | dpdk_sys::RTE_MBUF_F_EXTERNAL)
            != 0;
        !attached && unsafe { dpdk_sys::rte_mbuf_refcnt_read(self.raw.as_ptr()) } == 1
    }
}

impl Mbuf {
    /// The mbuf's receive offload flags (`ol_flags`): the bitset of `RTE_MBUF_F_RX_*` markers the
    /// PMD set on this packet (RSS-hash-valid, FDIR-id-valid, checksum status, VLAN-stripped, ...).
    #[must_use]
    pub fn ol_flags(&self) -> u64 {
        // SAFETY: `self.raw` is a live mbuf for the lifetime of `&self`.
        unsafe { self.raw.as_ref() }.ol_flags
    }

    /// The RSS hash the NIC computed for this packet, or `None` if the NIC did not report one
    /// (`RTE_MBUF_F_RX_RSS_HASH` clear).
    ///
    /// This is the value the receive-side-scaling redirection table is indexed by, so reading it is
    /// how software reproduces (and audits) the NIC's queue choice.
    #[must_use]
    pub fn rss_hash(&self) -> Option<u32> {
        if self.ol_flags() & u64::from(dpdk_sys::RTE_MBUF_F_RX_RSS_HASH) == 0 {
            return None;
        }
        // SAFETY: the flag above certifies `hash.rss` is the active union member; `self.raw` is a
        // live mbuf for the lifetime of `&self`.
        Some(unsafe { self.raw.as_ref().annon2.annon1.annon2.hash.rss })
    }

    /// The flow-director / `MARK`-action identifier the NIC attached to this packet, or `None` if
    /// the NIC did not set one (`RTE_MBUF_F_RX_FDIR_ID` clear).
    ///
    /// A flow rule's `MARK` action surfaces here, so this is the channel by which a packet trapped
    /// to software can carry hardware-stamped context (for example a pipeline epoch) up from the
    /// datapath.
    #[must_use]
    pub fn rx_mark(&self) -> Option<u32> {
        if self.ol_flags() & u64::from(dpdk_sys::RTE_MBUF_F_RX_FDIR_ID) == 0 {
            return None;
        }
        // SAFETY: the flag above certifies the FDIR id (`hash.fdir.hi`) is valid; `self.raw` is a
        // live mbuf for the lifetime of `&self`.
        Some(unsafe { self.raw.as_ref().annon2.annon1.annon2.hash.fdir.hi })
    }

    /// The flow `META` value a `SET_META` action attached to this packet, or `None` if absent.
    ///
    /// This is a second hardware-to-software channel alongside [`rx_mark`](Self::rx_mark): it is
    /// carried in a registered mbuf dynamic field rather than the flow-director id, so a trapped
    /// packet can convey more stamped context than the single `MARK` field allows. Requires
    /// [`rte_flow_dynf_metadata_register`](dpdk_sys::rte_flow_dynf_metadata_register) to have
    /// succeeded (it installs the dynfield offset/mask read here); returns `None` until then.
    #[must_use]
    pub fn rx_meta(&self) -> Option<u32> {
        // SAFETY: reading the value of these globals (set by rte_flow_dynf_metadata_register) is a
        // plain copy; no reference into the static is taken.
        let mask = unsafe { dpdk_sys::rte_flow_dynf_metadata_mask };
        if mask == 0 || self.ol_flags() & mask == 0 {
            return None;
        }
        let offs = unsafe { dpdk_sys::rte_flow_dynf_metadata_offs };
        // SAFETY: `offs` is the byte offset of the registered metadata dynfield within the mbuf
        // (the contract of rte_flow_dynf_metadata_register); the flag check above certifies the
        // field is populated; `self.raw` is a live mbuf for the lifetime of `&self`.
        let ptr = unsafe {
            self.raw
                .as_ptr()
                .cast::<u8>()
                .add(offs as usize)
                .cast::<u32>()
        };
        Some(unsafe { ptr.read_unaligned() })
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

    /// Consume the [`Mbuf`], returning the raw [`dpdk_sys::rte_mbuf`] pointer and suppressing the
    /// [`Drop`] that would otherwise free it.
    ///
    /// The caller takes over responsibility for the mbuf.
    /// This is the correct way to hand an mbuf to a `dpdk_sys` function that assumes ownership
    /// (for example [`dpdk_sys::rte_eth_tx_burst`], where the PMD frees transmitted mbufs): keeping
    /// the [`Mbuf`] around would let its [`Drop`] free the same pointer a second time.
    #[must_use]
    pub(crate) fn into_raw(self) -> *mut dpdk_sys::rte_mbuf {
        let raw = self.raw.as_ptr();
        core::mem::forget(self);
        raw
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

/// The default (and maximum) number of mbufs in an [`MbufArray`].
///
/// This is the burst size: packets are received, processed, and transmitted in batches of at most
/// this many.  It is the capacity of a default [`MbufArray`] and the chunk size used when bursting
/// to a transmit queue.
pub const MBUF_BURST: usize = 64;

/// An owning, bulk-freed, fixed-capacity array of [`Mbuf`]s.
///
/// This is the unit of allocation, receive, and transmit for these bindings: [`Pool::alloc_bulk`]
/// produces one, [`crate::queue::rx::RxQueue::receive`] returns one, and
/// [`crate::queue::tx::TxQueue::transmit`] consumes one (returning the packets it could not send).
///
/// # Why a dedicated, inline type
///
/// Packet processing is entirely batch-oriented, so the array is backed by an inline
/// [`ArrayVec`] of `N` slots (default [`MBUF_BURST`]) rather than a heap `Vec`: a burst never
/// allocates.  `N` is fixed at compile time; the array does not grow, so a batch larger than `N`
/// must be processed in `N`-sized chunks.
///
/// Rust's [`Drop`] runs per value, so dropping an array of `Mbuf` would otherwise free each mbuf
/// with its own `rte_pktmbuf_free` call.  An `MbufArray` instead releases everything it still owns
/// in a single [`rte_pktmbuf_free_bulk`](dpdk_sys::rte_pktmbuf_free_bulk) call on drop, which is
/// both faster and the only way to batch the release.  Making the batch the ownership unit also
/// removes whole classes of leaks and double-frees from the receive and transmit paths.
///
/// The contained [`Mbuf`]s are reachable as a slice via [`Deref`], and can be moved out by value
/// with [`IntoIterator`]; an `Mbuf` taken out individually is freed on its own when dropped.
#[derive(Debug)]
pub struct MbufArray<const N: usize = MBUF_BURST> {
    bufs: ArrayVec<Mbuf, N>,
}

impl<const N: usize> MbufArray<N> {
    /// The capacity of the array: the maximum number of mbufs it can hold.
    pub const CAPACITY: usize = N;

    /// Create an empty [`MbufArray`].
    #[must_use]
    pub fn new_empty() -> MbufArray<N> {
        MbufArray {
            bufs: ArrayVec::new(),
        }
    }

    /// The number of mbufs in the array.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bufs.len()
    }

    /// Returns `true` if the array contains no mbufs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }

    /// Append an mbuf to the array.
    ///
    /// # Errors
    ///
    /// Returns the mbuf back (so its ownership is not lost) if the array is already at capacity.
    pub fn try_push(&mut self, mbuf: Mbuf) -> Result<(), Mbuf> {
        self.bufs.try_push(mbuf).map_err(|err| err.element())
    }

    /// Build an array from raw mbuf pointers.
    ///
    /// # Safety
    ///
    /// Every pointer in `ptrs` must be a live, non-null mbuf that is solely owned by the caller,
    /// and `ptrs.len()` must not exceed `N`.
    pub(crate) unsafe fn from_raw_ptrs(ptrs: &[*mut dpdk_sys::rte_mbuf]) -> MbufArray<N> {
        debug_assert!(ptrs.len() <= N, "more mbufs than the array can hold");
        let mut bufs = ArrayVec::new();
        for &raw in ptrs {
            // SAFETY: the caller guarantees each pointer is a valid, singly-owned mbuf and that
            // there are at most `N` of them, so the push cannot exceed capacity.
            unsafe {
                bufs.push_unchecked(Mbuf::new_from_raw_unchecked(raw));
            }
        }
        MbufArray { bufs }
    }
}

impl<const N: usize> Default for MbufArray<N> {
    fn default() -> MbufArray<N> {
        MbufArray::new_empty()
    }
}

impl<const N: usize> Deref for MbufArray<N> {
    type Target = [Mbuf];

    fn deref(&self) -> &[Mbuf] {
        &self.bufs
    }
}

impl<const N: usize> DerefMut for MbufArray<N> {
    fn deref_mut(&mut self) -> &mut [Mbuf] {
        &mut self.bufs
    }
}

impl<const N: usize> IntoIterator for MbufArray<N> {
    type Item = Mbuf;
    type IntoIter = arrayvec::IntoIter<Mbuf, N>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Move the mbufs out, leaving an empty array behind.  When `self` then drops, the bulk
        // free below sees an empty array and does nothing; ownership of each `Mbuf` has passed to
        // the iterator, so they are freed individually if dropped.
        core::mem::take(&mut self.bufs).into_iter()
    }
}

impl<'a, const N: usize> IntoIterator for &'a MbufArray<N> {
    type Item = &'a Mbuf;
    type IntoIter = core::slice::Iter<'a, Mbuf>;

    fn into_iter(self) -> Self::IntoIter {
        self.bufs.iter()
    }
}

impl<'a, const N: usize> IntoIterator for &'a mut MbufArray<N> {
    type Item = &'a mut Mbuf;
    type IntoIter = core::slice::IterMut<'a, Mbuf>;

    fn into_iter(self) -> Self::IntoIter {
        self.bufs.iter_mut()
    }
}

impl<const N: usize> Drop for MbufArray<N> {
    fn drop(&mut self) {
        if self.bufs.is_empty() {
            return;
        }
        let count = self.bufs.len();
        // SAFETY: `Mbuf` is `#[repr(transparent)]` over `NonNull<rte_mbuf>`, so the `ArrayVec<Mbuf>`
        // backing storage is layout-identical to an array of `*mut rte_mbuf`.  Every element is a
        // live, singly-owned mbuf, so freeing the whole run in bulk frees each exactly once.
        unsafe {
            dpdk_sys::rte_pktmbuf_free_bulk(
                self.bufs.as_mut_ptr().cast::<*mut dpdk_sys::rte_mbuf>(),
                count as c_uint,
            );
            // The mbufs are freed; drop the wrappers without running `Mbuf::drop` (which would
            // free them a second time).
            self.bufs.set_len(0);
        }
    }
}
