// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK memory management wrappers.

use crate::socket::SocketId;
use crate::sync::Mutex;
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
    Append, DeepCopy, Headroom, PacketLength, Prepend, Tailroom, TrimFromEnd, TrimFromStart,
};
use std::ffi::CString;

#[cfg(test)]
mod buffer_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod copy_tests;

/// Owns mempools until EAL teardown, after their ports have closed.
/// Creation is synchronized and available through [`EalShared`](crate::eal::EalShared).
#[derive(Debug)]
#[non_exhaustive]
pub struct Manager {
    /// Every pool created through this manager, in creation order.
    pools: Mutex<Vec<Registered>>,
}

/// An EAL-owned mempool and its shared configuration.
#[derive(Debug)]
struct Registered {
    pool: NonNull<dpdk_sys::rte_mempool>,
    /// Leaked once per pool to provide a stable reference for every cloned handle.
    config: &'static PoolConfig,
}

// SAFETY: the pointer is only used through DPDK's internally-synchronized mempool entry points,
// and is freed exactly once, from the thread that owns the `Eal`.
unsafe impl Send for Registered {}

impl Manager {
    pub(crate) fn init() -> Manager {
        Manager {
            pools: Mutex::new(Vec::new()),
        }
    }

    /// Create a packet mempool that lives as long as the EAL.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMemPoolConfig`] if DPDK refuses the parameters -- most often a name
    /// already in use, or not enough memory to back the pool.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn new_pkt_pool(&self, config: PoolConfig) -> Result<Pool<'_>, InvalidMemPoolConfig> {
        let raw = unsafe {
            dpdk_sys::rte_pktmbuf_pool_create(
                config.name.as_ptr(),
                config.params.size,
                config.params.cache_size,
                config.params.private_size,
                config.params.data_size,
                // DPDK takes a signed socket ID; preserve the bit pattern for SOCKET_ID_ANY.
                config.params.socket_id.as_c_uint() as c_int,
            )
        };

        let Some(pool) = NonNull::new(raw) else {
            let errno = unsafe { dpdk_sys::rte_errno_get() };
            let c_err_str = unsafe { dpdk_sys::rte_strerror(errno) };
            // SAFETY: `rte_strerror` always returns a valid NUL-terminated string.
            let err_str = unsafe { CStr::from_ptr(c_err_str) }.to_string_lossy();
            let err_msg = format!("Failed to create mbuf pool: {err_str}; (errno: {errno})");
            error!("{err_msg}");
            return Err(InvalidMemPoolConfig::InvalidParams(
                Errno::from(errno),
                err_msg,
            ));
        };

        let config: &'static PoolConfig = alloc::boxed::Box::leak(alloc::boxed::Box::new(config));
        self.pools.lock().push(Registered { pool, config });

        Ok(Pool {
            pool,
            config,
            eal: PhantomData,
        })
    }

    /// Free every mempool, in reverse creation order.
    ///
    /// Called during [`Eal`](crate::eal::Eal) teardown, before `rte_eal_cleanup`.
    ///
    /// # Safety
    ///
    /// All devices must be closed and their mbufs returned to their pools.
    /// No pool or mbuf handle may be used after this call.
    #[cold]
    pub(crate) unsafe fn release_all(&mut self) {
        for entry in self.pools.get_mut().drain(..).rev() {
            info!("Freeing memory pool {name}", name = entry.config.name());
            // SAFETY: from a successful `rte_pktmbuf_pool_create`, and freed exactly once because
            // the `drain` removes it from the registry.
            unsafe { dpdk_sys::rte_mempool_free(entry.pool.as_ptr()) };
        }
    }
}

/// A cloneable handle to an EAL-owned mempool. Dropping a handle leaves the pool allocated.
/// The EAL lifetime prevents use after teardown.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::Pool;
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<Pool>();
/// ```
///
/// ```compile_fail,E0505
/// # use dataplane_dpdk::eal::Eal;
/// # use dataplane_dpdk::mem::{PoolConfig, PoolParams};
/// fn use_after_eal(eal: Eal) {
///     let config = PoolConfig::new("p", PoolParams::default()).expect("config");
///     let pool = eal.mem.new_pkt_pool(config).expect("pool");
///     drop(eal);
///     let _ = pool.name();
/// }
/// ```
///
/// ```compile_fail,E0713
/// # use dataplane_dpdk::eal::Eal;
/// # use dataplane_dpdk::mem::{Pool, PoolConfig, PoolParams};
/// fn escape(eal: Eal) -> Pool<'static> {
///     let config = PoolConfig::new("p", PoolParams::default()).expect("config");
///     eal.mem.new_pkt_pool(config).expect("pool")
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Pool<'eal> {
    pool: NonNull<dpdk_sys::rte_mempool>,
    config: &'static PoolConfig,
    eal: PhantomData<&'eal ()>,
}

// SAFETY: an immutable handle to a mempool whose allocate/free entry points DPDK synchronizes
// internally: the per-lcore cache is keyed by `rte_lcore_id()`, and non-EAL threads
// (`LCORE_ID_ANY`) bypass the cache for the multi-producer/multi-consumer ring underneath.
unsafe impl Send for Pool<'_> {}
unsafe impl Sync for Pool<'_> {}

impl PartialEq for Pool<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.pool == other.pool
    }
}

impl Eq for Pool<'_> {}

impl Display for Pool<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Pool({})", self.name())
    }
}

impl<'eal> Pool<'eal> {
    /// Get the name of the memory pool.
    #[must_use]
    pub fn name(&self) -> &str {
        self.config.name()
    }

    /// Get the configuration of the memory pool.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        self.config
    }

    /// A mutable pointer to the raw DPDK [`rte_mempool`](dpdk_sys::rte_mempool).
    ///
    /// Valid until EAL teardown; callers must ensure any native user finishes before then.
    pub(crate) fn as_mut_ptr(&self) -> *mut dpdk_sys::rte_mempool {
        self.pool.as_ptr()
    }

    /// The number of mbufs currently checked out of this pool.
    #[must_use]
    pub fn in_use(&self) -> u32 {
        // SAFETY: a live mempool for the lifetime of this handle; reads accounting only.
        unsafe { dpdk_sys::rte_mempool_in_use_count(self.pool.as_ptr()) }
    }

    /// Allocate `num` mbufs as an owning batch.
    ///
    /// # Errors
    ///
    /// Returns [`MbufAllocError::TooMany`] above [`MBUF_BURST`], or
    /// [`MbufAllocError::Exhausted`] if the pool cannot supply the entire batch.
    pub fn alloc_bulk(&self, num: usize) -> Result<MbufArray<'eal>, MbufAllocError> {
        if num == 0 {
            return Ok(MbufArray::new_empty());
        }
        if num > MBUF_BURST {
            return Err(MbufAllocError::TooMany {
                requested: num,
                capacity: MBUF_BURST,
            });
        }
        // Wrap pointers as non-null `Mbuf`s only after allocation succeeds.
        let mut raw = [null_mut::<dpdk_sys::rte_mbuf>(); MBUF_BURST];
        let ret = unsafe {
            dpdk_sys::rte_pktmbuf_alloc_bulk(self.as_mut_ptr(), raw.as_mut_ptr(), num as c_uint)
        };
        if ret != 0 {
            // Bulk allocation is all-or-nothing; no mbufs need freeing on failure.
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
    /// The pool cannot supply the entire batch.
    #[error("the pool could not supply {requested} mbufs (exhausted)")]
    Exhausted {
        /// Requested mbuf count.
        requested: usize,
    },
    /// More mbufs were requested than an [`MbufArray`] can hold.
    #[error("requested {requested} mbufs but an MbufArray holds at most {capacity}")]
    TooMany {
        /// Requested mbuf count.
        requested: usize,
        /// Batch capacity ([`MBUF_BURST`]).
        capacity: usize,
    },
}

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
            // Fixed room for jumbo frames; MTU changes do not resize existing pools.
            data_size: 12_188,
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

/// A DPDK Mbuf (memory buffer)
///
/// Usually used to hold an ethernet frame.
///
/// # Note
///
/// This is a 0-cost transparent wrapper around an [`dpdk_sys::rte_mbuf`] pointer.
///
/// Mbufs and batches borrow the EAL to keep their pool alive.
/// Batches from [`RxQueue::receive`](crate::queue::rx::RxQueue::receive) borrow the device,
/// so received packets must be released or transmitted before it stops.
///
/// An allocated batch cannot outlive the EAL:
///
/// ```compile_fail,E0505
/// # use dataplane_dpdk::eal::Eal;
/// # use dataplane_dpdk::mem::{PoolConfig, PoolParams};
/// fn batch_outlives_eal(eal: Eal) {
///     let config = PoolConfig::new("p", PoolParams::default()).expect("config");
///     let pool = eal.mem.new_pkt_pool(config).expect("pool");
///     let mbufs = pool.alloc_bulk(4).expect("alloc");
///     drop(eal);
///     drop(mbufs);
/// }
/// ```
///
/// Neither can an individual mbuf:
///
/// ```compile_fail,E0505
/// # use dataplane_dpdk::eal::Eal;
/// # use dataplane_dpdk::mem::{PoolConfig, PoolParams};
/// fn one_mbuf_outlives_eal(eal: Eal) {
///     let config = PoolConfig::new("p", PoolParams::default()).expect("config");
///     let pool = eal.mem.new_pkt_pool(config).expect("pool");
///     let mbufs = pool.alloc_bulk(1).expect("alloc");
///     let single = mbufs.into_iter().next().expect("one");
///     drop(eal);
///     drop(single);
/// }
/// ```
///
/// A received batch prevents its device from stopping:
///
/// ```compile_fail,E0505
/// # use dataplane_dpdk::dev::{Dev, Started};
/// # use dataplane_dpdk::queue::rx::RxQueueIndex;
/// fn hold_past_stop(dev: Dev<Started>) {
///     let mut queues = dev.take_queues().expect("queues");
///     let mut rxq = queues.take_rx(RxQueueIndex(0)).expect("rx 0");
///     let batch = rxq.receive();
///     drop(rxq);
///     drop(queues);
///     let _stopped = dev.stop();
///     drop(batch);
/// }
/// ```
///
/// # Thread affinity
///
/// `Mbuf` is `!Send` and `!Sync`, keeping packet processing on the receiving or allocating thread.
/// Keeping allocation and release on one lcore favors its local mempool cache.
/// Copy data needed by another thread into an owned value so slow consumers do not retain mbufs.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::Mbuf;
/// fn assert_send<T: Send>(_: T) {}
/// fn hand_off(mbuf: Mbuf) { assert_send(mbuf); }
/// ```
///
/// [`MbufArray`] has the same thread affinity:
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::MbufArray;
/// fn assert_send<T: Send>(_: T) {}
/// fn hand_off(batch: MbufArray) { assert_send(batch); }
/// ```
#[repr(transparent)]
#[derive(Debug)]
pub struct Mbuf<'eal> {
    pub(crate) raw: NonNull<dpdk_sys::rte_mbuf>,
    /// Keeps the EAL alive while this mbuf can be used.
    eal: PhantomData<&'eal ()>,
}

/// Failure to allocate an independent [`Mbuf`] with the source layout.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum MbufCopyError {
    #[error("failed to deep-copy mbuf: source pool exhausted")]
    Exhausted,
    #[error("source buffer has {source_size} bytes; pool buffers have {pool_size}")]
    IncompatibleLayout { source_size: u16, pool_size: u16 },
}

impl<'eal> DeepCopy for Mbuf<'eal> {
    type Error = MbufCopyError;

    /// Copy each segment from its own pool, preserving headroom, tailroom, and boundaries.
    fn deep_copy(&self) -> Result<Mbuf<'eal>, MbufCopyError> {
        // SAFETY: `self` owns a live chain. Copies are independently owned, and each
        // segment is linked once. The head owns the partial chain if allocation fails.
        unsafe {
            let mut source = self.raw.as_ref();
            let mut copy = Self::copy_segment(source)?;
            let mut tail = copy.raw;
            while let Some(next) = source.next.as_ref() {
                source = next;
                let segment = Self::copy_segment(source)?;
                let raw = segment.raw;
                tail.as_mut().next = segment.into_raw();
                tail = raw;
                copy.raw.as_mut().annon1.annon1.nb_segs += 1;
                copy.raw.as_mut().annon2.annon1.pkt_len += u32::from(source.annon2.annon1.data_len);
            }
            Ok(copy)
        }
    }
}

impl<'eal> Mbuf<'eal> {
    /// Copy a single segment without its successors.
    ///
    /// # Safety
    ///
    /// `source`, its data, and its pool must be live and valid throughout the copy.
    unsafe fn copy_segment(source: &dpdk_sys::rte_mbuf) -> Result<Mbuf<'eal>, MbufCopyError> {
        // SAFETY: the caller guarantees a live source and pool. Allocation gives us
        // independent storage; the size check below keeps the byte copy in bounds.
        unsafe {
            let raw = NonNull::new(dpdk_sys::rte_pktmbuf_alloc(source.pool))
                .ok_or(MbufCopyError::Exhausted)?;
            let mut copy = Mbuf {
                raw,
                eal: PhantomData,
            };
            let dest = copy.raw.as_mut();
            let source_size = source.annon2.annon1.buf_len;
            let pool_size = dest.annon2.annon1.buf_len;
            // Indirect or external buffers may differ from their pool's data room.
            // Changing buf_len would persist when the mbuf returns to the pool.
            if source_size != pool_size {
                return Err(MbufCopyError::IncompatibleLayout {
                    source_size,
                    pool_size,
                });
            }

            let offset = source.annon1.annon1.data_off;
            let len = source.annon2.annon1.data_len;
            dest.annon1.annon1.data_off = offset;
            dest.annon2.annon1.data_len = len;
            dest.annon2.annon1.pkt_len = u32::from(len);
            core::ptr::copy_nonoverlapping(
                source.buf_addr.cast::<u8>().add(usize::from(offset)),
                dest.buf_addr.cast::<u8>().add(usize::from(offset)),
                usize::from(len),
            );

            // Copy packet metadata as rte_pktmbuf_copy does, retaining the new buffer's ownership.
            dest.annon1.annon1.port = source.annon1.annon1.port;
            dest.annon2.annon1.annon1 = source.annon2.annon1.annon1;
            dest.annon2.annon1.vlan_tci = source.annon2.annon1.vlan_tci;
            dest.annon2.annon1.vlan_tci_outer = source.annon2.annon1.vlan_tci_outer;
            dest.annon2.annon1.annon2 = source.annon2.annon1.annon2;
            dest.annon3.tx_offload = source.annon3.tx_offload;
            dpdk_sys::rte_mbuf_dynfield_copy(dest, source);
            dest.ol_flags |=
                source.ol_flags & !(dpdk_sys::RTE_MBUF_F_INDIRECT | dpdk_sys::RTE_MBUF_F_EXTERNAL);
            Ok(copy)
        }
    }
}

impl Drop for Mbuf<'_> {
    fn drop(&mut self) {
        unsafe {
            dpdk_sys::rte_pktmbuf_free(self.raw.as_ptr());
        }
    }
}

impl AsRef<[u8]> for Mbuf<'_> {
    fn as_ref(&self) -> &[u8] {
        self.raw_data()
    }
}

impl AsMut<[u8]> for Mbuf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.raw_data_mut()
    }
}

impl PacketLength for Mbuf<'_> {
    fn packet_len(&self) -> usize {
        // SAFETY: `self.raw` is live and `pkt_len` is valid for packet mbufs.
        // It includes all segments; `data_len` covers only the head.
        unsafe { self.raw.as_ref().annon2.annon1.pkt_len as usize }
    }

    fn is_chained(&self) -> bool {
        // SAFETY: `self.raw` is live and `nb_segs` is valid for packet mbufs.
        unsafe { self.raw.as_ref().annon1.annon1.nb_segs > 1 }
    }
}

impl Headroom for Mbuf<'_> {
    fn headroom(&self) -> u16 {
        unsafe { rte_pktmbuf_headroom(self.raw.as_ptr()) }
    }
}

impl Tailroom for Mbuf<'_> {
    fn tailroom(&self) -> u16 {
        unsafe { rte_pktmbuf_tailroom(self.last_segment().as_ptr()) }
    }
}

impl Prepend for Mbuf<'_> {
    type Error = NotEnoughHeadRoom;

    fn prepend(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        self.prepend_to_headroom(len)
    }
}

impl Append for Mbuf<'_> {
    type Error = NotEnoughTailRoom;

    fn append(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        self.append_to_tailroom(len)
    }
}

impl TrimFromStart for Mbuf<'_> {
    type Error = MemoryBufferNotLongEnough;

    fn trim_from_start(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        match NonNull::new(unsafe { rte_pktmbuf_adj(self.raw.as_ptr(), len) }) {
            None => Err(MemoryBufferNotLongEnough),
            Some(_) => Ok(self.raw_data_mut()),
        }
    }
}

impl TrimFromEnd for Mbuf<'_> {
    type Error = MbufManipulationError;

    fn trim_from_end(&mut self, len: u16) -> Result<&mut [u8], Self::Error> {
        match unsafe { rte_pktmbuf_trim(self.raw.as_ptr(), len) } {
            // SAFETY: the tail is live and borrowed through `&mut self`.
            0 => Ok(unsafe { self.segment_data_mut(self.last_segment()) }),
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

impl<'eal> Mbuf<'eal> {
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
    pub(crate) unsafe fn new_from_raw_unchecked(raw: *mut dpdk_sys::rte_mbuf) -> Mbuf<'eal> {
        let raw = unsafe { NonNull::new_unchecked(raw) };
        Mbuf {
            raw,
            eal: PhantomData,
        }
    }

    /// Transfer ownership to the caller as a raw pointer, without freeing the mbuf.
    #[must_use]
    pub(crate) fn into_raw(self) -> *mut dpdk_sys::rte_mbuf {
        let raw = self.raw.as_ptr();
        core::mem::forget(self);
        raw
    }

    /// Get the contiguous bytes of the head segment.
    #[must_use]
    #[tracing::instrument(level = "trace")]
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

    /// Get mutable access to the head segment.
    #[must_use]
    #[tracing::instrument(level = "trace")]
    pub fn raw_data_mut(&mut self) -> &mut [u8] {
        // SAFETY: the head is live and borrowed through `&mut self`.
        unsafe { self.segment_data_mut(self.raw) }
    }

    fn last_segment(&self) -> NonNull<dpdk_sys::rte_mbuf> {
        // SAFETY: a live packet always has at least one segment.
        unsafe { NonNull::new_unchecked(dpdk_sys::rte_pktmbuf_lastseg(self.raw.as_ptr())) }
    }

    // SAFETY: `segment` must belong to this chain.
    unsafe fn segment_data_mut(&mut self, segment: NonNull<dpdk_sys::rte_mbuf>) -> &mut [u8] {
        unsafe {
            let seg = segment.as_ref();
            let start = seg
                .buf_addr
                .cast::<u8>()
                .add(seg.annon1.annon1.data_off as usize);
            from_raw_parts_mut(start, seg.annon2.annon1.data_len as usize)
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
        let tail = self.last_segment();
        let val = unsafe { rte_pktmbuf_append(self.raw.as_mut(), len) };
        match NonNull::new(val) {
            None => Err(NotEnoughTailRoom),
            // SAFETY: the tail is live and borrowed through `&mut self`.
            Some(_) => Ok(unsafe { self.segment_data_mut(tail) }),
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

/// Default batch capacity and queue burst size.
pub const MBUF_BURST: usize = 64;

/// An owning batch of at most `N` mbufs, stored inline.
///
/// Drop frees the remaining mbufs in one bulk call. Iteration by value transfers
/// ownership to the iterator, whose remaining mbufs are freed individually.
#[derive(Debug)]
pub struct MbufArray<'eal, const N: usize = MBUF_BURST> {
    bufs: ArrayVec<Mbuf<'eal>, N>,
}

impl<'eal, const N: usize> MbufArray<'eal, N> {
    /// Maximum number of mbufs.
    pub const CAPACITY: usize = N;

    /// Create an empty [`MbufArray`].
    #[must_use]
    pub fn new_empty() -> MbufArray<'eal, N> {
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
    /// Returns the mbuf if the array is full.
    pub fn try_push(&mut self, mbuf: Mbuf<'eal>) -> Result<(), Mbuf<'eal>> {
        self.bufs.try_push(mbuf).map_err(|err| err.element())
    }

    /// Free every mbuf held, in one call, and leave the array empty.
    ///
    /// Shared by [`Drop`] and [`MbufArray::refill_with`]. `ArrayVec::clear` would also be
    /// correct -- each `Mbuf` frees itself exactly once -- but it frees them one at a time, and
    /// the whole point of holding them in an array is that the PMD can take them back in bulk.
    fn free_all(&mut self) {
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

    /// Empty the array into an iterator without moving the array itself.
    ///
    /// [`IntoIterator`] takes `self` by value, which for a 64-slot array is half a kilobyte
    /// moved every time a caller wants to walk a burst. A worker that owns one array and refills
    /// it per poll needs to drain it in place instead.
    pub fn drain_all(&mut self) -> arrayvec::Drain<'_, Mbuf<'eal>, N> {
        self.bufs.drain(..)
    }

    /// Hand the array's whole storage to `fill`, and take its word for how many slots it wrote.
    ///
    /// This exists so a receive can write mbuf pointers straight into the array rather than into
    /// a stack buffer that is then copied in and returned by value. On a poll that receives
    /// nothing those copies are the entire cost of the call, and an idle worker spent half of all
    /// its cycles on them.
    ///
    /// Anything already in the array is dropped first, which frees those mbufs.
    ///
    /// # Safety
    ///
    /// `fill` must write `n` live, non-null mbufs, owned solely by this array from then on, into
    /// the first `n` slots of the buffer it is given, where `n` is what it returns. It is told
    /// the capacity and must not write beyond it.
    pub(crate) unsafe fn refill_with(
        &mut self,
        fill: impl FnOnce(*mut *mut dpdk_sys::rte_mbuf, u16) -> usize,
    ) {
        self.free_all();
        // `Mbuf` is `repr(transparent)` over a `NonNull<rte_mbuf>` plus a zero-sized brand, so
        // the array's storage has the layout of `[*mut rte_mbuf; N]` and can be handed to C.
        let slots = self.bufs.as_mut_ptr().cast::<*mut dpdk_sys::rte_mbuf>();
        let capacity = u16::try_from(N).unwrap_or(u16::MAX);
        let written = fill(slots, capacity);
        debug_assert!(written <= N, "filler wrote {written} mbufs into {N} slots");
        // SAFETY: the caller's contract is that `written` slots now hold live, singly-owned
        // mbufs, and the debug assertion above catches a filler that overran in testing.
        unsafe { self.bufs.set_len(written) };
    }

    /// Build an array from raw mbuf pointers.
    ///
    /// # Safety
    ///
    /// Every pointer in `ptrs` must be a live, non-null mbuf that is solely owned by the caller,
    /// and `ptrs.len()` must not exceed `N`.
    pub(crate) unsafe fn from_raw_ptrs(ptrs: &[*mut dpdk_sys::rte_mbuf]) -> MbufArray<'eal, N> {
        debug_assert!(ptrs.len() <= N, "more mbufs than the array can hold");
        let mut bufs = ArrayVec::new();
        for &raw in ptrs {
            // SAFETY: the caller guarantees valid, owned mbufs and enough capacity.
            unsafe {
                bufs.push_unchecked(Mbuf::new_from_raw_unchecked(raw));
            }
        }
        MbufArray { bufs }
    }
}

impl<const N: usize> Default for MbufArray<'_, N> {
    fn default() -> Self {
        MbufArray::new_empty()
    }
}

impl<'eal, const N: usize> Deref for MbufArray<'eal, N> {
    type Target = [Mbuf<'eal>];

    fn deref(&self) -> &[Mbuf<'eal>] {
        &self.bufs
    }
}

impl<'eal, const N: usize> DerefMut for MbufArray<'eal, N> {
    fn deref_mut(&mut self) -> &mut [Mbuf<'eal>] {
        &mut self.bufs
    }
}

impl<'eal, const N: usize> IntoIterator for MbufArray<'eal, N> {
    type Item = Mbuf<'eal>;
    type IntoIter = arrayvec::IntoIter<Mbuf<'eal>, N>;

    fn into_iter(mut self) -> Self::IntoIter {
        // Leave the batch empty so Drop cannot free the mbufs owned by the iterator.
        core::mem::take(&mut self.bufs).into_iter()
    }
}

impl<'a, 'eal, const N: usize> IntoIterator for &'a MbufArray<'eal, N> {
    type Item = &'a Mbuf<'eal>;
    type IntoIter = core::slice::Iter<'a, Mbuf<'eal>>;

    fn into_iter(self) -> Self::IntoIter {
        self.bufs.iter()
    }
}

impl<'a, 'eal, const N: usize> IntoIterator for &'a mut MbufArray<'eal, N> {
    type Item = &'a mut Mbuf<'eal>;
    type IntoIter = core::slice::IterMut<'a, Mbuf<'eal>>;

    fn into_iter(self) -> Self::IntoIter {
        self.bufs.iter_mut()
    }
}

impl<const N: usize> Drop for MbufArray<'_, N> {
    fn drop(&mut self) {
        self.free_all();
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use crate::with_eal;

    /// Pool names are process-global in DPDK, so each test needs its own.
    fn pool(name: &str, size: u32) -> Pool<'static> {
        let shared = crate::test_support::start_eal();
        let config = PoolConfig::new(
            name,
            PoolParams {
                size,
                cache_size: 0,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("invalid pool config: {e:?}"));
        shared
            .mem()
            .new_pkt_pool(config)
            .unwrap_or_else(|e| panic!("failed to create pool: {e:?}"))
    }

    #[test]
    #[with_eal]
    fn mbufs_outlive_the_pool_handle_that_allocated_them() {
        let mut mbufs = {
            let pool = pool("outlive_pool", 511);
            let mbufs = pool.alloc_bulk(4).expect("alloc_bulk failed");
            assert_eq!(mbufs.len(), 4);
            mbufs
        };

        for mbuf in &mut mbufs {
            let room = mbuf.tailroom();
            assert!(room > 0, "mbuf has no tailroom");
            mbuf.append(16).expect("append failed");
        }
        assert_eq!(mbufs.len(), 4);
        drop(mbufs);
    }

    #[test]
    #[with_eal]
    fn pool_handles_are_clones_of_one_mempool() {
        let first = pool("copy_pool", 511);
        let second = first.clone();
        assert_eq!(first, second);
        assert_eq!(first.as_mut_ptr(), second.as_mut_ptr());
        assert_eq!(first.name(), "copy_pool");

        let a = first.alloc_bulk(2).expect("alloc from first");
        let b = second.alloc_bulk(2).expect("alloc from second");
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
    }

    #[test]
    #[with_eal]
    fn distinct_pools_are_not_equal() {
        let a = pool("distinct_a", 511);
        let b = pool("distinct_b", 511);
        assert_ne!(a, b);
    }

    /// Refilling an array that still holds mbufs returns the old ones exactly once.
    ///
    /// `refill_with` exists to avoid copying the array, so it writes over storage that may still
    /// be occupied. Forgetting to free what was there leaks it, and "it did not crash" would pass
    /// on that; occupancy accounting catches it, and break-testing confirms it does.
    ///
    /// It does *not* catch the opposite mistake. Freeing the same mbufs twice leaves
    /// `rte_mempool_in_use_count` unchanged here, not below the baseline -- verified by removing
    /// the `set_len(0)` from `free_all`, which makes every array double-free and makes no test in
    /// this module fail. Detecting a double free needs a mempool built with debug checks, which this one is not.
    #[test]
    #[with_eal]
    fn refilling_a_full_array_frees_the_old_mbufs_exactly_once() {
        let pool = pool("refill_accounting", 511);
        let baseline = pool.in_use();

        let mut burst = pool.alloc_bulk(8).expect("alloc_bulk failed");
        assert_eq!(
            pool.in_use(),
            baseline + 8,
            "allocation should be accounted"
        );

        // Stand in for the PMD: hand back four freshly allocated mbufs, written straight into
        // the array's storage the way `rte_eth_rx_burst` would.
        let fresh = pool.alloc_bulk(4).expect("alloc_bulk failed");
        assert_eq!(pool.in_use(), baseline + 12);
        let mut raw: Vec<*mut dpdk_sys::rte_mbuf> =
            fresh.iter().map(|mbuf| mbuf.raw.as_ptr()).collect();
        // The array must not free what it is about to hand over.
        core::mem::forget(fresh);

        // SAFETY: `raw` holds four live mbufs that nothing else now owns, and four is under the
        // capacity the filler is offered.
        unsafe {
            burst.refill_with(|slots, capacity| {
                assert!(raw.len() <= capacity as usize);
                core::ptr::copy_nonoverlapping(raw.as_mut_ptr(), slots, raw.len());
                raw.len()
            });
        }

        assert_eq!(
            burst.len(),
            4,
            "the array should hold what the filler wrote"
        );
        assert_eq!(
            pool.in_use(),
            baseline + 4,
            "the eight it held must be back in the pool -- higher means a leak, lower a double free"
        );

        drop(burst);
        assert_eq!(pool.in_use(), baseline, "and the four go back too");
    }

    /// `drain_all` empties the array in place and hands ownership to the caller.
    ///
    /// The point of it is that the array is not moved, so the mbufs have to leave by the
    /// iterator rather than with the array. What this pins down is that the emptied array owns
    /// nothing afterwards and the drained mbufs are still live -- see the note above on what
    /// occupancy accounting can and cannot see.
    #[test]
    #[with_eal]
    fn drain_all_empties_in_place_and_transfers_ownership() {
        let pool = pool("drain_all_accounting", 511);
        let baseline = pool.in_use();

        let mut burst = pool.alloc_bulk(6).expect("alloc_bulk failed");
        let drained: Vec<_> = burst.drain_all().collect();

        assert_eq!(drained.len(), 6);
        assert!(burst.is_empty(), "the array is emptied, not consumed");
        assert_eq!(
            pool.in_use(),
            baseline + 6,
            "draining moves ownership; it must not free anything"
        );

        drop(burst);
        assert_eq!(
            pool.in_use(),
            baseline + 6,
            "the emptied array owns nothing, so dropping it frees nothing"
        );

        drop(drained);
        assert_eq!(
            pool.in_use(),
            baseline,
            "the drained mbufs free exactly once"
        );
    }

    /// A failed bulk allocation must leave the pool's full capacity available.
    #[test]
    #[with_eal]
    fn alloc_bulk_rejects_oversized_requests() {
        let pool = pool("oversized_pool", 15);
        match pool.alloc_bulk(MBUF_BURST + 1) {
            Err(MbufAllocError::TooMany {
                requested,
                capacity,
            }) => {
                assert_eq!(requested, MBUF_BURST + 1);
                assert_eq!(capacity, MBUF_BURST);
            }
            other => panic!("expected TooMany, got {other:?}"),
        }
        match pool.alloc_bulk(MBUF_BURST) {
            Err(MbufAllocError::Exhausted { requested }) => assert_eq!(requested, MBUF_BURST),
            other => panic!("expected Exhausted, got {other:?}"),
        }
        let ok = pool.alloc_bulk(15).expect("pool should still be full");
        assert_eq!(ok.len(), 15);
    }
}
