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

/// DPDK memory manager: owns every mempool for the life of the [`Eal`](crate::eal::Eal).
///
/// # Ownership model
///
/// A mempool cannot be released on any single holder's schedule. A worker may hold mbufs drawn
/// from it that the owner cannot see, and a PMD holds them until its device is closed. Rather than
/// track that, this crate takes the position that **a mempool lives as long as the EAL does**:
/// pools are created through [`new_pkt_pool`](Self::new_pkt_pool), recorded here, and freed in one
/// place during [`Eal`](crate::eal::Eal) teardown, after every device has been closed.
///
/// What makes that safe is in the type rather than in a runtime check: a [`Pool`] carries the
/// EAL's lifetime, so it cannot outlive the `Eal`, and a handle whose `Drop` would free a mempool
/// against a dismantled EAL is not expressible. Earlier revisions tried an owning `Pool` (freed
/// too early, while a device still held mbufs) and then a reference-counted one (freed too late,
/// after `rte_eal_cleanup`, which needed a runtime flag to make safe). The brand removes both
/// without either.
///
/// # Thread safety
///
/// Creation is safe from any thread -- `rte_pktmbuf_pool_create` is internally locked and the
/// registry is behind a mutex -- so this is reachable through
/// [`EalShared`](crate::eal::EalShared). Releasing is not: it happens once, on the thread that
/// owns the `Eal`, from its `Drop`.
#[derive(Debug)]
#[non_exhaustive]
pub struct Manager {
    /// Every pool created through this manager, in creation order.
    pools: Mutex<Vec<Registered>>,
}

/// A mempool owned by the [`Manager`], plus the leaked config that [`Pool`] handles point at.
#[derive(Debug)]
struct Registered {
    pool: NonNull<dpdk_sys::rte_mempool>,
    /// Leaked deliberately: a `Pool` handle can be cloned freely, so its `config` reference has to
    /// stay valid for as long as any clone. One small allocation per pool, at startup.
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
                // So many sign and bit-width errors in the DPDK API :/
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
    /// Called from [`Eal`](crate::eal::Eal)'s `Drop`, before `rte_eal_cleanup`. Reverse order so a
    /// pool that some later pool was built to feed outlives it.
    ///
    /// # Safety
    ///
    /// Every device must already be closed, which is what returns the PMD's mbufs to their pools.
    /// No [`Pool`] handle can still exist, since every handle borrows the `Eal` being dropped.
    #[cold]
    pub(crate) unsafe fn release_all(&mut self) {
        let mut pools = self.pools.lock();
        for entry in pools.drain(..).rev() {
            info!("Freeing memory pool {name}", name = entry.config.name());
            // SAFETY: from a successful `rte_pktmbuf_pool_create`, and freed exactly once because
            // the `drain` removes it from the registry.
            unsafe { dpdk_sys::rte_mempool_free(entry.pool.as_ptr()) };
        }
    }
}

/// A handle to a DPDK memory pool, valid for as long as the [`Eal`](crate::eal::Eal).
///
/// Cheap to clone, and dropping one does nothing: the mempool belongs to [`Manager`] and is freed
/// during EAL teardown. What the `'eal` brand buys is that a handle cannot outlive the EAL, so the
/// use-after-free a freely-droppable pool invites -- in either direction, too early or too late --
/// is not expressible.
///
/// Deliberately not `Copy`. Today a handle owns nothing, but freeing a pool before EAL teardown --
/// after a reconfiguration, say -- would need to know when its last handle is gone, which a `Copy`
/// type cannot track. Keeping `Copy` off now makes that change non-breaking.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::Pool;
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<Pool>();
/// ```
///
/// Obtained from [`Manager::new_pkt_pool`], reached through the owning `Eal` (`eal.mem`) or its
/// [`EalShared`](crate::eal::EalShared) projection.
///
/// A pool cannot be used after the EAL it came from is gone:
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
/// nor escape the scope that owns it:
///
/// ```compile_fail
/// # use dataplane_dpdk::eal::{self, Eal};
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
    /// Sound to hand to a `dpdk_sys` function that retains it: the pool is released only at EAL
    /// teardown, which this handle's brand proves has not happened.
    pub(crate) fn as_mut_ptr(&self) -> *mut dpdk_sys::rte_mempool {
        self.pool.as_ptr()
    }

    /// The number of mbufs currently checked out of this pool.
    ///
    /// A direct oracle for "was this batch freed exactly once": it rises by the size of an
    /// allocation and must return to its previous value once the mbufs are released. The tests use
    /// it to distinguish a leak (count stays high) from a double free (count drops *below* where it
    /// started, because the same objects were returned to the ring twice).
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

/// A DPDK Mbuf (memory buffer)
///
/// Usually used to hold an ethernet frame.
///
/// # Note
///
/// This is a 0-cost transparent wrapper around an [`dpdk_sys::rte_mbuf`] pointer.
/// It can be "safely" transmuted _to_ an `*mut rte_mbuf` under the assumption that
/// standard borrowing rules are observed.
///
/// # Thread affinity
///
/// An `Mbuf` is `!Send` and `!Sync`: it lives and dies on the thread that received or allocated
/// it. A worker's registered lcore has its own mempool cache, so allocating and freeing on one
/// lcore never touches the pool's shared ring, and keeping every mbuf on its lcore keeps that
/// true. Anything that has to leave the datapath -- a capture, a punted frame -- copies what it
/// needs (headers, metadata, bytes) into an owned value, so a slow consumer can never hold receive
/// pool memory hostage.
///
/// Pool liveness is not the reason; that is the `'eal` brand's job (see below). Adding `Send`
/// later would be non-breaking and removing it would not, so it stays off until something needs
/// it.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::Mbuf;
/// fn assert_send<T: Send>(_: T) {}
/// fn hand_off(mbuf: Mbuf) { assert_send(mbuf); }
/// ```
///
/// The same goes for a whole batch, which is the unit ownership actually travels in:
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::MbufArray;
/// fn assert_send<T: Send>(_: T) {}
/// fn hand_off(batch: MbufArray) { assert_send(batch); }
/// ```
///
/// # Outliving the EAL
///
/// An mbuf is a bare pointer into a [`Pool`]'s memory, and that memory is released during EAL
/// teardown. Before these were branded, both of the following compiled -- and both were a
/// `rte_pktmbuf_free` into a released mempool.
///
/// A whole batch:
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
/// and a single mbuf moved out of one:
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
#[repr(transparent)]
#[derive(Debug)]
pub struct Mbuf<'eal> {
    pub(crate) raw: NonNull<dpdk_sys::rte_mbuf>,
    /// The EAL brand, replacing what was a `PhantomData<rte_mbuf>` ownership marker.
    ///
    /// An mbuf is a bare pointer into a [`Pool`]'s memory. Without this, an `MbufArray` could
    /// outlive the `Eal` whose teardown freed that memory, and its `Drop` would then call
    /// `rte_pktmbuf_free` into a released mempool. Both forms of that were reachable from safe
    /// code before the brand: the array directly, and a single `Mbuf` moved out of one.
    eal: PhantomData<&'eal ()>,
}

// `Mbuf` is deliberately neither `Send` nor `Sync`; see "Thread affinity" above. It holds a
// `NonNull`, so both auto traits are already off and there is no impl to remove.

/// Failure to deep-copy an [`Mbuf`] (the destination pool could not supply a fresh mbuf).
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug, thiserror::Error)]
#[error("failed to deep-copy mbuf: source pool exhausted")]
pub struct MbufCopyError;

impl<'eal> DeepCopy for Mbuf<'eal> {
    type Error = MbufCopyError;

    /// Copy the entire segment chain into independent buffers from the same pool.
    fn deep_copy(&self) -> Result<Mbuf<'eal>, MbufCopyError> {
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
    /// The capacity of the array: the maximum number of mbufs it can hold.
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
    /// Returns the mbuf back (so its ownership is not lost) if the array is already at capacity.
    pub fn try_push(&mut self, mbuf: Mbuf<'eal>) -> Result<(), Mbuf<'eal>> {
        self.bufs.try_push(mbuf).map_err(|err| err.element())
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
            // SAFETY: the caller guarantees each pointer is a valid, singly-owned mbuf and that
            // there are at most `N` of them, so the push cannot exceed capacity.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pool_tests {
    use super::*;
    use crate::with_eal;

    /// Pool names are process-global in DPDK, so each test needs its own.
    ///
    /// Created through the shared projection rather than the owning `Eal`, because a unit test
    /// cannot know which thread initialised the EAL -- which is exactly why mempool creation is
    /// on [`EalShared`](crate::eal::EalShared) and releasing is not.
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

    /// The regression this whole design exists for.
    ///
    /// An owning `Pool` freed its mempool when the handle went out of scope, so mbufs drawn from
    /// it became dangling -- a SIGSEGV inside `rte_pktmbuf_free` during teardown, after every
    /// assertion had already passed. The handle now owns nothing, so dropping it is a no-op and
    /// the mbufs stay valid.
    #[test]
    #[with_eal]
    fn mbufs_outlive_the_pool_handle_that_allocated_them() {
        let mut mbufs = {
            let pool = pool("outlive_pool", 511);
            let mbufs = pool.alloc_bulk(4).expect("alloc_bulk failed");
            assert_eq!(mbufs.len(), 4);
            mbufs
            // `pool` goes out of scope here.
        };

        for mbuf in &mut mbufs {
            let room = mbuf.tailroom();
            assert!(room > 0, "mbuf has no tailroom");
            mbuf.append(16).expect("append failed");
        }
        assert_eq!(mbufs.len(), 4);
        drop(mbufs);
    }

    /// Cloning a `Pool` yields another name for the same mempool, and neither clone owns it.
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

    /// A bulk allocation larger than an `MbufArray` is rejected without touching DPDK, and one
    /// larger than the pool fails cleanly rather than partially.
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
