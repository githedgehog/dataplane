// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK memory management wrappers.

use crate::socket::SocketId;
use alloc::format;
use alloc::string::String;
use arrayvec::ArrayVec;
use concurrency::reclaim::{Attendants, Reclaimer};
use concurrency::sync::{Arc, Mutex, OnceLock};
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

/// How long [`Manager::shutdown`] waits for workers to release the pools they may be using.
///
/// Generous, because the alternative to waiting is leaking: a worker that has not reached a safe
/// point may still hold mbufs, and freeing their pool underneath it is the exact failure the
/// quiescence protocol exists to prevent.
const SHUTDOWN_GRACE: core::time::Duration = core::time::Duration::from_secs(5);

/// DPDK memory manager: owns the authority over mempool lifetime.
///
/// # Ownership model
///
/// Releasing a mempool is not safe on any single holder's schedule -- a worker may hold mbufs
/// drawn from it with nothing the owner can see, and a PMD holds them until its device is closed.
/// So release is deferred to quiescence, through
/// [`concurrency::reclaim`](concurrency::reclaim): the manager holds the live set, and a retired
/// pool is freed only once every worker has passed a safe point since its retirement. That also
/// buys drop affinity -- `rte_mempool_free` runs on the thread that owns the [`Eal`](crate::eal::Eal),
/// never on whichever worker happened to drop the last handle.
///
/// This is why `mem` is absent from [`EalShared`](crate::eal::EalShared): a
/// [`Reclaimer`] is `!Sync` by design, so the manager is too, and it is
/// reachable only through the owning `Eal`.
///
/// # Why creation does not go through here
///
/// [`Pool::new_pkt_pool`] is a free function that registers into a `Sync` inbox, and the manager
/// *adopts* from that inbox. Requiring the manager for creation would mean pool creation could
/// only happen on the owner's thread, which is more than DPDK asks (`rte_pktmbuf_pool_create` is
/// internally locked) and would make a pool unobtainable from a test that does not happen to be
/// running on whichever thread initialised the EAL. Between creation and adoption the inbox holds
/// the handle, so a pool is never unowned.
#[derive(Debug)]
#[non_exhaustive]
pub struct Manager {
    /// `Option` so [`shutdown`](Self::shutdown) can deliberately leak whatever it could not
    /// release: dropping the reclaimer after `rte_eal_cleanup` has run would free mempools too
    /// late, so on a failed drain the whole thing is forgotten instead.
    reclaimer: Option<Reclaimer<Pool>>,
}

impl Manager {
    pub(crate) fn init() -> Manager {
        Manager {
            // Built here, on the thread calling `rte_eal_init`, which is the main lcore and
            // therefore the thread every destructor should run on.
            reclaimer: Some(Reclaimer::new()),
        }
    }

    /// Move any newly-created pools from the inbox into the live set.
    fn adopt(&self) {
        let Some(reclaimer) = self.reclaimer.as_ref() else {
            return;
        };
        for pool in pending().lock().drain(..) {
            reclaimer.register(pool);
        }
    }

    /// Enrol workers in the quiescence protocol.
    ///
    /// A worker must call [`at_safe_point`](concurrency::reclaim::Attendant::at_safe_point)
    /// between units of work, at a point where it holds no mbuf. That declaration is what permits
    /// a retired pool to be freed; see [`concurrency::reclaim`] for the discipline in full.
    ///
    /// Returns `None` only after [`shutdown`](Self::shutdown).
    #[must_use]
    pub fn attendants(&self) -> Option<Attendants<'_, Pool>> {
        self.adopt();
        Some(self.reclaimer.as_ref()?.attendants())
    }

    /// Retire `pool`, so it is freed once no worker can still be using it.
    ///
    /// Returns `true` if it was live. Nothing is freed synchronously.
    pub fn retire(&self, pool: &Pool) -> bool {
        self.adopt();
        let Some(reclaimer) = self.reclaimer.as_ref() else {
            return false;
        };
        reclaimer.retire_unless(|entry| entry != pool) > 0
    }

    /// Free anything retired that no worker can still be using.
    pub fn reclaim(&self) {
        self.adopt();
        if let Some(reclaimer) = self.reclaimer.as_ref() {
            reclaimer.reclaim();
        }
    }

    /// Retire every pool and wait for it to be freed, then give up ownership.
    ///
    /// Called from [`Eal`](crate::eal::Eal)'s `Drop`, before `rte_eal_cleanup`.
    ///
    /// Whatever could not be released within [`SHUTDOWN_GRACE`] is leaked on purpose, and loudly:
    /// a worker still holding mbufs is exactly the case where freeing is worse than leaking. The
    /// reclaimer is forgotten either way, so drop glue cannot free a mempool after
    /// `rte_eal_cleanup` has already torn the EAL down.
    #[cold]
    pub(crate) fn shutdown(&mut self) {
        self.adopt();
        let Some(reclaimer) = self.reclaimer.take() else {
            return;
        };
        match reclaimer.drain_until(std::time::Instant::now() + SHUTDOWN_GRACE) {
            Ok(()) => info!("all memory pools released"),
            Err(still_held) => error!(
                "{still_held}; a worker did not reach a safe point within {SHUTDOWN_GRACE:?}, so                  these pools are leaked rather than freed while it may still be reading them"
            ),
        }
        // Never dropped: see the note on the field.
        core::mem::forget(reclaimer);
    }
}

/// A reference-counted handle to a DPDK memory pool.
///
/// # Ownership
///
/// `Pool` is `Clone` over an `Arc`, so every holder keeps the mempool alive: a device that was
/// configured with it (through [`RxQueueConfig::pool`](crate::queue::rx::RxQueueConfig)), and a
/// batch of mbufs in transit between threads (see [`Consigned`]). The mempool is freed when the
/// last handle drops -- which, because [`Manager`] tracks a handle to every pool and releases it
/// only once no worker can still be using it, cannot happen before every device is closed and
/// every worker has reached a safe point.
///
/// That ordering is the whole point. A mempool is not safe to free on any single owner's
/// schedule: the PMD keeps mbufs drawn from it until the device is stopped *and* closed
/// ([`rte_eth_dev_close`](dpdk_sys::rte_eth_dev_close) is what "frees all port resources"). An
/// earlier version of this type owned its mempool outright and freed it on drop, which made the
/// wrong teardown order the *natural* one -- Rust drops locals in reverse declaration order, so
/// the pool went first -- and presented as a SIGSEGV inside `rte_pktmbuf_free` during teardown,
/// after every assertion in the test had already passed.
///
/// # What this does *not* cover
///
/// An [`Mbuf`] holds no reference to its pool: it is a bare pointer, and adding a refcount to it
/// would put an atomic on the per-packet path. So an mbuf is `!Send`, and the only way to move a
/// batch across a thread boundary is [`Pool::consign`], which pairs the batch with a handle. That
/// keeps the cost at one refcount operation per *handoff*, not per packet, and leaves the
/// ordinary receive-process-transmit path free of atomics entirely.
#[derive(Debug, Clone)]
pub struct Pool(Arc<PoolInner>);

/// The owned mempool behind every [`Pool`] handle.
#[derive(Debug)]
pub(crate) struct PoolInner {
    config: PoolConfig,
    pool: NonNull<dpdk_sys::rte_mempool>,
}

// SAFETY: `PoolInner` is an immutable handle to a DPDK mempool, and `rte_mempool` is internally
// synchronized for the allocate/free operations this crate performs on it: the per-lcore cache is
// keyed by `rte_lcore_id()`, and non-EAL threads (`LCORE_ID_ANY`) bypass the cache for the
// multi-producer/multi-consumer ring underneath.
unsafe impl Send for PoolInner {}
unsafe impl Sync for PoolInner {}

impl Drop for PoolInner {
    fn drop(&mut self) {
        info!("Freeing memory pool {name}", name = self.config.name());
        // SAFETY: the pointer came from a successful `rte_pktmbuf_pool_create`, and this runs only
        // when the last handle to it is gone, so it is freed exactly once.
        unsafe { dpdk_sys::rte_mempool_free(self.pool.as_ptr()) };
    }
}

impl PartialEq for Pool {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Pool {}

impl Display for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Pool({})", self.name())
    }
}

/// Pools created but not yet adopted by the [`Manager`].
///
/// A `Sync` staging area, not the authority: authority over mempool lifetime belongs to
/// [`Manager`]'s [`Reclaimer`], which is `!Sync` and lives in the owning
/// [`Eal`](crate::eal::Eal). Creation can happen on any thread, so it stages here and the manager
/// adopts on its next operation.
///
/// The inbox holds a handle, so a pool is never without an owner between creation and adoption --
/// and a pool created when no `Eal` exists, or after shutdown, simply stays here. That leaks it,
/// which is the correct outcome for memory nothing is tracking.
///
/// A `OnceLock` around the `Mutex` rather than a `Mutex` in the static directly:
/// `loom::sync::Mutex::new` is not `const fn`, so a static initializer does not typecheck under
/// the loom backend of `concurrency`.
static PENDING: OnceLock<Mutex<Vec<Pool>>> = OnceLock::new();

fn pending() -> &'static Mutex<Vec<Pool>> {
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

impl Pool {
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

        let handle = Pool(Arc::new(PoolInner { config, pool }));

        // Stage before handing out a handle, so a manager adopting concurrently cannot miss it --
        // and so a clone is a floor on the reference count from the moment the pool exists,
        // whether or not an `Eal` has adopted it yet.
        pending().lock().push(handle.clone());

        Ok(handle)
    }

    /// Get the name of the memory pool.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.config.name()
    }

    /// Get the configuration of the memory pool.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.0.config
    }

    /// The number of mbufs currently checked out of this pool.
    ///
    /// A direct oracle for "was this batch freed exactly once": it rises by the size of an
    /// allocation and must return to its previous value once the mbufs are released. Used by the
    /// tests to distinguish a leak (count stays high) from a double free (count goes *below* where
    /// it started, because the same objects were returned to the ring twice).
    #[must_use]
    pub fn in_use(&self) -> u32 {
        // SAFETY: `self.0.pool` is a live mempool for the lifetime of this handle, and this reads
        // its accounting without mutating it.
        unsafe { dpdk_sys::rte_mempool_in_use_count(self.0.pool.as_ptr()) }
    }

    /// A mutable pointer to the raw DPDK [`rte_mempool`](dpdk_sys::rte_mempool).
    ///
    /// Handing this to a `dpdk_sys` function that retains it is sound in a way it was not when
    /// `Pool` owned the mempool: the pool is released only at EAL teardown, so a retained copy
    /// cannot be invalidated by a `Pool` handle going out of scope.
    pub(crate) fn as_mut_ptr(&self) -> *mut dpdk_sys::rte_mempool {
        self.0.pool.as_ptr()
    }

    /// Clear a batch of mbufs to cross a thread boundary, pairing it with a handle to this pool.
    ///
    /// This is the only way to move mbufs between threads: [`Mbuf`] is `!Send`, and the resulting
    /// [`Consigned`] is `Send` precisely because it carries the guard.
    ///
    /// # Errors
    ///
    /// Returns [`WrongPool`] if any mbuf in the batch came from a different mempool, in which case
    /// the batch is handed back untouched. Guarding the wrong pool would keep the wrong memory
    /// alive and prove nothing about the memory actually referenced, so this is checked rather
    /// than assumed -- an O(n) scan on a path that runs once per handoff, not once per packet.
    // The error intentionally carries the batch back so a rejected handoff does not leak it. The
    // `Ok` variant is the same batch plus a handle, so the `Result` is large either way and boxing
    // the error would buy nothing; see the same note on `Dev::start`.
    #[allow(clippy::result_large_err)]
    pub fn consign(&self, batch: MbufArray) -> Result<Consigned, (WrongPool, MbufArray)> {
        let expected = self.as_mut_ptr();
        for (index, mbuf) in batch.iter().enumerate() {
            // SAFETY: `mbuf` is live for the duration of this loop; `pool` is a plain field read.
            let actual = unsafe { mbuf.raw.as_ref().pool };
            if !core::ptr::eq(actual, expected) {
                return Err((WrongPool { index }, batch));
            }
        }
        Ok(Consigned {
            batch,
            guard: self.clone(),
        })
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
            dpdk_sys::rte_pktmbuf_alloc_bulk(self.as_mut_ptr(), raw.as_mut_ptr(), num as c_uint)
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
/// An `Mbuf` is `!Send` and `!Sync`: it cannot cross a thread boundary. An mbuf is a bare pointer
/// into a [`Pool`] with no link back to it, so a mbuf that has escaped to another thread has
/// nothing left to keep its pool alive. Cross-thread handoff has to go through a conveyance that
/// carries a guard for the pool; see the comment on the (absent) `Send` impl.
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
#[repr(transparent)]
#[derive(Debug)]
pub struct Mbuf {
    pub(crate) raw: NonNull<dpdk_sys::rte_mbuf>,
    marker: PhantomData<dpdk_sys::rte_mbuf>,
}

// `Mbuf` is deliberately neither `Send` nor `Sync`.
//
// It holds a `NonNull`, so it is `!Send + !Sync` by default and there is no impl here to make it
// otherwise.  That is the point, and removing it would reintroduce a use-after-free:
//
// An mbuf is a bare pointer into a `Pool`'s memory with no reference to that pool and no
// refcount tying the two together.  A `Send` mbuf can therefore be handed to another thread, and
// once it has escaped the thread that received it there is nothing left to prove that its pool
// outlives it -- not the device's queue set, not a quiescent point, nothing.  The bug this
// prevented in practice was a SIGSEGV inside `rte_pktmbuf_free` during teardown, on a mempool
// that had already been freed.
//
// Moving mbufs between threads is a legitimate thing to want (trapping control-plane packets to a
// tap writer, handing a new connection to a designated owner core), so the answer is not "never"
// -- it is that the crossing must go through a conveyance that carries a guard keeping the pool
// alive for as long as the batch is in flight.  Making `Mbuf` `!Send` is what forces every such
// handoff through that conveyance instead of allowing an ad-hoc `Vec<Mbuf>` behind a mutex.

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

/// A batch of mbufs cleared to cross a thread boundary, together with the [`Pool`] handle that
/// makes it safe to do so.
///
/// # Why this type exists
///
/// [`Mbuf`] is `!Send`, because an mbuf is a bare pointer into a pool with no reference back to it:
/// once one has escaped to another thread there is nothing left keeping its pool alive. Putting a
/// refcount on the mbuf itself would mean an atomic per packet on the receive and transmit paths,
/// which is the one place that cost is unaffordable.
///
/// Consigning a batch instead pairs it with one `Pool` clone, so the cost is a single refcount
/// operation per *handoff* -- and handoffs are the exception path (trapping control-plane packets
/// to a tap writer, routing a new connection to the core that owns the state for it), not the
/// steady state. Ordinary receive-process-transmit never touches an atomic.
///
/// Because the batch cannot be separated from its guard, the type system now enforces what was
/// previously a convention: an ad-hoc `Vec<Mbuf>` behind a mutex does not compile, and this does.
///
/// # No unwrapping
///
/// There is deliberately no way to take the [`MbufArray`] back out. Doing so on the receiving
/// thread would yield an unguarded batch whose pool could then be freed underneath it -- exactly
/// the hazard this type exists to close. Read the batch through [`AsRef`], modify it through
/// [`AsMut`], and transmit it with [`transmit_on`](Self::transmit_on).
///
/// A consigned batch is `Send`, which a bare [`MbufArray`] is not:
///
/// ```
/// # use dataplane_dpdk::mem::Consigned;
/// fn assert_send<T: Send>() {}
/// assert_send::<Consigned>();
/// ```
///
/// but it is still `!Sync`, so two threads cannot work on one batch at once:
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::mem::Consigned;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<Consigned>();
/// ```
#[derive(Debug)]
pub struct Consigned {
    batch: MbufArray,
    guard: Pool,
}

impl Drop for Consigned {
    fn drop(&mut self) {
        // The mbufs must be returned to the pool *before* the guard that keeps that pool alive is
        // released.  The other way round, the guard could be the last handle, the mempool would be
        // freed, and the bulk free of the batch would then walk memory that no longer exists.
        //
        // Field declaration order above already places `batch` before `guard`, so default
        // field-drop order honours it.  This assignment states the ordering in code instead of
        // leaving it implied, in the same spirit as `quiescent::Subscriber`'s `Drop`: an invariant
        // that holds only because of declaration order is one a field reorder breaks silently,
        // with no compile error.  Assigning drops the old value, so this is the bulk free.
        //
        // Worth being honest about the current strength of this: the hazard is **latent, not
        // live**.  Reversing the fields *and* deleting this line leaves every test passing,
        // because the pool registry holds a handle to each pool until EAL teardown, so `guard`
        // can never be the last one.  The ordering becomes real the moment that floor goes away --
        // which the planned QSBR ownership work may well do, since its whole purpose is to decide
        // reclamation by quiescence rather than by a process-lifetime handle.  Keeping the
        // ordering explicit now means that change does not have to rediscover this.
        self.batch = MbufArray::new_empty();
    }
}

// SAFETY: what makes an `Mbuf` unsafe to send is that its pool might be freed while it is in
// flight; `guard` is a strong reference to that pool, so it cannot be.  Nothing else about an mbuf
// is thread-affine: the data buffer is plain memory, and `rte_pktmbuf_free`/`rte_pktmbuf_free_bulk`
// on a different lcore than the one that allocated is a supported mempool operation (a non-EAL
// thread bypasses the per-lcore cache for the MP/MC ring underneath).
//
// `Consigned` is deliberately *not* `Sync`: it holds `Mbuf`s, which are `!Sync`, so two threads
// touching one batch at the same time remains unrepresentable.
unsafe impl Send for Consigned {}

impl Consigned {
    /// The number of mbufs in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    /// Returns `true` if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// The pool these mbufs came from.
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.guard
    }

    /// Transmit as much of the batch as the queue accepts, keeping the unsent remainder.
    ///
    /// Returns the number transmitted. The guard never leaves the batch, so this is safe to call
    /// on whichever thread the batch was consigned to.
    pub fn transmit_on(&mut self, tx: &mut crate::queue::tx::TxQueue<'_>) -> usize {
        let offered = self.batch.len();
        // Move the batch out and put the unsent remainder back; `transmit` takes ownership, and
        // `MbufArray::default()` is empty, so nothing is lost if this unwinds.
        let batch = core::mem::take(&mut self.batch);
        self.batch = tx.transmit(batch);
        offered - self.batch.len()
    }
}

impl AsRef<[Mbuf]> for Consigned {
    fn as_ref(&self) -> &[Mbuf] {
        &self.batch
    }
}

impl AsMut<[Mbuf]> for Consigned {
    fn as_mut(&mut self) -> &mut [Mbuf] {
        &mut self.batch
    }
}

/// Returned when a batch offered to [`Pool::consign`] contains an mbuf from a different pool.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[error("mbuf at index {index} belongs to a different mempool than the consigning pool")]
pub struct WrongPool {
    /// The index within the batch of the first mbuf that did not match.
    pub index: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_eal;

    /// Pool names are process-global in DPDK, so each test needs its own.
    fn pool(name: &str, size: u32) -> Pool {
        let config = PoolConfig::new(
            name,
            PoolParams {
                size,
                cache_size: 0,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("invalid pool config: {e:?}"));
        Pool::new_pkt_pool(config).unwrap_or_else(|e| panic!("failed to create pool: {e:?}"))
    }

    /// The regression this whole design exists for.
    ///
    /// A `Pool` handle going out of scope while mbufs drawn from it are still live used to free
    /// the mempool out from under them; touching and then freeing those mbufs was a
    /// use-after-free that presented as a SIGSEGV inside `rte_pktmbuf_free` during teardown.
    /// Now the handle is `Copy` and owns nothing, so dropping it is a no-op and the mbufs stay
    /// valid.
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

        // Touch every mbuf: under the old owning `Pool` this read freed memory.
        for mbuf in &mut mbufs {
            let room = mbuf.tailroom();
            assert!(room > 0, "mbuf has no tailroom");
            mbuf.append(16).expect("append failed");
        }
        assert_eq!(mbufs.len(), 4);
        // And free them, which returns them to a mempool that must still exist.
        drop(mbufs);
    }

    /// A `Pool` is a reference-counted handle: cloning one yields another name for the same
    /// mempool, and the mempool outlives any individual clone.
    #[test]
    #[with_eal]
    fn pool_handles_are_clones_of_one_mempool() {
        let first = pool("clone_pool", 511);
        let second = first.clone();
        assert_eq!(first, second);
        assert_eq!(first.as_mut_ptr(), second.as_mut_ptr());
        assert_eq!(first.name(), "clone_pool");

        // Allocating through one clone draws from the same pool the other sees.
        let a = first.alloc_bulk(2).expect("alloc from first");
        let b = second.alloc_bulk(2).expect("alloc from second");
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
    }

    /// A tracked handle is a floor on the reference count, so dropping every caller-held clone
    /// cannot free the mempool. This is what makes the `Drop` on `PoolInner` safe to have at all.
    #[test]
    #[with_eal]
    fn a_tracked_pool_is_held_alive() {
        let handle = pool("floor_pool", 511);
        // Two: the inbox's clone and this one.
        assert_eq!(Arc::strong_count(&handle.0), 2);

        let mbufs = handle.alloc_bulk(4).expect("alloc_bulk failed");
        drop(handle);

        // Only the tracked clone remains, so nothing was freed and the mbufs are still live.
        drop(mbufs);
    }

    /// Distinct pools are distinct handles.
    #[test]
    #[with_eal]
    fn distinct_pools_are_not_equal() {
        let a = pool("distinct_a", 511);
        let b = pool("distinct_b", 511);
        assert_ne!(a, b);
    }

    /// Every created pool lands in the adoption inbox. One that never staged would be invisible
    /// to the manager and leaked outright.
    #[test]
    #[with_eal]
    fn created_pools_are_staged_for_adoption() {
        let created = pool("staged_pool", 511);
        // Membership, not a count: the whole test binary shares one inbox and sibling tests
        // create pools concurrently, so any count taken here is immediately stale.
        let staged = pending().lock();
        let matching: Vec<_> = staged.iter().filter(|entry| **entry == created).collect();
        assert_eq!(
            matching.len(),
            1,
            "a created pool must appear in the adoption inbox exactly once"
        );
        assert_eq!(matching[0].name(), "staged_pool");
    }

    /// The manager's side of the contract: it adopts from the inbox, and a retired pool loses its
    /// tracked handle only through the reclaimer.
    ///
    /// Builds its own [`Manager`] rather than reaching through an [`Eal`](crate::eal::Eal), which
    /// a unit test cannot do: the test EAL is exposed only as an
    /// [`EalShared`](crate::eal::EalShared), and `mem` is deliberately absent from that
    /// projection because a [`Reclaimer`] is `!Sync`. Sound here only because nothing else in the
    /// test binary drains the inbox -- in production there is exactly one `Eal` and therefore one
    /// manager, since DPDK permits one `rte_eal_init` per process.
    #[test]
    #[with_eal]
    fn the_manager_adopts_then_releases_on_retirement() {
        let manager = Manager::init();
        let handle = pool("adopt_pool", 511);
        assert!(
            !pending().lock().is_empty(),
            "the new pool should be staged"
        );

        // Adopting moves it from the inbox into the reclaimer.
        manager.reclaim();
        assert!(
            !pending().lock().contains(&handle),
            "adoption should have taken this pool out of the inbox"
        );
        // A floor, not an exact count: the reclaimer holds a clone in its live set *and* one in
        // the published snapshot, and how many copies it keeps is its business. What matters here
        // is that something other than this test still holds the pool.
        assert!(
            Arc::strong_count(&handle.0) > 1,
            "the manager should be tracking the pool"
        );

        // With no attendants there is nothing to wait for, so retiring and reclaiming drops the
        // tracked clone at once.
        assert!(manager.retire(&handle), "the pool should have been live");
        manager.reclaim();
        assert_eq!(
            Arc::strong_count(&handle.0),
            1,
            "after retirement this should be the only handle left"
        );

        // The mempool itself survives while this handle lives, which is what keeps outstanding
        // mbufs valid.
        let mbufs = handle.alloc_bulk(2).expect("pool must still be usable");
        drop(mbufs);
    }

    /// Shutdown gives up ownership, so a pool created afterwards stays staged -- leaked rather
    /// than freed by something no longer tracking it.
    #[test]
    #[with_eal]
    fn shutdown_stops_adopting() {
        let mut manager = Manager::init();
        manager.shutdown();
        assert!(
            manager.attendants().is_none(),
            "a shut-down manager must not enrol new workers"
        );
        let handle = pool("post_shutdown_pool", 511);
        manager.reclaim();
        assert!(
            pending().lock().contains(&handle),
            "with no manager to adopt it, the pool stays staged"
        );
    }

    /// The point of the whole design: a consigned batch really can cross a thread boundary, be
    /// used there, and be freed there -- with the pool kept alive by the guard it carries.
    #[test]
    #[with_eal]
    fn a_consigned_batch_crosses_a_thread_and_is_freed_there() {
        let pool = pool("consign_pool", 511);
        let mut batch = pool.alloc_bulk(8).expect("alloc_bulk failed");
        for mbuf in &mut batch {
            mbuf.append(32).expect("append failed");
        }

        let consigned = pool.consign(batch).map_err(|(e, _)| e).expect("consign");
        assert_eq!(consigned.len(), 8);

        // Drop every handle on this side. Only the registry's clone and the batch's guard remain,
        // so the mempool survives the move.
        drop(pool);

        let observed = std::thread::spawn(move || {
            let mut consigned = consigned;
            // Read and mutate on the far thread.
            let seen = consigned.as_ref().len();
            for mbuf in consigned.as_mut() {
                let _ = mbuf.append(8);
            }
            // ...and free them there, which is the operation that would fault on a freed mempool.
            drop(consigned);
            seen
        })
        .join()
        .expect("far thread panicked");
        assert_eq!(observed, 8);
    }

    /// Dropping a `Consigned` must return its mbufs to the pool exactly once.
    ///
    /// This is the test for the explicit `Drop` on `Consigned`. "It did not crash" would pass
    /// even if the batch leaked, and a double free of a bulk batch pushes the same pointers into
    /// the mempool ring twice -- which shows up as an in-use count *below* where it started, not
    /// as a fault. Only occupancy accounting distinguishes all three outcomes.
    #[test]
    #[with_eal]
    fn dropping_a_consigned_batch_returns_every_mbuf_exactly_once() {
        let pool = pool("consign_accounting", 511);
        let baseline = pool.in_use();

        let batch = pool.alloc_bulk(8).expect("alloc_bulk failed");
        assert_eq!(
            pool.in_use(),
            baseline + 8,
            "allocation should be accounted"
        );

        let consigned = pool.consign(batch).map_err(|(e, _)| e).expect("consign");
        assert_eq!(
            pool.in_use(),
            baseline + 8,
            "consigning must not allocate or free anything"
        );

        drop(consigned);
        assert_eq!(
            pool.in_use(),
            baseline,
            "every mbuf must be back in the pool -- higher means a leak, lower means a double free"
        );
    }

    /// Guarding the wrong pool would keep the wrong memory alive, so it is rejected -- and the
    /// batch comes back so the caller does not lose it.
    #[test]
    #[with_eal]
    fn consign_rejects_a_batch_from_another_pool() {
        let a = pool("consign_from_a", 511);
        let b = pool("consign_to_b", 511);
        let batch = a.alloc_bulk(3).expect("alloc from a");

        match b.consign(batch) {
            Err((err, returned)) => {
                assert_eq!(err.index, 0);
                assert_eq!(returned.len(), 3, "the batch must be handed back intact");
            }
            Ok(_) => panic!("consigning a batch from pool a under pool b must fail"),
        }
    }

    /// An empty batch is consignable, and consigning does not disturb the count.
    #[test]
    #[with_eal]
    fn consign_accepts_an_empty_batch() {
        let pool = pool("consign_empty", 511);
        let consigned = pool
            .consign(MbufArray::new_empty())
            .map_err(|(e, _)| e)
            .expect("consign empty");
        assert!(consigned.is_empty());
        assert_eq!(consigned.pool(), &pool);
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
        // The pool holds 15 mbufs; asking for more than that is all-or-nothing.
        match pool.alloc_bulk(MBUF_BURST) {
            Err(MbufAllocError::Exhausted { requested }) => assert_eq!(requested, MBUF_BURST),
            other => panic!("expected Exhausted, got {other:?}"),
        }
        // ...and the failed request consumed nothing, so a fitting one still succeeds.
        let ok = pool.alloc_bulk(15).expect("pool should still be full");
        assert_eq!(ok.len(), 15);
    }
}
