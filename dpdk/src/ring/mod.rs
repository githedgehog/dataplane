// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK ring (lock-free FIFO queue) abstraction.
//!
//! A [`Ring`] is a fixed-size, lock-free, multi-producer / multi-consumer
//! (or single-producer / single-consumer) FIFO queue backed by
//! [`dpdk_sys::rte_ring`].  It stores opaque pointer-sized values; this
//! wrapper provides type-safe ownership semantics by transferring
//! heap-allocated `Box<T>` values through the ring.
//!
//! # Ownership Model
//!
//! [`Ring::enqueue`] consumes a `Box<T>` (converting it to a raw pointer
//! stored inside the DPDK ring).  [`Ring::dequeue`] retrieves that raw
//! pointer and reconstitutes the `Box<T>`, transferring ownership to the
//! caller.  When the `Ring` is dropped, any items still queued are drained
//! and dropped.

use crate::socket;
use core::ffi::{c_int, c_uint, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use errno::{Errno, ErrorCode, StandardErrno};
use std::ffi::CString;
use tracing::debug;

/// A DPDK lock-free ring queue.
///
/// See the [module documentation](self) for the ownership model.
#[derive(Debug)]
pub struct Ring<T> {
    inner: NonNull<dpdk_sys::rte_ring>,
    params: CheckedParams,
    marker: PhantomData<dpdk_sys::rte_ring>,
    marker2: PhantomData<T>,
}

#[derive(Debug, Clone)]
pub struct Params {
    pub name: String,
    pub size: usize,
    pub socket_preference: socket::Preference,
}

#[repr(transparent)]
#[derive(Debug, Clone)]
struct CheckedParams(Params);

#[allow(unused)]
impl CheckedParams {
    fn name(&self) -> &str {
        self.0.name.as_str()
    }

    fn size(&self) -> usize {
        self.0.size
    }
}

impl Params {
    pub const MAX_NAME_LENGTH: usize = 127;

    #[allow(unused)]
    #[cold]
    fn validate(self) -> Result<CheckedParams, err::InvalidArgument> {
        if !self.size.is_power_of_two() {
            return Err(err::InvalidArgument::SizeNotPowerOfTwo(self));
        }
        if !self.name.is_ascii() {
            return Err(err::InvalidArgument::NameNotAscii(self));
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(err::InvalidArgument::IllegalCharacters(self));
        }
        if self.name.len() > Params::MAX_NAME_LENGTH {
            return Err(err::InvalidArgument::NameTooLong(self));
        }
        Ok(CheckedParams(self))
    }
}

/// Producer / consumer threading mode for a [`Ring`].
///
/// Controls whether the ring uses multi-threaded safe operations (with CAS)
/// or cheaper single-threaded operations on the producer / consumer side.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThreadMode {
    /// Only one thread will call the corresponding operation.
    Single,
    /// Multiple threads may call the corresponding operation concurrently.
    Multi,
}

impl<T> Ring<T> {
    /// Create a new DPDK ring.
    ///
    /// `producer` and `consumer` select the threading mode for the
    /// respective side of the queue.
    ///
    /// # Errors
    ///
    /// Returns a [`err::RingCreateErr`] if parameter validation or the
    /// underlying DPDK call fails.
    pub fn new(
        params: Params,
        producer: ThreadMode,
        consumer: ThreadMode,
    ) -> Result<Self, err::RingCreateErr> {
        /// TODO: figure out why musl builds don't expose E_RTE_NO_CONFIG
        /// likely a config error for bindgen
        // use dpdk_sys::_bindgen_ty_4::E_RTE_NO_CONFIG;
        const E_RTE_NO_CONFIG: u64 = 1002;
        use err::RingCreateErr::*;
        let params = params.validate().map_err(InvalidArgument)?;
        let name = CString::new(params.name())
            .unwrap_or_else(|_| unreachable!("null characters already excluded"));
        let socket_id = socket::SocketId::try_from(params.0.socket_preference).map_err(|e| {
            UnableToDetermineNumaNode {
                params: params.0.clone(),
                code: e,
            }
        })?;

        // RING_F_SP_ENQ = 0x0001, RING_F_SC_DEQ = 0x0002
        let mut flags: c_uint = 0;
        if producer == ThreadMode::Single {
            flags |= 0x1; // RING_F_SP_ENQ
        }
        if consumer == ThreadMode::Single {
            flags |= 0x2; // RING_F_SC_DEQ
        }

        let inner = match NonNull::new(unsafe {
            dpdk_sys::rte_ring_create(
                name.as_ptr(),
                params.size() as c_uint,
                socket_id.0 as c_int,
                flags,
            )
        }) {
            None => {
                let errno = Errno::from(unsafe { dpdk_sys::rte_errno_get() });
                if errno.0 == E_RTE_NO_CONFIG as i32 {
                    return Err(NoConfig(params.0));
                }
                return match ErrorCode::parse_errno(errno) {
                    ErrorCode::Standard(StandardErrno::InvalidArgument) => Err(InvalidArgument(
                        err::InvalidArgument::SizeNotPowerOfTwo(params.0),
                    )),
                    ErrorCode::Standard(StandardErrno::NoSpaceLeftOnDevice) => {
                        Err(NotEnoughMemZones(params.0))
                    }
                    ErrorCode::Standard(StandardErrno::FileExists) => Err(MemZoneExists(params.0)),
                    ErrorCode::Standard(StandardErrno::NoMemory) => {
                        Err(UnableToAllocateMemZone(params.0))
                    }
                    code => Err(UnexpectedErrno {
                        code,
                        params: params.0,
                    }),
                };
            }
            Some(ring_ptr) => ring_ptr,
        };
        Ok(Self {
            inner,
            params,
            marker: PhantomData,
            marker2: PhantomData,
        })
    }

    /// Enqueue a single item, transferring ownership into the ring.
    ///
    /// The `Box<T>` is leaked into a raw pointer and stored inside the
    /// DPDK ring.  It will be reclaimed either by a subsequent
    /// [`dequeue`](Self::dequeue) call or when the ring is dropped.
    ///
    /// # Errors
    ///
    /// Returns the item back to the caller if the ring is full.
    pub fn enqueue(&self, item: Box<T>) -> Result<(), Box<T>> {
        let raw = Box::into_raw(item);
        // SAFETY: self.inner is a valid rte_ring pointer, and raw is a
        // valid heap pointer that we are intentionally leaking into the ring.
        let ret = unsafe {
            dpdk_sys::rte_ring_enqueue(self.inner.as_ptr(), raw.cast::<c_void>())
        };
        if ret == 0 {
            Ok(())
        } else {
            // Ring is full — reclaim the Box.
            Err(unsafe { Box::from_raw(raw) })
        }
    }

    /// Dequeue a single item, transferring ownership out of the ring.
    ///
    /// Returns `None` if the ring is empty.
    pub fn dequeue(&self) -> Option<Box<T>> {
        let mut obj: *mut c_void = ptr::null_mut();
        // SAFETY: self.inner is a valid rte_ring pointer, and obj is a
        // valid stack-local pointer that DPDK will fill in.
        let ret = unsafe {
            dpdk_sys::rte_ring_dequeue(self.inner.as_ptr(), &mut obj)
        };
        if ret == 0 {
            // SAFETY: the pointer was created by Box::into_raw in enqueue().
            Some(unsafe { Box::from_raw(obj.cast::<T>()) })
        } else {
            None
        }
    }

    /// Enqueue multiple items in bulk.
    ///
    /// Either **all** items are enqueued or **none** are.
    ///
    /// Returns `Ok(())` on success, or `Err(items)` if there is not
    /// enough free space in the ring.
    pub fn enqueue_bulk(&self, items: Vec<Box<T>>) -> Result<(), Vec<Box<T>>> {
        if items.is_empty() {
            return Ok(());
        }
        let count = items.len();
        // Leak every Box into a raw pointer array.
        let mut ptrs: Vec<*mut c_void> = items
            .into_iter()
            .map(|b| Box::into_raw(b).cast::<c_void>())
            .collect();

        // SAFETY: ptrs contains count valid heap pointers.
        let enqueued = unsafe {
            dpdk_sys::rte_ring_enqueue_bulk(
                self.inner.as_ptr(),
                ptrs.as_mut_ptr().cast::<*mut c_void>(),
                count as c_uint,
                ptr::null_mut(), // free_space output (unused)
            )
        };

        if enqueued as usize == count {
            Ok(())
        } else {
            // Bulk enqueue is all-or-nothing; reclaim every pointer.
            let reclaimed = ptrs
                .into_iter()
                .map(|p| unsafe { Box::from_raw(p.cast::<T>()) })
                .collect();
            Err(reclaimed)
        }
    }

    /// Dequeue up to `count` items in bulk.
    ///
    /// Returns the dequeued items.  If fewer than `count` items are
    /// available, **nothing** is dequeued and an empty `Vec` is returned
    /// (DPDK bulk dequeue is all-or-nothing).
    pub fn dequeue_bulk(&self, count: usize) -> Vec<Box<T>> {
        if count == 0 {
            return Vec::new();
        }
        let mut ptrs: Vec<*mut c_void> = vec![ptr::null_mut(); count];

        // SAFETY: ptrs has `count` slots for DPDK to fill.
        let dequeued = unsafe {
            dpdk_sys::rte_ring_dequeue_bulk(
                self.inner.as_ptr(),
                ptrs.as_mut_ptr().cast::<*mut c_void>(),
                count as c_uint,
                ptr::null_mut(), // available output (unused)
            )
        };

        (0..dequeued as usize)
            .map(|i| unsafe { Box::from_raw(ptrs[i].cast::<T>()) })
            .collect()
    }

    /// Return the number of items currently stored in the ring.
    #[must_use]
    pub fn count(&self) -> u32 {
        // SAFETY: self.inner is a valid rte_ring pointer.
        unsafe { dpdk_sys::rte_ring_count(self.inner.as_ptr()) }
    }

    /// Return the number of free slots in the ring.
    #[must_use]
    pub fn free_count(&self) -> u32 {
        // SAFETY: self.inner is a valid rte_ring pointer.
        unsafe { dpdk_sys::rte_ring_free_count(self.inner.as_ptr()) }
    }

    /// Returns `true` if the ring is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        // SAFETY: self.inner is a valid rte_ring pointer.
        unsafe { dpdk_sys::rte_ring_full(self.inner.as_ptr()) != 0 }
    }

    /// Returns `true` if the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // SAFETY: self.inner is a valid rte_ring pointer.
        unsafe { dpdk_sys::rte_ring_empty(self.inner.as_ptr()) != 0 }
    }

    /// The validated parameters this ring was created with.
    #[must_use]
    pub fn name(&self) -> &str {
        self.params.name()
    }

    /// The requested capacity of the ring (number of slots).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.params.size()
    }
}

/// # Safety
///
/// The underlying `rte_ring` is thread-safe for the producer / consumer
/// modes selected at creation time.  The `Ring` struct owns the resource
/// uniquely (no aliasing through this API), so transferring it to
/// another thread is safe.
unsafe impl<T: Send> Send for Ring<T> {}

/// # Safety
///
/// Concurrent `enqueue` / `dequeue` access is safe when the ring was
/// created with [`ThreadMode::Multi`] on the corresponding side.
/// Single-producer or single-consumer rings are safe under `&Ring`
/// provided the caller upholds the single-thread guarantee externally
/// (e.g., by only accessing from one thread at a time), which is the
/// same contract DPDK itself requires.
unsafe impl<T: Send> Sync for Ring<T> {}

impl<T> Drop for Ring<T> {
    fn drop(&mut self) {
        // Drain any items remaining in the ring so their memory is freed.
        let mut obj: *mut c_void = ptr::null_mut();
        loop {
            // SAFETY: self.inner is valid until rte_ring_free below.
            let ret = unsafe {
                dpdk_sys::rte_ring_dequeue(self.inner.as_ptr(), &mut obj)
            };
            if ret != 0 {
                break;
            }
            // SAFETY: pointer was created by Box::into_raw in enqueue.
            let _ = unsafe { Box::from_raw(obj.cast::<T>()) };
        }

        debug!(
            "Freeing DPDK ring '{name}'",
            name = self.params.name(),
        );
        // SAFETY: self.inner was obtained from a successful rte_ring_create
        // and we have exclusive ownership.
        unsafe { dpdk_sys::rte_ring_free(self.inner.as_ptr()) };
    }
}

pub mod err {
    use crate::ring::Params;
    use errno::ErrorCode;

    #[derive(thiserror::Error, Debug)]
    pub enum InvalidArgument {
        #[error("size must be a power of two ({size} given)", size=.0.size)]
        SizeNotPowerOfTwo(Params),
        #[error("ring name must be ASCII")]
        NameNotAscii(Params),
        #[error("only alphanumeric ring names are supported (may contain -, _, and .)")]
        IllegalCharacters(Params),
        #[error("name too long (max is 127 ASCII characters)")]
        NameTooLong(Params),
    }

    #[derive(thiserror::Error, Debug)]
    pub enum RingCreateErr {
        #[error("function could not get pointer to rte_config structure")]
        NoConfig(Params),
        #[error(transparent)]
        InvalidArgument(InvalidArgument),
        #[error("unable to determine NUMA node: {code:?}")]
        UnableToDetermineNumaNode { code: ErrorCode, params: Params },
        #[error("insufficient memory zones to create ring")]
        NotEnoughMemZones(Params),
        #[error("memZone with name '{name}' already exists", name=.0.name)]
        MemZoneExists(Params),
        #[error("unable to allocate MemZone")]
        UnableToAllocateMemZone(Params),
        #[error("unexpected error code: {code:?}")]
        UnexpectedErrno { code: ErrorCode, params: Params },
    }
}
