// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK socket functions.
//!
//! # Note
//!
//! What DPDK calls a "socket" is more accurately a [NUMA] node, but DPDK calls it a socket, so
//! we're sticking with that.
//!
//! [NUMA]: https://en.wikipedia.org/wiki/Non-uniform_memory_access
use crate::dev::DevIndex;
#[allow(unused_imports)]
/// imported for rustdoc
use crate::eal::Eal;
use dpdk_sys::rte_socket_id;
use core::ffi::c_uint;
use core::marker::PhantomData;
use tracing::debug;
use errno::{ErrorCode, StandardErrno};

#[repr(transparent)]
#[derive(Debug)]
/// DPDK socket manager.
pub struct Manager {
    _private: PhantomData<()>,
}

impl Drop for Manager {
    fn drop(&mut self) {
        debug!("Closing DPDK socket manager");
    }
}

impl Manager {
    #[tracing::instrument(level = "trace")]
    /// Initialize the DPDK socket manager.
    ///
    /// Only [`Eal`] should only call this function, and only during initialization.
    pub(crate) fn init() -> Manager {
        debug!("Initializing DPDK socket manager");
        Manager {
            _private: PhantomData,
        }
    }

    /// [`Iterator`] over all the [`SocketId`]s available to the [`Eal`].
    pub fn iter(&self) -> impl Iterator<Item = SocketId> {
        SocketId::iter()
    }

    /// The number of sockets (aka NUMA nodes) on the [`Eal`].
    #[must_use] pub fn count(&self) -> u32 {
        SocketId::count()
    }

    #[tracing::instrument(level = "trace")]
    /// Get the [`SocketId`] of the currently executing thread.
    ///
    /// <div class="warning">
    ///
    /// [`SocketId`] is **NOT** the same thing as [`Index`]!
    ///
    /// </div>
    pub fn id_current(&self) -> SocketId {
        SocketId::current()
    }

    /// Look up a [`SocketId`] by its [`Index`].
    ///
    /// Returns `None` if the index does not map to a valid [`SocketId`].
    #[must_use] pub fn id_for_index(&self, index: Index) -> Option<SocketId> {
        SocketId::get_by_index(index)
    }

    /// Look up a [`SocketId`] by the lcore it is associated with.
    ///
    /// Returns `None` if the lcore is not valid.
    #[must_use] pub fn id_for_lcore(&self, lcore: u32) -> Option<SocketId> {
        if lcore >= unsafe { dpdk_sys::rte_lcore_count() } {
            return None;
        }
        Some(SocketId(unsafe { dpdk_sys::rte_lcore_to_socket_id(lcore) }))
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A CPU socket index.
///
/// This is a newtype around `c_uint` to provide type safety and prevent accidental misuse.
///
/// <div class="warning">
///
/// A [`Index`] is not at all the same thing as a [`SocketId`]!
///
/// See [`SocketId`] for more information.
///
/// </div>
pub struct Index(pub c_uint);

impl From<Index> for c_uint {
    fn from(index: Index) -> c_uint {
        index.0
    }
}

impl From<c_uint> for Index {
    fn from(index: c_uint) -> Index {
        Index(index)
    }
}

/// Iterator over all the [`SocketId`]s available to the [`Eal`].
struct SocketIdIterator {
    index: Index,
    count: c_uint,
}

impl SocketIdIterator {
    fn new() -> SocketIdIterator {
        SocketIdIterator {
            index: Index(0),
            count: SocketId::count(),
        }
    }
}

impl Iterator for SocketIdIterator {
    type Item = SocketId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index.0 >= self.count {
            return None;
        }
        let socket = SocketId::get_by_index(self.index);
        self.index.0 += 1;
        socket
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// This would be more accurately called a [NUMA] node id, but DPDK calls it a socket id
/// and things are confusing enough as it is, so I'm sticking with that.
///
/// This is a newtype around [`c_uint`] to provide type safety and prevent accidental misuse.
///
/// <div class="warning">
///
/// A [`SocketId`] is not at all the same thing as a socket index!
///
/// A socket index is a zero-based index into the list of sockets on the [`Eal`].
/// For example, if the [`SocketId`]s on the [`Eal`] are `[2, 3, 5]`, then index `1` would refer
/// to [`SocketId(3)`].
/// It needs to work this way because there is no rule stating that we have a contiguous,
/// zero-indexed list of sockets in the [`Eal`].
///
/// </div>
///
/// [NUMA]: https://en.wikipedia.org/wiki/Non-uniform_memory_access
pub struct SocketId(pub(crate) c_uint);

impl SocketId {
    /// A special [`SocketId`] that represents any socket.
    pub const ANY: SocketId = SocketId(c_uint::MAX /* -1 in c_int */);

    /// Get the [`SocketId`] of the currently executing thread.
    ///
    /// This is a wrapper around [`rte_socket_id`].
    ///
    /// # Safety
    ///
    /// This function is safe so long as the DPDK environment has been initialized.
    ///
    /// # Note
    ///
    /// Ideally, this method should be accessed via the [`Manager::id_for_index`] object as that
    /// makes lifetime issues simpler.
    pub(crate) fn current() -> SocketId {
        SocketId(unsafe { rte_socket_id() })
    }

    /// The index of the socket represented as a [`c_uint`].
    ///
    /// This function is mostly useful for interfacing with [`dpdk_sys`].
    #[must_use] pub fn as_c_uint(&self) -> c_uint {
        self.0
    }

    /// Look up a [`SocketId`] by its [`Index`].
    pub(crate) fn get_by_index(index: Index) -> Option<SocketId> {
        let idx_num = unsafe { dpdk_sys::rte_socket_id_by_idx(index.0) };
        if idx_num == -1 {
            None
        } else {
            Some(SocketId(idx_num as c_uint))
        }
    }

    /// [`Iterator`] over all the [`SocketId`]s available to the [`Eal`].
    pub(crate) fn iter() -> impl Iterator<Item = SocketId> {
        SocketIdIterator::new()
    }

    /// The number of sockets (aka NUMA nodes) on the [`Eal`].
    ///
    /// This is a wrapper around [`rte_socket_count`].
    ///
    /// # Safety
    ///
    /// This function is safe so long as the DPDK environment has been initialized.
    pub(crate) fn count() -> u32 {
        unsafe { dpdk_sys::rte_socket_count() }
    }

    /// Look up a [`SocketId`] by the lcore it is associated with.
    ///
    /// Returns `None` if the lcore is not valid.
    ///
    /// TODO: change lcore to a proper lcore id type.
    #[must_use] pub fn get_by_lcore(lcore: u32) -> Option<SocketId> {
        if lcore >= unsafe { dpdk_sys::rte_lcore_count() } {
            return None;
        }
        Some(SocketId(unsafe { dpdk_sys::rte_lcore_to_socket_id(lcore) }))
    }

    /// Look up a [`SocketId`] by the device it is associated with.
    #[must_use] pub fn get_by_dev(dev: DevIndex) -> Option<SocketId> {
        dev.socket_id().ok()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// A preference for a socket to use.
///
/// This shows up in configuration preferences for things like memory pools and queues.
pub enum Preference {
    /// Use a specific socket.
    Id(SocketId),
    /// Use the socket of a specific lcore.
    Lcore(u32 /* TODO: change to a proper lcore id type */),
    /// Use the socket of the device.
    Dev(DevIndex),
}

impl TryFrom<Preference> for SocketId {
    // TODO: this is a silly error type.  Design something better.
    type Error = ErrorCode;

    fn try_from(value: Preference) -> Result<Self, Self::Error> {
        match value {
            Preference::Id(id) => Ok(id),
            Preference::Lcore(lcore_id) => {
                SocketId::get_by_lcore(lcore_id).ok_or(ErrorCode::Standard(StandardErrno::InvalidArgument))
            }
            Preference::Dev(dev) => dev.socket_id(),
        }
    }
}
