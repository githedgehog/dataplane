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
use crate::lcore::LCoreId;
use core::ffi::c_uint;
use errno::{ErrorCode, StandardErrno};
use tracing::{debug, info};

/// DPDK socket manager.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug)]
pub struct Manager;

impl Drop for Manager {
    fn drop(&mut self) {
        info!("Closing DPDK socket manager");
    }
}

impl Manager {
    /// Initialize the DPDK socket manager.
    ///
    /// Only [`Eal`][crate::eal::Eal] should only call this function, and only during
    /// initialization.
    pub(crate) fn init() -> Manager {
        debug!("Initializing DPDK socket manager");
        Manager
    }

    /// [`Iterator`] over all the [`SocketId`]s available to the [`Eal`][crate::eal::Eal].
    pub fn iter(&self) -> impl Iterator<Item = SocketId> {
        SocketId::iter()
    }

    /// The number of sockets (aka NUMA nodes) on the [`Eal`][crate::eal::Eal].
    #[must_use]
    pub fn count(&self) -> u32 {
        SocketId::count()
    }

    /// Get the [`SocketId`] of the currently executing thread.
    ///
    /// <div class="warning">
    ///
    /// [`SocketId`] is **NOT** the same thing as [`Index`]!
    ///
    /// </div>
    #[tracing::instrument(level = "trace")]
    pub fn current(&self) -> SocketId {
        SocketId::current()
    }

    /// Look up a [`SocketId`] by its [`Index`].
    ///
    /// Returns `None` if the index does not map to a valid [`SocketId`].
    #[must_use]
    pub fn id_for_index(&self, index: Index) -> Option<SocketId> {
        SocketId::get_by_index(index)
    }

    /// Look up a [`SocketId`] by the lcore it is associated with.
    ///
    /// Returns `None` if the lcore is not valid.
    #[must_use]
    pub fn id_for_lcore(&self, lcore: u32) -> Option<SocketId> {
        SocketId::get_by_lcore_id(LCoreId(lcore))
    }
}

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
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Iterator over all the [`SocketId`]s available to the [`Eal`][crate::eal::Eal].
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

/// This would be more accurately called a [NUMA] node id, but DPDK calls it a socket id
/// and things are confusing enough as it is, so I'm sticking with that.
///
/// This is a newtype around [`c_uint`] to provide type safety and prevent accidental misuse.
///
/// <div class="warning">
///
/// A [`SocketId`] is not at all the same thing as a socket index!
///
/// A socket index is a zero-based index into the list of sockets on the [`Eal`][crate::eal::Eal].
/// For example, if the [`SocketId`]s on the [`Eal`][crate::eal::Eal] are `[2, 3, 5]`, then index
/// `1` would refer to `SocketId(3)`.
/// It needs to work this way because there is no rule stating that we have a contiguous,
/// zero-indexed list of sockets in the [`Eal`][crate::eal::Eal].
///
/// </div>
///
/// [NUMA]: https://en.wikipedia.org/wiki/Non-uniform_memory_access
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// simplifies lifetime issues.
    pub(crate) fn current() -> SocketId {
        SocketId(unsafe { dpdk_sys::rte_socket_id() })
    }

    /// The index of the socket represented as a [`c_uint`].
    ///
    /// This function is mostly useful for interfacing with [`dpdk_sys`].
    #[must_use]
    pub fn as_c_uint(&self) -> c_uint {
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

    /// [`Iterator`] over all the [`SocketId`]s available to the [`Eal`][crate::eal::Eal].
    pub(crate) fn iter() -> impl Iterator<Item = SocketId> {
        SocketIdIterator::new()
    }

    /// The number of sockets (aka NUMA nodes) on the [`Eal`][crate::eal::Eal].
    ///
    /// This is a wrapper around [`rte_socket_count`].
    ///
    /// # Safety
    ///
    /// This function is safe so long as the DPDK environment has been initialized.
    pub(crate) fn count() -> u32 {
        unsafe { dpdk_sys::rte_socket_count() }
    }

    /// Look up the socket of an active lcore, including registered non-EAL threads.
    ///
    /// Returns `None` for out-of-range or inactive IDs.
    #[must_use]
    pub fn get_by_lcore_id(id: LCoreId) -> Option<SocketId> {
        if id.as_u32() >= LCoreId::MAX {
            return None;
        }
        if unsafe { dpdk_sys::rte_eal_lcore_role(id.as_u32()) }
            == dpdk_sys::rte_lcore_role_t::ROLE_OFF
        {
            return None;
        }
        Some(SocketId(unsafe {
            dpdk_sys::rte_lcore_to_socket_id(id.as_u32())
        }))
    }

    /// Look up a [`SocketId`] by the device it is associated with.
    #[must_use]
    pub fn get_by_dev(dev: DevIndex) -> Option<SocketId> {
        dev.socket_id().ok()
    }
}

/// A preference for a socket to use.
///
/// This shows up in configuration preferences for things like memory pools and queues.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Preference {
    #[default]
    CurrentThread,
    /// Use a specific socket.
    Id(SocketId),
    /// Use the socket of a specific lcore ID.
    LCore(LCoreId),
    /// Use the socket of the device.
    Dev(DevIndex),
}

impl TryFrom<Preference> for SocketId {
    // TODO: this is a silly error type.  Design something better.
    type Error = ErrorCode;

    fn try_from(value: Preference) -> Result<Self, Self::Error> {
        match value {
            // TLS lookup also works on unregistered threads.
            Preference::CurrentThread => Ok(SocketId::current()),
            Preference::Id(id) => Ok(id),
            Preference::LCore(lcore_id) => SocketId::get_by_lcore_id(lcore_id)
                .ok_or(ErrorCode::Standard(StandardErrno::InvalidArgument)),
            Preference::Dev(dev) => dev.socket_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lcore::RegisteredThread;
    use crate::with_eal;

    #[test]
    #[with_eal]
    fn a_registered_thread_resolves_to_its_socket() {
        std::thread::scope(|scope| {
            RegisteredThread::new(scope, "socket-lookup", |_| {
                let id = LCoreId::current();
                assert!(id.as_u32() < LCoreId::MAX);
                assert_eq!(
                    unsafe { dpdk_sys::rte_eal_lcore_role(id.as_u32()) },
                    dpdk_sys::rte_lcore_role_t::ROLE_NON_EAL
                );
                let socket = SocketId::current();
                assert_eq!(SocketId::get_by_lcore_id(id), Some(socket));
                assert_eq!(Manager::init().id_for_lcore(id.as_u32()), Some(socket));
                assert_eq!(SocketId::try_from(Preference::LCore(id)), Ok(socket));
            })
            .join()
            .expect("registered thread panicked");
        });
    }

    #[test]
    #[with_eal]
    fn resolving_the_current_thread_preference_off_an_lcore_does_not_fault() {
        // A plain std thread is not an EAL thread and has not registered.
        let (lcore, resolved, by_lcore) = std::thread::spawn(|| {
            let lcore = LCoreId::current();
            (
                lcore.as_u32(),
                SocketId::try_from(Preference::CurrentThread),
                SocketId::get_by_lcore_id(lcore),
            )
        })
        .join()
        .expect("unregistered thread panicked");

        assert_eq!(
            lcore,
            u32::MAX,
            "an unregistered thread reports LCORE_ID_ANY"
        );
        assert!(
            resolved.is_ok(),
            "the default preference must resolve on any thread"
        );
        assert!(
            by_lcore.is_none(),
            "an out-of-range lcore id must be rejected, not indexed"
        );
    }

    /// Query DPDK directly to check the wrapper independently of its iterator.
    fn enabled_lcores() -> Vec<u32> {
        (0..LCoreId::MAX)
            .filter(|id| unsafe { dpdk_sys::rte_lcore_is_enabled(*id) } != 0)
            .collect()
    }

    /// The shared test EAL enables only lcore 0; sparse IDs need a separate process.
    #[test]
    #[with_eal]
    fn every_enabled_lcore_resolves_to_a_socket() {
        let enabled = enabled_lcores();
        assert!(!enabled.is_empty(), "a running EAL has at least one lcore");
        let manager = Manager::init();
        for lcore in enabled {
            assert!(
                manager.id_for_lcore(lcore).is_some(),
                "lcore {lcore} is enabled but did not resolve"
            );
        }
    }

    #[test]
    #[with_eal]
    fn an_in_range_but_inactive_lcore_is_rejected() {
        // Registrations take low IDs; choose an inactive ID from the other end.
        let Some(inactive) = (0..LCoreId::MAX).rev().find(|id| {
            (unsafe { dpdk_sys::rte_eal_lcore_role(*id) }) == dpdk_sys::rte_lcore_role_t::ROLE_OFF
        }) else {
            return; // every lcore active; nothing to assert
        };
        let manager = Manager::init();
        assert!(
            manager.id_for_lcore(inactive).is_none(),
            "lcore {inactive} is inactive and must not resolve"
        );
        assert_eq!(
            SocketId::try_from(Preference::LCore(LCoreId(inactive))),
            Err(ErrorCode::Standard(StandardErrno::InvalidArgument))
        );
    }

    #[test]
    #[with_eal]
    fn id_for_lcore_rejects_out_of_range_ids() {
        let manager = Manager::init();
        for id in [LCoreId::MAX, LCoreId::MAX + 1, u32::MAX] {
            assert!(
                manager.id_for_lcore(id).is_none(),
                "lcore id {id} is out of range and must be rejected"
            );
        }
    }

    #[test]
    #[with_eal]
    fn a_valid_lcore_still_resolves() {
        let main = crate::lcore::LCoreId::main();
        assert!(main.as_u32() < LCoreId::MAX);
        assert!(
            SocketId::get_by_lcore_id(main).is_some(),
            "the main lcore must have a socket"
        );
        assert!(SocketId::try_from(Preference::LCore(main)).is_ok());
    }

    #[test]
    #[with_eal]
    fn out_of_range_lcore_ids_are_all_rejected() {
        for id in [LCoreId::MAX, LCoreId::MAX + 1, u32::MAX / 2, u32::MAX] {
            assert!(
                SocketId::get_by_lcore_id(LCoreId(id)).is_none(),
                "lcore id {id} is out of range and must be rejected"
            );
        }
    }
}
