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
        // Delegated rather than checked here, because the check this used to do was wrong:
        // `rte_lcore_count()` is the number of *enabled* lcores, not the highest valid id, and
        // lcore ids are not required to be dense. `--lcores 0@(0),7@(7)` enables ids 0 and 7 with
        // a count of 2, so comparing an id against the count rejected lcore 7 -- a perfectly
        // valid, enabled lcore -- while accepting id 1, which is not enabled at all. Both
        // directions wrong from one comparison.
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

    /// Look up a [`SocketId`] by the lcore it is associated with.
    ///
    /// Returns `None` unless `id` is both in range and an lcore the EAL actually enabled.
    ///
    /// Two distinct checks, for two distinct reasons.
    ///
    /// The range check is a memory-safety requirement.
    /// [`rte_lcore_to_socket_id`](dpdk_sys::rte_lcore_to_socket_id) indexes a fixed array with no
    /// checking of its own -- its contract says the argument "MUST be between 0 and
    /// RTE_MAX_LCORE-1" -- and the value most likely to be passed here is
    /// [`LCoreId::current`](crate::lcore::LCoreId::current), which is `LCORE_ID_ANY`
    /// (`u32::MAX`) on any thread that is neither an EAL thread nor registered. Handing that
    /// through read wildly out of bounds and segfaulted, from entirely safe code.
    ///
    /// The enabled check is a correctness one: an in-range id the EAL did not enable has whatever
    /// socket the array happened to be initialised with, which is a plausible-looking answer to a
    /// question that has none.
    #[must_use]
    pub fn get_by_lcore_id(id: LCoreId) -> Option<SocketId> {
        if id.as_u32() >= LCoreId::MAX {
            return None;
        }
        // Checked before the lookup rather than relying on `rte_lcore_is_enabled` to range-check
        // for us, so the ordering here does not depend on a DPDK internal.
        if unsafe { dpdk_sys::rte_lcore_is_enabled(id.as_u32()) } == 0 {
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
    /// Use the socket of a specific lcore index.
    LCore(LCoreId),
    /// Use the socket of the device.
    Dev(DevIndex),
}

impl TryFrom<Preference> for SocketId {
    // TODO: this is a silly error type.  Design something better.
    type Error = ErrorCode;

    fn try_from(value: Preference) -> Result<Self, Self::Error> {
        match value {
            // `rte_socket_id` reads a per-thread value and is safe to call from anywhere,
            // reporting `ANY` on a thread with no NUMA affinity.  The lcore route is *not*: it
            // used to go through `get_by_lcore_id(LCoreId::current())`, and on any non-EAL thread
            // `current()` is `LCORE_ID_ANY`, which indexed an array out of bounds and segfaulted.
            // Since this is the `#[default]` preference, that was reachable from a plain
            // `RxQueueConfig { .. }` on the wrong thread.
            Preference::CurrentThread => Ok(SocketId::current()),
            Preference::Id(id) => Ok(id),
            Preference::LCore(lcore_id) => SocketId::get_by_lcore_id(lcore_id)
                .ok_or(ErrorCode::Standard(StandardErrno::InvalidArgument)),
            Preference::Dev(dev) => dev.socket_id(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::with_eal;

    /// Regression test for a segfault reachable from safe code.
    ///
    /// `rte_lcore_to_socket_id` indexes a fixed array and requires its argument to be a real
    /// lcore id. `LCoreId::current()` is `LCORE_ID_ANY` (`u32::MAX`) on any thread that is
    /// neither an EAL thread nor registered, and `get_by_lcore_id` used to pass it straight
    /// through -- reading wildly out of bounds. Since `Preference::CurrentThread` is the
    /// `#[default]`, a plain `RxQueueConfig { .. }` built on the wrong thread was enough to hit
    /// it.
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
        .expect("far thread panicked -- it should not even be able to fault now");

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

    /// The set of lcores the EAL actually enabled, from DPDK's own predicate.
    ///
    /// Deliberately not `LCoreId::iter()`: that passes `skip_main = 1` to `rte_get_next_lcore`,
    /// so it enumerates *worker* lcores and is empty under the test EAL, which enables only the
    /// main lcore. Scanning the predicate is the ground truth this needs.
    fn enabled_lcores() -> Vec<u32> {
        (0..LCoreId::MAX)
            .filter(|id| unsafe { dpdk_sys::rte_lcore_is_enabled(*id) } != 0)
            .collect()
    }

    /// The invariant the old `id_for_lcore` violated: every lcore the EAL enabled must resolve to
    /// a socket.
    ///
    /// Honest about its own strength -- this does not currently *catch* the bug it describes. The
    /// old check compared an lcore id against `rte_lcore_count()`, which only goes wrong when ids
    /// are sparse, and the test EAL passes `--lcores 0@(0,1,...)`, which enables exactly one
    /// lcore (id 0) and so is dense. The road tests pass no `--lcores` at all, enabling every
    /// detected lcore, which is also dense. A sparse `--lcores 0@(0),7@(7)` is what distinguishes
    /// them, and there is no way to get one here: DPDK permits a single `rte_eal_init` per
    /// process, and the shared test EAL's arguments exist for an unrelated reason (thread
    /// affinity -- see `eal::main_lcore_arg`). Kept because it is the right assertion and would
    /// hold a regression under any configuration that does exercise it.
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

    /// An id that is in range but not enabled is rejected, rather than answered with whatever the
    /// array happened to hold.
    #[test]
    #[with_eal]
    fn an_in_range_but_disabled_lcore_is_rejected() {
        let enabled = enabled_lcores();
        let Some(disabled) = (0..LCoreId::MAX).find(|id| !enabled.contains(id)) else {
            return; // every lcore enabled; nothing to assert
        };
        let manager = Manager::init();
        assert!(
            manager.id_for_lcore(disabled).is_none(),
            "lcore {disabled} is not enabled and must not resolve"
        );
    }

    /// And an out-of-range id is rejected without indexing on it.
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

    /// An in-range lcore still resolves, so the bounds check did not break the useful case.
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

    /// Every lcore id at or past `RTE_MAX_LCORE` is rejected rather than indexed.
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
