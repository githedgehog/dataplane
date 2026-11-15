// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Synchronization primitive imported from std::sync
 * @description Import synchronization primitives via `concurrency::sync::*`,
 *              not `std::sync::*`. The facade hands out parking_lot-backed
 *              locks in production and loom/shuttle equivalents under the
 *              model-checker features; reaching `std::sync` directly bypasses
 *              that backend swap.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id rust-no-direct-std-sync-import
 * @tags correctness
 *       concurrency
 */

// Replaces .semgrep/rules/no-std-sync-direct.yaml. Same id, same names, same
// exclusions, same `nosemgrep` suppressions.
//
// The rule matches the path *as written*, not what it resolves to: the facade
// re-exports `std::sync::Arc`, so `concurrency::sync::Arc` and `std::sync::Arc`
// resolve to the same item, and only the spelling tells them apart. `fullPath`
// spells out enclosing `use` groups, so `use std::{sync::{atomic::AtomicU64}}`
// is caught as well (opengrep 1.x missed that shape).
import rust
import Lints

/** The names under `std::sync` that must come from the facade. */
string guardedName() {
  result =
    [
      "Arc", "Weak", "Mutex", "MutexGuard", "RwLock", "RwLockReadGuard", "RwLockWriteGuard",
      "OnceLock", "LazyLock", "Once", "Barrier", "Condvar", "PoisonError", "atomic"
    ]
}

predicate excluded(File f) {
  underAny(f,
    "concurrency/src/sync/, concurrency/src/quiescent.rs, concurrency/src/slot.rs, " +
      "concurrency/tests/, n-vm/, n-vm-macros/, n-vm-protocol/, n-it/, n-preinit/")
}

from Path p, string written
where
  written = fullPath(p) and
  written = "std::sync::" + guardedName() and
  firstParty(p.getLocation().getFile()) and
  writtenInSource(p) and
  not excluded(p.getLocation().getFile()) and
  not suppressed(p, "rust-no-direct-std-sync-import")
select p,
  "`" + written + "` bypasses the `concurrency::sync` facade; import it from `concurrency::sync` instead."
