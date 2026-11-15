// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Inconsistent lock order
 * @description Two locks are taken in both orders somewhere in the workspace,
 *              or a lock is taken while a guard of the same lock is held.
 *              Either can deadlock.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id rust-lock-order
 * @tags correctness
 *       concurrency
 */

// Locks are named `Struct.field` (or by static), so all instances of one field
// are one lock. Acquisitions through a local or a parameter have no name and
// are not checked yet.
//
// Test code is excluded: the one hit there takes the same field of two
// different instances (forward and reply flow), which a name cannot tell apart.
import rust
import Lints
import Locks

from string k1, string k2, Acquire held, Call via, Acquire inner, string msg
where
  orderEdge(k1, k2, held, via, inner) and
  not testOnly(via) and
  not suppressed(via, "rust-lock-order") and
  (
    k1 != k2 and
    exists(Acquire h2 | orderEdge(k2, k1, h2, _, _) and not testOnly(h2)) and
    msg = "`" + k2 + "` taken while `" + k1 + "` is held; elsewhere the order is reversed."
    or
    k1 = k2 and
    msg = "`" + k1 + "` taken while a `" + k1 + "` guard is held (re-entrant, or two instances)."
  )
select via, msg
