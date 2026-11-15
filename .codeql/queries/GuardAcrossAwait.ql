// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Guard held across an await point
 * @description A synchronous lock guard (or another guard type) is alive at
 *              an `.await`. The task can be suspended with the lock held,
 *              blocking every thread that wants it, and resume on another
 *              thread. Drop the guard before awaiting.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id rust-guard-across-await
 * @tags correctness
 *       concurrency
 */

// The lint `must_not_suspend` would want, without its blind spot for guards
// inside an `Option`. tokio's own locks are made to be held across awaits and
// are not reported.
import rust
import Lints
import Locks

from GuardSource g, AwaitExpr w
where
  heldAcross(g, w) and
  g.getKind() != "async-lock" and
  not testOnly(g) and
  not harness(g) and
  not suppressed(w, "rust-guard-across-await") and
  // Report each guard once, at its first await.
  not exists(AwaitExpr earlier | heldAcross(g, earlier) and after(earlier, w))
select w, "`" + g.describe() + "` (taken $@) is held across this await.", g, "here"
