// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Blocking call on an async executor thread
 * @description A blocking call (file system, network, thread sleep or join,
 *              channel wait, process wait, `block_on`) runs on an executor
 *              thread, directly in async code or in a synchronous function
 *              async code calls. It stalls every task on that thread. Use the
 *              async equivalent or `spawn_blocking`.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id rust-blocking-in-async
 * @tags advisory
 *       concurrency
 */

import rust
import Lints
import AsyncBlocking

from Call c, string category, string what, string how
where
  inAsync(c) and
  blockingCall(c, category, what) and
  not suppressed(c, "rust-blocking-in-async") and
  if lexicallyAsync(c) then how = "in async code" else how = "in a function async code calls"
select c, category + ": `" + what + "` blocks the executor thread (" + how + ")."
