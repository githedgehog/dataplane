// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Lock, blocking call, allocation or panic on the packet path
 * @description Code reachable from a `NetworkFunction` that takes a lock,
 *              makes a blocking call, allocates, or may panic. Advisory: some
 *              of these are deliberate (setup on first use, invariants).
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id rust-packet-path-sink
 * @tags advisory
 *       performance
 */

import rust
import Lints
import HotPath

from AstNode s, string category, string what
where packetPathSink(s, category, what) and not suppressed(s, "rust-packet-path-sink")
select s, category + ": `" + what + "` on the packet path."
