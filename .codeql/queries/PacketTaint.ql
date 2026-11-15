// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Unchecked packet bytes reach an index, bound, subtraction or allocation
 * @description A value read from packet bytes in a `Parse` implementation is
 *              used as an index, slice bound, subtrahend or allocation size
 *              without a bounds check. A crafted packet can make it panic,
 *              underflow, or allocate as much as the sender likes.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id rust-packet-taint
 * @tags security
 *       correctness
 */

import rust
import Lints
import PacketTaint
import PacketFlow::PathGraph

from PacketFlow::PathNode src, PacketFlow::PathNode snk, string kind
where
  PacketFlow::flowPath(src, snk) and
  sink(snk.getNode(), kind) and
  not suppressed(snk.getNode().asExpr(), "rust-packet-taint")
select snk.getNode(), src, snk, kind + ": packet bytes from $@ reach this unchecked.",
  src.getNode(), "a parser input"
