// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Taint from the packet bytes handed to `dataplane_net::parse::Parse`
 * implementations to indexes, slice bounds, subtractions and allocation sizes.
 *
 * Bounds checks that stop the taint: a comparison against an upper bound (as
 * in GitHub's allocation-size query), and the workspace idiom of checking via
 * `.get(..)` (`let Some(x) = buf.get(..n) else { .. }`).
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.security.UncontrolledAllocationSizeExtensions
import codeql.rust.security.AccessInvalidPointerExtensions
import Lints

/** `parse` in an `impl dataplane_net::parse::Parse for ...`. */
private predicate parseImpl(Function f) {
  exists(Impl i |
    f = i.getAssocItemList().getAnAssocItem() and
    f.getName().getText() = "parse" and
    // The fixture declares its own `Parse`.
    i.getTrait().(Addressable).getCanonicalPath().regexpMatch("dataplane_net::parse::Parse|test::.*Parse") and
    inWorkspace(f)
  )
}

/** Packet bytes: the `buf: &[u8]` handed to every parser. */
class PacketBytes extends DataFlow::Node {
  PacketBytes() { exists(Function f | parseImpl(f) and this.asParameter() = f.getParam(0)) }
}

/** A sink, with its kind. */
predicate sink(DataFlow::Node n, string kind) {
  n instanceof UncontrolledAllocationSize::Sink and kind = "alloc-size"
  or
  n instanceof AccessInvalidPointer::Sink and kind = "pointer"
  or
  exists(IndexExpr ix |
    inWorkspace(ix) and not ix.getIndex() instanceof RangeExpr and n.asExpr() = ix.getIndex()
  ) and
  kind = "index"
  or
  exists(IndexExpr ix, RangeExpr r |
    inWorkspace(ix) and r = ix.getIndex() and n.asExpr() = [r.getStart(), r.getEnd()]
  ) and
  kind = "slice-bound"
  or
  // `a - b` underflows when `b > a`: the subtracted value is what matters.
  exists(BinaryArithmeticOperation b |
    inWorkspace(b) and b.getOperatorName() = "-" and n.asExpr() = b.getRhs()
  ) and
  kind = "subtract"
}

/** `e` was compared against an upper bound on this branch. */
private predicate upperBoundCheck(AstNode g, Expr e, boolean branch) {
  g =
    any(BinaryExpr cmp |
      e = cmp.(RelationalOperation).getLesserOperand() and branch = true
      or
      e = cmp.(RelationalOperation).getGreaterOperand() and branch = false
    )
}

/**
 * The bounds-check idiom: `let Some(x) = s.get(..n) else { return .. }` (or
 * `s.get(n)?`, `if let Some(..) = s.get(a..b)`). After a variable is used
 * inside `.get(..)`, later uses of it in the same function count as checked.
 * Approximate: it does not verify that the `None` path leaves.
 */
private predicate checkedByGet(VariableAccess later) {
  exists(MethodCallExpr get, VariableAccess inGet, Variable v |
    get.getIdentifier().getText() = ["get", "get_mut", "split_at_checked"] and
    inGet.getParentNode+() = get.getArgList() and
    inGet.getVariable() = v and
    later.getVariable() = v and
    later.getEnclosingCallable() = get.getEnclosingCallable() and
    after(get, later)
  )
}

module PacketConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof PacketBytes }

  predicate isSink(DataFlow::Node n) { sink(n, _) }

  /**
   * Dependencies are extracted without bodies, so CodeQL cannot see data pass
   * through them (etherparse, for one). Assume a call into a bodiless
   * function outside the standard library returns something derived from its
   * arguments.
   */
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(Call c |
      inWorkspace(c) and
      not exists(c.getStaticTarget().(Function).getFunctionBody()) and
      not c.getStaticTarget().getCanonicalPath().regexpMatch("<(core|alloc|std)::.*|(core|alloc|std)::.*") and
      a.asExpr() = [c.getAnArgument(), c.(MethodCallExpr).getReceiver()] and
      b.asExpr() = c
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    n = DataFlow::BarrierGuard<upperBoundCheck/3>::getABarrierNode()
    or
    checkedByGet(n.asExpr())
  }
}

module PacketFlow = TaintTracking::Global<PacketConfig>;
