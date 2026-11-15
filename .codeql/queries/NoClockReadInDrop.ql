// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Clock read in a Drop implementation
 * @description Do not read the clock from a `Drop` implementation. Once
 *              anything has paused the virtual clock, tokio routes every read
 *              through the calling thread's runtime context; a `Drop` running
 *              during thread-local teardown may find that context gone, and
 *              tokio panics inside the destructor, aborting the process.
 *              Take the reading before the value is dropped, or record the
 *              instant when the value is created.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id rust-no-clock-read-in-drop
 * @tags correctness
 */

// Replaces .semgrep/rules/no-clock-read-in-drop.yaml. Same id, same exclusions,
// same `nosemgrep` suppressions.
//
// Like the opengrep rule this matches any `fn drop(&mut self)` and any call
// nested in it, closures included. It also matches a facade read however it is
// spelled (`use clock::now; now()`), which opengrep cannot see. It does NOT yet
// follow calls out of `drop`; the call graph would allow it.
import rust
import Lints

predicate excluded(File f) { underAny(f, ".codeql/tests/, clock/src/") }

/** A `fn drop(&mut self)`, as in opengrep's `pattern-inside`. */
predicate dropFn(Function f) {
  f.getName().getText() = "drop" and
  f.getParamList().getSelfParam().isMut() and
  f.getParamList().getSelfParam().isRef() and
  not exists(f.getParamList().getParam(_))
}

/**
 * A node inside the body of a `fn drop(&mut self)`. Walked down from the body
 * so it stays bounded by drop bodies; `getParentNode+()` upwards from every
 * call in the database is far slower.
 */
AstNode inDrop(Function drop) {
  dropFn(drop) and result = drop.getFunctionBody()
  or
  result.getParentNode() = inDrop(drop)
}

from Call c, Function drop
where
  c = inDrop(drop) and
  firstParty(c.getLocation().getFile()) and
  not excluded(c.getLocation().getFile()) and
  not suppressed(c, "rust-no-clock-read-in-drop") and
  writtenInSource(c.(CallExpr).getFunction().(PathExpr).getPath()) and
  (
    fullPath(c.(CallExpr).getFunction().(PathExpr).getPath()) = ["clock::now", "clock::system_now"]
    or
    // `dataplane_clock::now` in the workspace; any `clock` module in the fixture.
    resolvedCallee(c).regexpMatch("(.*::)?(dataplane_)?clock::(now|system_now)")
  )
select c, "Clock read in `Drop`; take the reading before the value is dropped."
