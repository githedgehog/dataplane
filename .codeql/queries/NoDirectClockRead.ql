// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Clock read bypassing the clock facade
 * @description Read the clock via `clock::now()` (or `clock::system_now()`
 *              for wall time), not `Instant::now()` / `SystemTime::now()`.
 *              Under the `virtual` feature the facade reads tokio's pausable
 *              clock; reading `std` directly makes deadlines and timers
 *              diverge in tests that advance time. `anchor.elapsed()` is the
 *              same read in disguise; use `clock::elapsed(anchor)`.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id rust-no-direct-clock-read
 * @tags correctness
 */

// Replaces .semgrep/rules/no-std-time-direct.yaml. Same id, same exclusions,
// same `nosemgrep` suppressions.
//
// A call is flagged if it is *written* as one of the opengrep patterns, or if
// it *resolves* to `std`'s or tokio's `now()` however it is spelled (an alias,
// or `clock::Instant::now()` through the facade's re-export of the type).
// Resolution is by name only (`resolvedCallee`), not type inference, which
// would cost ~2 min.
import rust
import Lints

predicate excluded(File f) { underAny(f, ".codeql/tests/, clock/src/, concurrency/tests/") }

/** Written forms from the opengrep rule. */
predicate writtenClockRead(string written) {
  written =
    [
      "Instant::now", "std::time::Instant::now", "SystemTime::now", "std::time::SystemTime::now",
      "tokio::time::Instant::now"
    ]
}

/** Canonical paths of the clock reads, however they are spelled. */
predicate resolvedClockRead(string canonical) {
  canonical =
    [
      "<std::time::Instant>::now", "<std::time::SystemTime>::now",
      "<tokio::time::instant::Instant>::now"
    ]
}

from Expr e, string what
where
  firstParty(e.getLocation().getFile()) and
  not excluded(e.getLocation().getFile()) and
  not suppressed(e, "rust-no-direct-clock-read") and
  (
    exists(CallExpr c, string written | c = e |
      written = fullPath(c.getFunction().(PathExpr).getPath()) and
      writtenInSource(c.getFunction().(PathExpr).getPath()) and
      writtenClockRead(written) and
      what = "`" + written + "()`"
    )
    or
    exists(CallExpr c, string canonical | c = e |
      canonical = resolvedCallee(c) and
      resolvedClockRead(canonical) and
      // Not inside code a macro generated: a dependency's macro reading the
      // clock is not something we can change at the call site.
      writtenInSource(c.(CallExpr).getFunction().(PathExpr).getPath()) and
      not writtenClockRead(fullPath(c.(CallExpr).getFunction().(PathExpr).getPath())) and
      what = "a call resolving to `" + canonical + "`"
    )
    or
    // Any receiver, as in the opengrep rule: `$ANCHOR.elapsed()`.
    exists(MethodCallExpr m | m = e |
      m.getIdentifier().getText() = "elapsed" and
      // Written in the source: the identifier's span is exactly `elapsed`.
      exists(Location l | l = m.getIdentifier().getLocation() |
        l.getStartLine() = l.getEndLine() and l.getEndColumn() - l.getStartColumn() = 6
      ) and
      not exists(m.getArgList().getArg(_)) and
      what = "`.elapsed()`"
    )
  )
select e, what + " reads the clock directly; use `clock::now()`, `clock::system_now()` or `clock::elapsed(anchor)`."
