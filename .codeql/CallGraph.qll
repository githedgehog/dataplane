// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * A call graph for the semantic queries.
 *
 * Unlike the opengrep ports, these need CodeQL's type inference (to resolve
 * method calls), which costs ~2 min on the workspace, paid once per run.
 */

import rust

/**
 * Dynamic dispatch with more candidates than this is not followed.
 * `Clone::clone` alone has ~15,000 implementations in the database, and
 * following it makes everything reach everything.
 */
int maxFanout() { result = 8 }

/**
 * The callables `c` may run: its static target if that has a body, else its
 * dispatch set if that is small. Dependencies are extracted without bodies,
 * so calls into them end here.
 */
Callable callTarget(Call c) {
  result = c.getStaticTarget() and exists(result.(Function).getFunctionBody())
  or
  not exists(c.getStaticTarget().(Function).getFunctionBody()) and
  count(c.getARuntimeTarget()) <= maxFanout() and
  result = c.getARuntimeTarget()
}

/** Holds if `c` dispatches to more candidates than `maxFanout()` and is not followed. */
predicate cutDispatch(Call c) {
  not exists(c.getStaticTarget().(Function).getFunctionBody()) and
  count(c.getARuntimeTarget()) > maxFanout()
}

/** One call-graph step, including closures defined inside a callable. */
predicate callStep(Callable a, Callable b) {
  exists(Call c | c.getEnclosingCallable() = a and b = callTarget(c))
  or
  b.(ClosureExpr).getEnclosingCallable() = a
}
