// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Code that runs on an async executor thread: lexically inside an async fn,
 * closure or block, or in a synchronous function such code calls, minus
 * closures handed to `spawn_blocking`, `block_in_place` or a thread spawn.
 */

import rust
import Lints
import CallGraph

/** Calls that run their closure argument somewhere other than the current task. */
private predicate escapeCall(Call c) {
  c.getStaticTarget()
      .getCanonicalPath()
      .regexpMatch(".*(spawn_blocking|block_in_place)|.*::thread::.*spawn.*|.*Builder.*>::spawn(_scoped|_unchecked)?")
}

private predicate escapeClosure(ClosureExpr cl) {
  exists(Call c | escapeCall(c) and cl = c.getAnArgument())
}

private predicate asyncBoundary(AstNode a) {
  a.(Function).isAsync() or a.(ClosureExpr).isAsync() or a.(BlockExpr).isAsync()
}

private predicate inScope(AstNode n) { inWorkspace(n) and not testOnly(n) and not harness(n) }

/** `n` is lexically inside an async boundary, with no escaping closure in between. */
predicate lexicallyAsync(AstNode n) {
  inScope(n) and
  exists(AstNode a | asyncBoundary(a) and n.getParentNode+() = a |
    not exists(ClosureExpr cl | escapeClosure(cl) and n.getParentNode+() = cl and cl.getParentNode+() = a)
  )
}

/** A synchronous callable that runs on the executor because async code calls it. */
private predicate asyncReached(Callable f) {
  exists(Call c | lexicallyAsync(c) and f = callTarget(c))
  or
  exists(Callable g, Call c | asyncReached(g) and c.getEnclosingCallable() = g and f = callTarget(c))
  or
  exists(Callable g |
    asyncReached(g) and f.(ClosureExpr).getEnclosingCallable() = g and not escapeClosure(f)
  )
}

/** `n` runs on an async executor thread. */
predicate inAsync(AstNode n) {
  lexicallyAsync(n)
  or
  inScope(n) and
  asyncReached(n.getEnclosingCallable()) and
  not exists(ClosureExpr cl | escapeClosure(cl) and n.getParentNode+() = cl)
}

/**
 * A call that blocks the thread, by category. Synchronous locks are left out:
 * they are usually short critical sections, and the dangerous case (a guard
 * alive across an await) is `rust-guard-across-await`.
 */
predicate blockingCall(Call c, string category, string what) {
  // `#[tokio::test]`/`#[tokio::main]` expand to `Runtime::block_on`.
  not c.isFromMacroExpansion() and
  what = c.getStaticTarget().getCanonicalPath() and
  (
    // std moves these between submodules (`std::thread::functions::sleep`).
    what.regexpMatch("std::thread::([a-z_]+::)?(sleep|sleep_ms|sleep_until|scope)|<std::thread::([a-z_]+::)?(Scoped)?JoinHandle(<.*>)?>::join") and
    category = "thread"
    or
    what.regexpMatch("std::fs::(read|read_to_string|write|read_dir|read_link|metadata|symlink_metadata|canonicalize|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all|rename|copy|set_permissions|hard_link|exists)|<std::fs::OpenOptions>::open|<std::fs::File>::(open|create|create_new|sync_all|sync_data|set_len|metadata|set_permissions)|<std::fs::File as .*(Read|Write|Seek)>::.*|<std::fs::ReadDir as .*Iterator>::next|<std::fs::DirEntry>::(metadata|file_type)") and
    category = "fs"
    or
    what.regexpMatch("<std::net::.*|std::net::.*") and category = "net"
    or
    what.regexpMatch(".*std::io::(stdio::)?(stdin|Stdin).*") and category = "stdin"
    or
    what.regexpMatch("<std::sync::(mpsc|mpmc)::.*>::(recv|recv_timeout|send)|<std::sync::(Condvar|condvar::Condvar|Barrier|barrier::Barrier)>::wait.*") and
    category = "sync-wait"
    or
    what.regexpMatch("<std::process::(Command|Child)>::(output|status|wait|wait_with_output)") and
    category = "process"
    or
    what.regexpMatch(".*::block_on") and category = "block_on"
    or
    what.regexpMatch("<tokio::.*>::blocking_(recv|send|lock|read|write)") and
    category = "tokio-blocking"
  )
}
