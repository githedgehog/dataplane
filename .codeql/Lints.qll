// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Shared helpers for the dataplane lint queries.
 *
 * These queries replace the opengrep rules in `.semgrep/rules/`, one query per
 * rule, keeping each rule's id, path exclusions and `// nosemgrep: <id>`
 * suppressions so the two tools can run side by side during the switch.
 *
 * One deliberate exception to using only public `codeql/rust-all` API:
 * `resolvedCallee` uses the internal `PathResolution` module, to resolve calls
 * without CodeQL's whole-program type inference (see there). Internal API can
 * change in any release; the fixtures pin resolution-only positives so a
 * break fails `just codeql-lint-test` instead of going quiet.
 */

import rust
private import codeql.rust.internal.PathResolution

/**
 * Holds if `f` is workspace source rather than a dependency or sysroot file.
 *
 * Only files in the database's source archive have a relative path.
 */
predicate firstParty(File f) { exists(f.getRelativePath()) }

/**
 * Holds if `f` is under one of `prefixes`, each either a directory ending in
 * `/` or an exact file path; the same shape as an opengrep `paths.exclude`.
 */
bindingset[prefixes]
predicate underAny(File f, string prefixes) {
  exists(string rel, string p |
    rel = f.getRelativePath() and
    p = prefixes.splitAt(",").trim() and
    p != ""
  |
    if p.matches("%/") then rel.matches(p + "%") else rel = p
  )
}

/**
 * A comment in workspace source that mentions a suppression marker, with its
 * text and start column. Prefiltered with cheap substring tests: the sysroot
 * and dependencies carry millions of comments, and running the regexes below
 * over all of them dominated the query time (404 s -> 23 s).
 */
private predicate suppressionComment(File f, int line, int col, string text) {
  exists(Comment c |
    c.getLocation().getFile() = f and
    firstParty(f) and
    c.getLocation().getStartLine() = line and
    c.getLocation().getStartColumn() = col and
    text = c.getCommentText() and
    (text.matches("%nosemgrep%") or text.matches("%codeql[%"))
  )
}

/**
 * Holds if the comment at `line`:`col` of `f` suppresses `ruleId`.
 *
 * Mirrors opengrep: `nosemgrep` alone suppresses every rule, and
 * `nosemgrep: a, b` suppresses only the listed ones. `codeql[id]` is accepted
 * too, so new suppressions need not mention opengrep.
 */
bindingset[ruleId]
private predicate suppresses(File f, int line, int col, string ruleId) {
  exists(string text | suppressionComment(f, line, col, text) |
    exists(string body | body = text.regexpCapture("(?i).*\\bnosemgrep\\b(.*)", 1) |
      not body.regexpMatch("\\s*:.*")
      or
      body.regexpCapture("\\s*:\\s*([A-Za-z0-9_, -]+).*", 1).splitAt(",").trim() = ruleId
    )
    or
    text.regexpCapture(".*\\bcodeql\\[([A-Za-z0-9_, -]+)\\].*", 1).splitAt(",").trim() = ruleId
  )
}

/**
 * Holds if code starts before the suppression comment at `line`:`col`, i.e.
 * the comment trails code rather than standing alone.
 *
 * "Starts before" rather than "starts on the line": rust-analyzer attaches a
 * leading `//` comment to the item that follows it, so that item starts at the
 * comment's own position, and a plain "anything on this line" test would call
 * every standalone comment a trailing one.
 */
private predicate trailsCode(File f, int line, int col) {
  suppressionComment(f, line, col, _) and
  exists(AstNode n, Location l |
    not n instanceof Comment and
    l = n.getLocation() and
    l.getFile() = f and
    l.getStartLine() = line and
    l.getStartColumn() < col
  )
}

/**
 * The line opengrep anchors a finding on `n` to: the start of the whole `use`
 * tree for an import (a multi-line group is one match starting at `use`), the
 * node's own line otherwise.
 */
int anchorLine(AstNode n) {
  if exists(UseTree t | n.getParentNode+() = t and not t.getParentNode() instanceof UseTreeList)
  then
    exists(UseTree t | n.getParentNode+() = t and not t.getParentNode() instanceof UseTreeList |
      result = t.getLocation().getStartLine()
    )
  else result = n.getLocation().getStartLine()
}

/**
 * Holds if a finding on `n` for `ruleId` is suppressed, as opengrep would: by
 * a comment on the finding's line or its anchor line, or by a comment standing
 * alone on the line directly above the anchor line.
 */
bindingset[ruleId]
predicate suppressed(AstNode n, string ruleId) {
  exists(File f | f = n.getLocation().getFile() |
    suppresses(f, [n.getLocation().getStartLine(), anchorLine(n)], _, ruleId)
    or
    exists(int line, int col |
      line = anchorLine(n) - 1 and
      suppresses(f, line, col, ruleId) and
      not trailsCode(f, line, col)
    )
  )
}

/**
 * The path text spelled by `p`'s own segments, without the prefix inherited
 * from enclosing `use` groups: `Arc` for the `Arc` in `use std::sync::{Arc}`.
 */
private string ownText(Path p) {
  firstParty(p.getLocation().getFile()) and
  (
    not p.hasQualifier() and result = segmentText(p)
    or
    result = ownText(p.getQualifier()) + "::" + segmentText(p)
  )
}

/**
 * Holds if `p` is written in the source, as opposed to generated by a macro.
 *
 * Paths a macro *generates* (clap's derive emits `std::sync::OnceLock`) carry
 * the span of the macro call, not of tokens spelling the path; opengrep, which
 * reads the source text, never sees them. A path whose span is exactly as wide
 * as its own text came from the source, including paths passed to a macro as
 * arguments (`assert!(x == std::sync::Arc::new(1))`), which opengrep does see.
 */
predicate writtenInSource(Path p) {
  not p.isInMacroExpansion()
  or
  exists(Location l | l = p.getLocation() |
    l.getStartLine() = l.getEndLine() and
    l.getEndColumn() - l.getStartColumn() + 1 = ownText(p).length()
  )
}

/** The identifier text of `p`'s last segment, e.g. `Arc` for `std::sync::Arc`. */
string segmentText(Path p) { result = p.getSegment().getIdentifier().getText() }

/**
 * Gets the `UseTree` whose (possibly qualified) path is, or ends in, `p`.
 */
private UseTree useTreeOf(Path p) {
  result.getPath() = p
  or
  exists(Path parent | parent.getQualifier() = p | result = useTreeOf(parent))
}

/**
 * The `::` prefix that a nested use tree inherits from its enclosing groups,
 * e.g. `std::` for `sync::Arc` in `use std::{sync::Arc}`. Empty at top level.
 */
private string useTreePrefix(UseTree t) {
  exists(UseTree outer | t = outer.getUseTreeList().getAUseTree() |
    // `fullPath` of the outer path already carries the outer tree's own prefix.
    result = fullPath(outer.getPath()) + "::"
    or
    not outer.hasPath() and result = useTreePrefix(outer)
  )
  or
  not t = any(UseTree outer).getUseTreeList().getAUseTree() and result = ""
}

/**
 * The path as written, with any enclosing `use` groups spelled out:
 * `std::sync::atomic::AtomicU64` for `AtomicU64` in
 * `use std::{sync::{atomic::{AtomicU64}}}`. Generic arguments are dropped.
 */
string fullPath(Path p) {
  // Workspace files only: the sysroot and dependencies are ~95 % of the paths
  // in the database, and nothing reports on them.
  firstParty(p.getLocation().getFile()) and
  not p.hasQualifier() and
  (
    exists(UseTree t | t = useTreeOf(p) | result = useTreePrefix(t) + segmentText(p))
    or
    not exists(useTreeOf(p)) and result = segmentText(p)
  )
  or
  firstParty(p.getLocation().getFile()) and
  result = fullPath(p.getQualifier()) + "::" + segmentText(p)
}

/**
 * The canonical path of the function a path call (`a::b::f(..)`) names,
 * resolved by name resolution alone.
 *
 * `Call.getStaticTarget()` would do, but it needs CodeQL's full type
 * inference, which costs ~2 min on this workspace (one library predicate makes
 * 262M rows). Path calls need no types to resolve. Method calls are not
 * covered; the queries match those syntactically.
 *
 * `PathResolution` is internal CodeQL API: an upgrade can break this, and the
 * fixtures (which pin resolution-only positives) are what catch it.
 */
string resolvedCallee(CallExpr c) {
  firstParty(c.getLocation().getFile()) and
  result = resolvePath(c.getFunction().(PathExpr).getPath()).(Addressable).getCanonicalPath()
}
