// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * Lock acquisitions, guards and how long guards live, for the lock-order and
 * guard-across-await queries.
 *
 * Guard lifetimes are modelled lexically, after the edition 2024 rules: a
 * guard bound by `let` lives to the end of its block or an explicit
 * `drop(guard)`; a temporary guard lives to the end of its temporary scope
 * (statement, `if` condition, match arm, ...). Guards moved elsewhere (into a
 * struct, returned from the function) are not followed.
 */

import rust
import Lints
import CallGraph

/** A lock-type method that acquires: `lock`, `read`, `write` and their `try_` forms. */
bindingset[t]
private predicate acquireTarget(string t) {
  t.regexpMatch(".*(Mutex|RwLock)(<.*>)?>?::(lock|read|write|try_lock|try_read|try_write|upgradable_read|lock_owned|read_owned|write_owned)")
}

/** Holds if `n` is inside a lock type's own implementation (e.g. the `concurrency` facade's `Mutex::lock`). */
private predicate inWrapper(AstNode n) {
  exists(Impl i, Function f |
    n.getParentNode+() = f and
    f = i.getAssocItemList().getAnAssocItem() and
    i.getSelfTy().toString().regexpMatch(".*(Mutex|RwLock).*")
  )
}

/** A function whose declared return type is a guard (`MutexGuard`, `FlowTableReadGuard`, ...). */
private predicate returnsGuard(Function f) {
  f.getRetType().getTypeRepr().toString().regexpMatch(".*Guard.*")
}

private Expr peel(Expr e) {
  if e instanceof ParenExpr
  then result = peel(e.(ParenExpr).getExpr())
  else
    if e instanceof RefExpr
    then result = peel(e.(RefExpr).getExpr())
    else
      if e instanceof PrefixExpr
      then result = peel(e.(PrefixExpr).getExpr())
      else result = e
}

/** A call in workspace code that produces a guard. */
class GuardSource extends Call {
  string kind;

  GuardSource() {
    inWorkspace(this) and
    not inWrapper(this) and
    not this.isFromMacroExpansion() and
    (
      acquireTarget(this.getStaticTarget().getCanonicalPath()) and
      this instanceof MethodCallExpr and
      if this.getStaticTarget().getCanonicalPath().matches("%tokio%")
      then kind = "async-lock"
      else kind = "sync-lock"
      or
      not acquireTarget(this.getStaticTarget().getCanonicalPath()) and
      returnsGuard(this.getStaticTarget()) and
      not this.getStaticTarget().getCanonicalPath().matches("%tokio%") and
      kind = "guard"
    )
  }

  /** `sync-lock`, `async-lock` (tokio, made to be held across awaits) or `guard` (another guard type). */
  string getKind() { result = kind }

  /** The lock's name if it has one, else the function producing the guard. */
  string describe() {
    result = this.(Acquire).key()
    or
    not exists(this.(Acquire).key()) and result = this.getStaticTarget().getCanonicalPath()
  }
}

/** A lock acquisition in workspace code. */
class Acquire extends GuardSource, MethodCallExpr {
  Acquire() { kind = ["sync-lock", "async-lock"] }

  /** The receiver with references, derefs and parentheses peeled off. */
  Expr base() { result = peel(this.getReceiver()) }

  /**
   * A name for the lock: `Struct.field` for a field, the path for a static.
   * None for locks reached through a local or a parameter.
   */
  string key() {
    exists(StructField sf, Struct s |
      sf = this.base().(FieldExpr).getStructField() and sf.getParentNode+() = s
    |
      result = s.getName().getText() + "." + sf.getName().getText()
    )
    or
    exists(FieldExpr fe, Struct s | fe = this.base() and fe.getTupleField().getParentNode+() = s |
      result = s.getName().getText() + "." + fe.getIdentifier().getText()
    )
    or
    exists(PathExpr p | p = peel(this.base().(IndexExpr).getBase()) |
      p.getPath().toString().regexpMatch("[A-Z][A-Z0-9_]+(::[A-Z][A-Z0-9_]+)*") and
      result = "static " + p.getPath().toString() + "[]"
    )
    or
    exists(PathExpr p | p = this.base() |
      p.getPath().toString().regexpMatch("[A-Z][A-Z0-9_]+(::[A-Z][A-Z0-9_]+)*") and
      result = "static " + p.getPath().toString()
    )
  }
}

/** The value a guard is bound from, through `.unwrap()`, `.expect()`, `?`, `.await` and `Some(..)`. */
private Expr guardValue(GuardSource g) {
  result = g
  or
  exists(Expr inner | inner = guardValue(g) |
    result.(MethodCallExpr).getReceiver() = inner and
    result.(MethodCallExpr).getIdentifier().getText() = ["unwrap", "expect", "unwrap_or_else"]
    or
    result.(TryExpr).getExpr() = inner
    or
    result.(AwaitExpr).getExpr() = inner
    or
    // `Some(guard)` keeps the guard alive: the `Option` blind spot of `must_not_suspend`.
    result.(CallExpr).getFunction().(PathExpr).getPath().toString() = "Some" and
    result.(CallExpr).getArgList().getArg(0) = inner
  )
}

/** The `let` that binds the guard from `g` to a name, if any. */
private LetStmt guardLet(GuardSource g) {
  result.getInitializer() = guardValue(g) and result.getPat() instanceof IdentPat
}

/** The block a `let`-bound guard lives in. */
private BlockExpr guardBlock(GuardSource g) {
  result = guardLet(g).getParentNode+() and
  not exists(BlockExpr inner |
    inner = guardLet(g).getParentNode+() and inner.getParentNode+() = result
  )
}

/** An explicit `drop(guard)` that ends a `let`-bound guard early. */
private CallExpr dropOf(GuardSource g) {
  exists(Variable v |
    v.getPat() = guardLet(g).getPat() and
    result.getFunction().(PathExpr).getPath().toString().regexpMatch("((std|core)::)?(mem::)?drop") and
    result.getArgList().getArg(0).(VariableAccess).getVariable() = v and
    result.getParentNode+() = guardBlock(g) and
    after(g, result)
  )
}

/**
 * A temporary-scope boundary (edition 2024): a node at which temporaries
 * created inside it are dropped.
 */
private predicate tempBoundary(AstNode x) {
  x = any(IfExpr i | not i.getCondition() instanceof LetExpr).getCondition()
  or
  x = any(WhileExpr w | not w.getCondition() instanceof LetExpr).getCondition()
  or
  x instanceof MatchGuard
  or
  x = any(MatchArm m).getExpr()
  or
  x instanceof MatchExpr
  or
  x instanceof ExprStmt
  or
  x instanceof LetStmt
  or
  x = any(StmtList l).getTailExpr()
  or
  x = any(IfExpr i | i.getCondition() instanceof LetExpr)
  or
  x = any(WhileExpr w | w.getCondition() instanceof LetExpr)
}

/** The innermost temporary scope around a temporary guard. */
private AstNode tempScope(GuardSource g) {
  result = g.getParentNode+() and
  tempBoundary(result) and
  not exists(AstNode mid |
    mid = g.getParentNode+() and tempBoundary(mid) and mid.getParentNode+() = result
  )
}

/** Holds if `n` is lexically inside the region where the guard from `g` is alive. */
bindingset[n]
private predicate inHeldRegion(GuardSource g, AstNode n) {
  after(g, n) and
  (
    n.getParentNode+() = guardBlock(g) and not after(dropOf(g), n)
    or
    not exists(guardLet(g)) and
    exists(AstNode sc | sc = tempScope(g) |
      n.getParentNode+() = sc and
      // `if let`: the scrutinee's temporaries are gone in the `else` branch.
      not n.getParentNode*() = sc.(IfExpr).getElse()
    )
  )
}

/** Holds if call `n` runs while the guard from `a` is held. */
predicate whileHeld(Acquire a, Call n) {
  n.getEnclosingCallable() = a.getEnclosingCallable() and inHeldRegion(a, n)
}

/** `f`, or something it calls, acquires lock `key`; `site` is the acquisition. */
predicate acquires(Callable f, string key, Acquire site) {
  site.getEnclosingCallable() = f and key = site.key()
  or
  exists(Call c, Callable g |
    c.getEnclosingCallable() = f and
    inWorkspace(c) and
    g = callTarget(c) and
    acquires(g, key, site)
  )
}

/**
 * Lock `k2` is taken while `k1` is held: `held` holds `k1`; `via` is the
 * acquisition of `k2` itself or a call that leads to it (`inner`).
 */
predicate orderEdge(string k1, string k2, Acquire held, Call via, Acquire inner) {
  k1 = held.key() and
  (
    whileHeld(held, inner) and via = inner and k2 = inner.key()
    or
    whileHeld(held, via) and acquires(callTarget(via), k2, inner)
  )
}

/** The innermost async boundary (async fn, closure or block) around `n`. */
private AstNode asyncScope(AstNode n) {
  result = n.getParentNode+() and
  (result.(Function).isAsync() or result.(ClosureExpr).isAsync() or result.(BlockExpr).isAsync()) and
  not exists(AstNode mid |
    mid = n.getParentNode+() and
    mid.getParentNode+() = result and
    (mid.(ClosureExpr).isAsync() or mid.(BlockExpr).isAsync())
  )
}

/** `w` suspends the task while the guard from `g` is alive. */
predicate heldAcross(GuardSource g, AwaitExpr w) {
  asyncScope(w) = asyncScope(g) and inHeldRegion(g, w)
}
