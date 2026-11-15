// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * @name Config invariant enforced at runtime
 * @description An `Option` field of a `dataplane_config` type is assumed
 *              present: `unwrap`/`expect`, `unwrap_or_else` with a panicking
 *              closure, or a `None` branch that panics. Encode the invariant
 *              in the validated type instead (development guide: use static
 *              typing to enforce validity constraints).
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id rust-config-option-assumed
 * @tags advisory
 *       maintainability
 */

import rust
import Lints

/** An `Option` field of a config-model struct (the fixture's stand-ins are named `Cfg*`). */
predicate configOptionField(StructField sf, string name) {
  exists(Struct s |
    sf.getParentNode+() = s and
    s.(Addressable).getCanonicalPath().regexpMatch("dataplane_config::.*|test::.*Cfg.*") and
    sf.getTypeRepr().toString().regexpMatch("Option(::<.*>|<.*>)?") and
    name = s.getName().getText() + "." + sf.getName().getText()
  )
}

/** The field read, seen through `&`, parentheses, `.as_ref()`, `.as_deref()`, `.clone()`, ... */
Expr viewOf(FieldExpr fe) {
  result = fe
  or
  exists(Expr inner | inner = viewOf(fe) |
    result.(RefExpr).getExpr() = inner
    or
    result.(ParenExpr).getExpr() = inner
    or
    result.(MethodCallExpr).getReceiver() = inner and
    result.(MethodCallExpr).getIdentifier().getText() =
      ["as_ref", "as_deref", "clone", "as_mut", "copied", "cloned"]
  )
}

/** A panic-family macro inside `n`, not inside a nested closure. */
predicate panics(AstNode n) {
  exists(MacroCall m |
    m.getParentNode*() = n and
    m.getPath().toString().regexpMatch("(core::|std::)?(panic|unreachable|todo|unimplemented)")
  |
    not exists(ClosureExpr c | m.getParentNode+() = c and c.getParentNode+() = n)
  )
}

predicate isNonePat(Pat p) {
  p.(PathPat).getPath().toString() = "None" or p.(IdentPat).getName().getText() = "None"
}

/**
 * `fe` reads config `Option` field `field`. `conf` says how sure: resolved by
 * type, or matched by field name alone when CodeQL could not infer the
 * receiver's type (1-17 % of field reads per crate, e.g. an iterator's item).
 */
predicate readsConfigOption(FieldExpr fe, string field, string conf) {
  configOptionField(fe.getStructField(), field) and conf = ""
  or
  not exists(fe.getStructField()) and
  not exists(fe.getTupleField()) and
  exists(StructField sf |
    configOptionField(sf, field) and sf.getName().getText() = fe.getIdentifier().getText()
  ) and
  conf = " [matched by field name; receiver type unresolved]"
}

from FieldExpr fe, string field, AstNode use, string how, string conf
where
  readsConfigOption(fe, field, conf) and
  inWorkspace(fe) and
  not testOnly(fe) and
  (
    exists(MethodCallExpr m | m.getReceiver() = viewOf(fe) and use = m |
      m.getIdentifier().getText() = ["unwrap", "expect", "unwrap_unchecked"] and
      how = "." + m.getIdentifier().getText() + "()"
      or
      m.getIdentifier().getText() = "unwrap_or_else" and
      panics(m.getArgList().getArg(0)) and
      how = ".unwrap_or_else(panic)"
    )
    or
    exists(MatchExpr me, MatchArm arm |
      me.getScrutinee() = viewOf(fe) and
      arm = me.getMatchArmList().getAnArm() and
      isNonePat(arm.getPat()) and
      panics(arm.getExpr()) and
      use = arm and
      how = "`None =>` arm that panics"
    )
    or
    exists(LetStmt s |
      s.getInitializer() = viewOf(fe) and
      panics(s.getLetElse()) and
      use = s and
      how = "`let ... else` that panics"
    )
  ) and
  not suppressed(use, "rust-config-option-assumed")
select use,
  "`" + field + "` is assumed present (" + how + "); encode the invariant in the validated type." +
    conf
