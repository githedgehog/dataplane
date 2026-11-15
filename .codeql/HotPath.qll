// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/**
 * The packet path: everything reachable from the methods of
 * `impl NetworkFunction for ...` outside test code, through the call graph in
 * `CallGraph.qll`. Dispatch wider than `maxFanout()` is not followed.
 */

import rust
import Lints
import CallGraph

/** A method of `impl NetworkFunction for ...`, outside test code. */
predicate packetRoot(Function f) {
  exists(Impl i |
    f = i.getAssocItemList().getAnAssocItem() and
    i.getTrait().getName().getText() = "NetworkFunction" and
    inWorkspace(f) and
    not testOnly(f)
  )
}

/** Holds if `c` runs on the packet path. */
predicate onPacketPath(Callable c) { exists(Function r | packetRoot(r) and callStep*(r, c)) }

/**
 * Calls that allocate (or may reallocate). `Vec::new` and `String::new` do not
 * allocate; `Arc::clone` is a refcount bump. Growth methods may reallocate.
 */
bindingset[t]
private predicate allocating(string t) {
  t.regexpMatch("<alloc::(vec::Vec|string::String|collections::[a-z_]+::[A-Za-z]+)(<.*>)?>::(with_capacity|push|push_str|insert|extend|extend_from_slice|reserve|resize|append|from|to_owned|split_off|repeat)")
  or
  t.regexpMatch("<alloc::(boxed::Box|sync::Arc|rc::Rc)(<.*>)?>::(new|new_uninit|from|pin)")
  or
  t.regexpMatch("<alloc::(vec::Vec|string::String|boxed::Box|collections::[a-z_]+::[A-Za-z]+)(<.*>)? as core::clone::Clone>::clone")
  or
  t.regexpMatch("<.* as alloc::(string::ToString|borrow::ToOwned)>::(to_string|to_owned)|<alloc::slice::.*>::to_vec|alloc::fmt::format|<.* as core::iter::traits::collect::FromIterator<.*>>::from_iter")
  or
  t.regexpMatch("<.* as core::iter::traits::collect::Extend<.*>>::extend")
}

/**
 * Something on the packet path that costs a lock, a blocking syscall, an
 * allocation or a possible panic. `what` names it. Logging macros are left
 * out: they are many, and mostly rate-limited or debug level.
 */
predicate packetPathSink(AstNode n, string category, string what) {
  onPacketPath(n.getEnclosingCallable()) and
  inWorkspace(n) and
  not testOnly(n) and
  (
    exists(Call c | c = n and what = c.getStaticTarget().getCanonicalPath() |
      allocating(what) and category = "alloc"
      or
      what.regexpMatch(".*(Mutex|RwLock)(<.*>)?>?::(lock|read|write|try_lock|try_read|try_write)") and
      category = "lock"
      or
      what.regexpMatch("<core::(option::Option|result::Result)(<.*>)?>::(unwrap|expect)") and
      category = "panic"
      or
      what.regexpMatch("<?std::(fs|net)::.*|std::thread::([a-z_]+::)?sleep.*|std::io::(stdio::)?(stdout|stderr).*") and
      category = "blocking"
    )
    or
    exists(MacroCall m, string name | m = n and name = m.getPath().toString() |
      name.regexpMatch("(core::|std::)?(panic|unreachable|todo|unimplemented)") and
      category = "panic" and
      what = name + "!"
      or
      name.regexpMatch("(alloc::|std::)?(vec|format)") and category = "alloc" and what = name + "!"
    )
  )
}
