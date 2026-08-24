// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![warn(missing_docs)]

//! Attribute macros for running tests inside the `n-vm` nested test
//! environment.
//!
//! `#[n_vm::test]` rewrites a `fn()` or `async fn()` test into a three-tier
//! dispatch:
//!
//! - host: start a Docker container;
//! - container: boot the selected hypervisor backend;
//! - VM guest: run the original test body under `n-it`.
//!
//! It *is* the test attribute -- it injects `#[test]` itself, so there is no
//! companion `#[test]` or `#[tokio::test]` to write (or to get in the wrong
//! order).  It takes one argument, `config = PATH`, and everything else about
//! the VM is a field of the `VmConfig` that names.
//!
//! # Configuring the VM
//!
//! The VM's shape comes from a `const VmConfig`, named by path:
//!
//! ```ignore
//! const DPDK_VM: n_vm::VmConfig = n_vm::VmConfigBuilder::default()
//!     .iommu(true)
//!     .guest_hugepages(n_vm::GuestHugePageConfig::Allocate {
//!         size: n_vm::GuestHugePageSize::Huge2M,
//!         count: 256,
//!     })
//!     .nic_model(n_vm::NicModel::E1000)
//!     .build();
//!
//! #[n_vm::test(config = DPDK_VM)]
//! fn test_dpdk() {}
//! ```
//!
//! Or inline, in the body of the test it configures:
//!
//! ```ignore
//! #[n_vm::test]
//! fn test_dpdk() {
//!     #[n_vm::config]
//!     const _: _ = n_vm::VmConfigBuilder::default()
//!         .iommu(true)
//!         .kernel_features(&[n_vm::features::VFIO_PCI])
//!         .build();
//!
//!     // the test body follows
//! }
//! ```
//!
//! The two forms are equivalent and a test may use either, not both.  A named
//! `const` is right when several tests share a machine; the inline form keeps
//! a one-off beside the test that wants it.  `#[n_vm::config]` is searched for
//! only at the top level of the body, and the `const` is lifted out before
//! anything runs -- so it cannot refer to the test body, which is what the
//! host tier needs: it is evaluated in another process, before the guest
//! exists.
//!
//! This replaces the former `#[hypervisor]`, `#[guest]`, and `#[network]`
//! companion attributes.  The reason is not brevity -- it is that a `const`
//! is ordinary Rust in an ordinary position, so completion, hover, and
//! go-to-definition all work on it, and the enums in `n_vm::config` enforce
//! what those attributes had to hand-check.  `hugepage_count` alongside
//! `hugepage_size = "none"` needed a dedicated error only because the two
//! were independent strings; `GuestHugePageConfig::None` has no count to set.
//!
//! Being `const` also lets the generated code assert the configuration is
//! coherent at compile time, *including against the requested backend* -- so
//! a NIC only QEMU can emulate is still rejected by the build rather than by
//! a VM that fails to boot.
//!
//! An `async fn` runs on a tokio runtime in the guest, shaped by the config's
//! `runtime` field -- current-thread by default, or
//! `GuestRuntime::MultiThread { worker_threads }`.  The worker count sits
//! inside the variant that has one, so a count without a pool is not
//! something that can be written.
//!
//! The hypervisor is the config's `backend`.  "The same VM on both backends"
//! is therefore two configurations, which is what it is; `VmConfig::to_builder`
//! keeps the second to one line.
//!
//! # Attribute routing
//!
//! Attributes below this one decorate the *test body* and are emitted onto an
//! inner function that only the guest tier calls.  That matters for anything
//! with side effects: `#[wrap(with_caps(...))]` needs privileges the guest
//! has and the host does not, so running it on the host tier would fail
//! before a VM ever booted.  The exceptions are the harness-level attributes
//! (`#[cfg]`, `#[ignore]`, doc comments), which stay on the generated
//! dispatch function where libtest and rustdoc can see them.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{ReturnType, parse_macro_input};

/// Options that used to be accepted here, and where they went.
///
/// Kept as errors rather than dropped: a stale option would otherwise read
/// as an unknown one, with no hint about the const that replaced it.
const MIGRATED_OPTIONS: &[(&str, &str)] = &[
    ("iommu", "the `iommu` field of a `const VmConfig`"),
    ("qemu", "`.backend(RequestedBackend::Qemu)` on the config"),
    (
        "cloud_hypervisor",
        "`.backend(RequestedBackend::CloudHypervisor)` on the config",
    ),
    (
        "current_thread",
        "`.runtime(GuestRuntime::CurrentThread)` on the config",
    ),
    (
        "multi_thread",
        "`.runtime(GuestRuntime::MultiThread { worker_threads: None })` on the config",
    ),
    (
        "worker_threads",
        "the `worker_threads` field of `GuestRuntime::MultiThread`",
    ),
];

/// Companion attributes this macro used to consume, now replaced by the
/// `config = PATH` argument.
///
/// Detected explicitly because nothing consumes them any more: left alone,
/// `#[guest(...)]` would be an inert attribute and the VM would quietly boot
/// with the default configuration instead of the one the test appears to ask
/// for.
const RETIRED_ATTRS: &[&str] = &["hypervisor", "guest", "network"];

#[must_use]
fn migration_hint(ident: &str) -> Option<&'static str> {
    MIGRATED_OPTIONS
        .iter()
        .find(|(name, _)| *name == ident)
        .map(|(_, hint)| *hint)
}

/// The one thing `#[n_vm::test(...)]` still accepts in its own argument list.
///
/// A path rather than an arbitrary expression on purpose: the value is then
/// written as a normal item, where an editor can help with it, and the
/// attribute holds nothing an editor has to parse.
///
/// Everything else that used to be spelled here -- the hypervisor backend,
/// the guest tokio runtime -- is a field of the `VmConfig` it configures.
/// The attribute described the machine in one vocabulary while the `const`
/// described it in another, and a reader had to hold both.
fn parse_config_arg(attr: TokenStream) -> syn::Result<Option<syn::Path>> {
    if attr.is_empty() {
        return Ok(None);
    }

    use syn::parse::Parser;
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let metas = parser.parse(attr).map_err(|_| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[n_vm::test] takes an optional `config = PATH` naming a `const VmConfig`, \
             and nothing else",
        )
    })?;

    let mut config: Option<syn::Path> = None;
    for meta in metas {
        let path = meta.path();
        let name = path
            .get_ident()
            .map_or_else(String::new, ToString::to_string);

        if let Some(hint) = migration_hint(&name) {
            return Err(syn::Error::new_spanned(
                path,
                format!("`{name}` has moved out of #[n_vm::test(...)] -- use {hint} instead"),
            ));
        }

        let syn::Meta::NameValue(nv) = &meta else {
            return Err(syn::Error::new_spanned(path, unknown_option_msg(&name)));
        };
        if !nv.path.is_ident("config") {
            return Err(syn::Error::new_spanned(&nv.path, unknown_option_msg(&name)));
        }
        if config.is_some() {
            return Err(syn::Error::new_spanned(
                &nv.path,
                "duplicate `config` in #[n_vm::test]",
            ));
        }
        // Rejecting an inline value here is what steers callers towards
        // writing the config as an item -- or, for a one-off, towards the
        // `#[n_vm::config]` form in the body.
        let syn::Expr::Path(syn::ExprPath { path, .. }) = &nv.value else {
            return Err(syn::Error::new_spanned(
                &nv.value,
                "`config` takes the path of a `const VmConfig`, not an \
                 inline value; declare it as an item and name it here, \
                 e.g.\n\n\
                 const FAST_VM: n_vm::VmConfig = \
                 n_vm::VmConfigBuilder::default().iommu(true).build();\n\n\
                 #[n_vm::test(config = FAST_VM)]\n\n\
                 or write it inline with #[n_vm::config] in the test body.",
            ));
        };
        config = Some(path.clone());
    }

    Ok(config)
}

fn unknown_option_msg(name: &str) -> String {
    format!(
        "unknown #[n_vm::test] option `{name}`; the only argument is \
         `config = PATH`, naming a `const VmConfig`.  Everything about the VM \
         -- backend, runtime, NIC, pages, kernel features -- is a field of \
         that config, set with `n_vm::VmConfigBuilder`."
    )
}

fn is_tokio_test_attr(attr: &syn::Attribute) -> bool {
    let path = attr.path();
    let segs: Vec<_> = path.segments.iter().collect();
    segs.len() == 2 && segs[0].ident == "tokio" && segs[1].ident == "test"
}

/// Attributes that libtest (or rustdoc) must see on the generated dispatch
/// function rather than on the inner guest body.
///
/// `cfg` gates whether the test exists at all, `ignore` is read by the test
/// harness, and doc comments belong on the item a reader navigates to.
/// Everything else is treated as decorating the *body* -- see the routing
/// comment in [`test`] for why that default matters.
///
/// `cfg_attr` is deliberately body-level: it most often expands to a body
/// wrapper (`#[cfg_attr(not(emulated), traced_test)]`), and we cannot know
/// what it expands to from here.  A conditional `ignore` therefore has to be
/// written as a plain `#[ignore]`.
const HARNESS_ATTRS: &[&str] = &["cfg", "ignore", "doc"];

fn is_harness_attr(attr: &syn::Attribute) -> bool {
    HARNESS_ATTRS.iter().any(|name| attr.path().is_ident(name))
}

const KNOWN_ATTR_PREFIXES: &[&str] = &["n_vm", "n_vm_macros"];

fn attr_has_name(attr: &syn::Attribute, name: &str) -> bool {
    let path = attr.path();
    if path.is_ident(name) {
        return true;
    }
    let segments: Vec<_> = path.segments.iter().collect();
    segments.len() == 2
        && KNOWN_ATTR_PREFIXES
            .iter()
            .any(|prefix| segments[0].ident == prefix)
        && segments[1].ident == name
}

fn extract_unique_attr(
    attrs: &mut Vec<syn::Attribute>,
    name: &str,
) -> syn::Result<Option<syn::Attribute>> {
    let idx = match attrs.iter().position(|a| attr_has_name(a, name)) {
        Some(i) => i,
        None => return Ok(None),
    };
    let attr = attrs.remove(idx);

    if let Some(dup) = attrs.iter().find(|a| attr_has_name(a, name)) {
        return Err(syn::Error::new_spanned(
            dup,
            format!("duplicate #[{name}] attribute"),
        ));
    }

    Ok(Some(attr))
}

/// Finds a `#[n_vm::config]` const item in a test body, removes it, and
/// returns its initializer.
///
/// A `const` item rather than a `let` for three reasons, all load-bearing.
/// It is an *item*, so a custom attribute on it is ordinary stable Rust --
/// attributes on statements are not.  It cannot capture anything from the
/// body, which is exactly the constraint the host tier needs: the
/// configuration is evaluated in another process, before the guest exists.
/// The initializer keeps the spans it was written with, so naming a local is
/// reported as E0425 *at that name in the test body* rather than somewhere
/// inside generated code.  And it keeps `VmConfig::assert_valid` running at
/// compile time.
///
/// Only the top level of the body is searched.  Items nest -- inside a
/// helper `fn`, a closure, an inner block -- and a marker found at depth
/// would either be lifted out of a scope it appears to belong to or ignored
/// altogether; both are worse than not finding it.
///
/// The type must be the placeholder `_`, and is discarded along with the
/// item -- only the initializer is used.  That spelling is legal only because
/// the item is deleted before rustc sees it; in a real const item it is
/// E0121, which is exactly the signal a reader should get.
fn extract_inline_config(block: &mut syn::Block) -> syn::Result<Option<syn::Expr>> {
    let mut found: Option<usize> = None;
    for (idx, stmt) in block.stmts.iter().enumerate() {
        let syn::Stmt::Item(syn::Item::Const(item)) = stmt else {
            continue;
        };
        if !item.attrs.iter().any(|attr| attr_has_name(attr, "config")) {
            continue;
        }
        if found.is_some() {
            return Err(syn::Error::new_spanned(
                item,
                "duplicate #[n_vm::config] in this test body; a test describes one VM",
            ));
        }
        // The type is required to be `_`, because it is discarded.  Written
        // out it would look checked and would not be: the item is re-declared
        // as `::n_vm::VmConfig` and only the initializer survives, so
        // `const _: u32 = ...` would compile and mean nothing.  `_` also makes
        // the construct honest about where it works -- a placeholder is E0121
        // in a real const item, so a marker copied out of a test body says so
        // immediately rather than silently configuring nothing.
        if !matches!(*item.ty, syn::Type::Infer(_)) {
            return Err(syn::Error::new_spanned(
                &item.ty,
                "#[n_vm::config] is written `const _: _ = ...`; the type is not \
                 yours to state.  The item is lifted out of the body and \
                 re-declared as `n_vm::VmConfig`, so a type written here would be \
                 discarded rather than checked.",
            ));
        }
        found = Some(idx);
    }

    let Some(idx) = found else {
        return Ok(None);
    };
    let syn::Stmt::Item(syn::Item::Const(item)) = block.stmts.remove(idx) else {
        unreachable!("the index came from a matched const item");
    };
    Ok(Some(*item.expr))
}

/// Declares a test that runs inside an ephemeral VM.
///
/// This *is* the test attribute -- it injects `#[test]` itself, so do not
/// add one.  A `fn` runs its body directly in the guest; an `async fn`
/// runs on a tokio runtime whose shape comes from the config's `runtime`
/// field (current-thread by default).
///
/// ```ignore
/// #[n_vm::test]                                  // cloud-hypervisor, sync
/// fn plain() {}
///
/// const FANCY_VM: n_vm::VmConfig = n_vm::VmConfigBuilder::default()
///     .iommu(true)
///     .backend(n_vm::RequestedBackend::Qemu)
///     .runtime(n_vm::GuestRuntime::MultiThread { worker_threads: Some(4) })
///     .build();
///
/// #[n_vm::test(config = FANCY_VM)]
/// async fn fancy() {}
/// ```
///
/// The decorated function must take no parameters and return `()`.  The VM
/// is configured either by `config = PATH`, naming a `const VmConfig`, or by
/// a `#[n_vm::config]` `const` in the body; with neither it uses
/// `VmConfig::DEFAULT`.  A writable corpus directory is granted by
/// `.corpus(CorpusPolicy::Fuzz)` on that configuration.
#[proc_macro_attribute]
pub fn test(attr: TokenStream, input: TokenStream) -> TokenStream {
    let config = match parse_config_arg(attr) {
        Ok(config) => config,
        Err(err) => return err.to_compile_error().into(),
    };

    let mut func = parse_macro_input!(input as syn::ItemFn);

    // This macro owns the test attribute, so a user-written `#[test]` or
    // `#[tokio::test]` is always a mistake -- and a silent one if we just
    // dropped it, because `#[tokio::test]` would have carried runtime
    // options we no longer read.  Reject both with the migration.
    if let Some(bad) = func
        .attrs
        .iter()
        .find(|a| a.path().is_ident("test") || is_tokio_test_attr(a))
    {
        let is_tokio = is_tokio_test_attr(bad);
        let hint = if is_tokio {
            "#[n_vm::test] already provides the test harness and the guest \
             tokio runtime: remove #[tokio::test] and move its options into \
             #[n_vm::test(...)] (e.g. `#[n_vm::test(multi_thread, \
             worker_threads = 4)]`)"
        } else {
            "#[n_vm::test] already provides the test harness: remove the \
             #[test] attribute"
        };
        return syn::Error::new_spanned(bad, hint).to_compile_error().into();
    }

    // `#[should_panic]` cannot compose with `#[n_vm::test]`: the test body runs
    // in a separate VM-guest process, and the generated function is run by
    // libtest at all three dispatch tiers (host, container, guest).  A
    // panic is absorbed at whichever tier produces it, so `should_panic`
    // semantics are incoherent across tiers (and depend on whether the
    // guest panic unwinds cleanly).  Reject it with a clear message rather
    // than miscompile.
    if let Some(attr) = func
        .attrs
        .iter()
        .find(|a| a.path().is_ident("should_panic"))
    {
        return syn::Error::new_spanned(
            attr,
            "#[should_panic] is not supported with #[n_vm::test]: the test body runs \
             in a separate VM-guest process across three dispatch tiers, so panic \
             semantics do not compose.  Assert the failure condition inside the \
             test body instead (e.g. `assert!(result.is_err())`).",
        )
        .to_compile_error()
        .into();
    }

    let is_async = func.sig.asyncness.is_some();

    if !func.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &func.sig.inputs,
            "#[n_vm::test] functions must take no parameters; \
             the function is re-invoked by name as `fn()` inside the VM guest",
        )
        .to_compile_error()
        .into();
    }

    if !matches!(func.sig.output, ReturnType::Default) {
        return syn::Error::new_spanned(
            &func.sig.output,
            "#[n_vm::test] functions must return `()`; \
             the generated dispatch branches use bare `return;` statements",
        )
        .to_compile_error()
        .into();
    }

    // A leftover companion attribute is now inert rather than wrong-looking,
    // so it has to be caught explicitly: left alone the VM would quietly boot
    // with the default configuration instead of the one the test appears to
    // ask for.
    if let Some(stale) = func
        .attrs
        .iter()
        .find(|a| RETIRED_ATTRS.iter().any(|name| attr_has_name(a, name)))
    {
        let name = stale
            .path()
            .segments
            .last()
            .map_or_else(String::new, |s| s.ident.to_string());
        return syn::Error::new_spanned(
            stale,
            format!(
                "#[{name}] has been replaced by a `const VmConfig`; declare one \
                 and name it with `config = ...`, e.g.\n\n\
                 const MY_VM: n_vm::VmConfig = \
                 n_vm::VmConfig {{ iommu: true, ..n_vm::VmConfig::DEFAULT }};\n\n\
                 #[n_vm::test(config = MY_VM)]",
            ),
        )
        .to_compile_error()
        .into();
    }

    // `#[corpus]` is now `.corpus(CorpusPolicy::Fuzz)` on the config.  It is
    // rejected here rather than silently ignored, because a fuzz target that
    // quietly lost its writable share does not fail: it runs, generates
    // inputs, and saves none of them.
    if let Ok(Some(attr)) = extract_unique_attr(&mut func.attrs, "corpus") {
        return syn::Error::new_spanned(
            attr,
            "#[corpus] has been replaced by `.corpus(CorpusPolicy::Fuzz)` on \
             the config, e.g.\n\n\
             #[n_vm::config]\n\
             const _: _ = n_vm::VmConfigBuilder::default()\n\
             \u{20}   .corpus(n_vm::CorpusPolicy::Fuzz)\n\
             \u{20}   .build();",
        )
        .to_compile_error()
        .into();
    }

    // `CARGO_MANIFEST_DIR` rides along because `file!()` is not reliably
    // workspace-relative here: this workspace builds with
    // `--remap-path-prefix==${src}`, which rewrites it to an absolute nix
    // store path.  The crate directory is the anchor that recovers the
    // workspace-relative tail (see `VmConfig::corpus_rel_dir`).  Both are
    // expanded at the call site rather than here, because a proc macro sees
    // only tokens -- rustc is what knows which file it is compiling.
    //
    // Injected unconditionally now that the fuzz decision lives in the
    // config: this macro cannot read a `const`, so it can no longer tell
    // whether the file will be wanted.  It costs two `&'static str`s in a
    // struct that is already `const`.
    let source_file = quote! {
        ::core::option::Option::Some((
            ::core::file!(),
            ::core::env!("CARGO_MANIFEST_DIR"),
        ))
    };

    // The inline configuration, if the body declares one.  Removed from the
    // block here, so no tier sees it as part of the test.
    let inline_config = match extract_inline_config(&mut func.block) {
        Ok(found) => found,
        Err(err) => return err.to_compile_error().into(),
    };
    if let (Some(path), Some(expr)) = (&config, &inline_config) {
        return syn::Error::new_spanned(
            expr,
            format!(
                "this test is configured twice: `config = {path}` names one \
                 `const VmConfig` and #[n_vm::config] declares another.  Keep one.",
                path = quote! { #path },
            ),
        )
        .to_compile_error()
        .into();
    }

    // Split the remaining attributes by which tier they belong to.
    //
    // Anything left on the generated dispatch function runs at *every*
    // tier -- host, container, and guest.  That is wrong for the common
    // case: `#[wrap(with_caps([CAP_NET_ADMIN]))]` exists precisely because
    // the body needs privileges it can only have inside the guest, and
    // running it on the unprivileged host tier fails with EPERM before a VM
    // is ever started.  So only harness-level attributes (the ones libtest
    // itself must see) stay outside; everything else moves onto an inner
    // function that only the guest branch calls.
    let (harness_attrs, body_attrs): (Vec<_>, Vec<_>) =
        func.attrs.iter().cloned().partition(is_harness_attr);

    let block = &func.block;
    let vis = &func.vis;
    let ident = &func.sig.ident;

    let mut sig = func.sig.clone();
    sig.asyncness = None;

    // Named here because the discovery shim below branches on its value.
    let config_ident = format_ident!("__N_VM_CONFIG_{}", ident);

    // Tier 0, and only for a fuzz target.
    //
    // `cargo bolero list` runs this binary with `CARGO_BOLERO_SELECT=all` and collects a line that
    // each `bolero::check!` prints *as it executes*. The body never executes on the host -- that is
    // what this attribute is for -- so without this an in-VM fuzz target is invisible to the
    // coverage-guided runner and can never be named to `cargo bolero test`.
    //
    // Answering here rather than by running the body is the point: a body may open netlink sockets,
    // bind devices or assume it is root, none of which may happen on a developer's workstation
    // merely because something asked what tests exist.
    //
    // Emitted for every test but *entered* only by a fuzz target. Announcing every tiered test
    // would put forty-odd entries containing no `check!` into a list whose whole purpose is naming
    // things that can be fuzzed.
    //
    // The guard is a `const fn` on a `const`, so rustc folds it: an ordinary test compiles to
    // nothing at all here. It has to be a runtime-shaped branch rather than a macro-level one
    // because the decision now lives in the configuration, and a proc macro sees tokens -- given
    // `config = SOME_VM` it cannot know what `SOME_VM` holds. Moving the branch from the macro to
    // the value is the whole reason this reads as a branch.
    //
    // `should_run` is `true` whenever `CARGO_BOLERO_SELECT` is unset, so an ordinary run falls
    // straight through. `__item_path__!` must expand at the call site or it names a path inside
    // `n-vm`; what it yields here is the *outer* test's path, which is the name libtest accepts as
    // a filter when `cargo bolero test` selects it.
    let discovery = quote! {
        if #config_ident.is_fuzz_target() {
            let __n_vm_bolero_location = ::n_vm::bolero::TargetLocation {
                package_name: ::core::env!("CARGO_PKG_NAME"),
                manifest_dir: ::core::env!("CARGO_MANIFEST_DIR"),
                module_path: ::core::module_path!(),
                file: ::core::file!(),
                line: ::core::line!(),
                item_path: ::n_vm::bolero::__item_path__!(),
                test_name: ::core::option::Option::None,
            };
            if !__n_vm_bolero_location.should_run() {
                return;
            }
        }
    };

    // The requested backend is resolved against the host architecture at
    // The base configuration: whatever the test named, or the default.  This
    // macro never inspects it -- it is a path to a `const` whose value only
    // rustc can know -- which is exactly why the checks that used to live
    // here are now `const fn` assertions on the value itself.
    let base_config = match (&config, &inline_config) {
        (Some(path), _) => quote! { #path },
        (None, Some(expr)) => quote! { #expr },
        (None, None) => quote! { ::n_vm::VmConfig::DEFAULT },
    };

    // The config and its assertion are emitted beside the test function
    // rather than inside it, because `#[test]` items are stripped in a
    // non-test build -- an assertion in the body would vanish with them, and
    // could never be exercised by a compile-fail test.  At module scope it
    // is checked in every build.
    //
    // Only `#[cfg]` carries over: a config for a test that does not exist
    // would fail to compile if it referenced cfg'd-out items.  `#[ignore]`
    // and doc comments are meaningless on a const.
    let cfg_attrs: Vec<_> = harness_attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .collect();

    // The guest body becomes a nested function so that body-level
    // attributes (`#[wrap(...)]`, `#[traced_test]`, ...) apply to it and
    // nowhere else.
    //
    // The wrapper is deliberately a plain `fn` even for an `async` test: the
    // runtime is driven *inside* it, so a routed attribute sees a function
    // that returns `()`.  Routing them onto an `async fn` instead would hand
    // every such attribute a future, which is not what any of them expect --
    // `fixin::wrap` expands to `with_caps(..)(__n_vm_guest_body)` in the
    // wrapper's own tail position, so an async inner function fails to
    // compile with "expected `()`, found future".  This also matches what
    // these attributes saw before this macro existed, where `#[tokio::test]`
    // expanded first and left them a synchronous function.
    //
    // Only wrap when there is something to route, because the wrapper is
    // observable: anything deriving a name from its own call site sees the
    // extra frame.  `bolero` builds its on-disk corpus directory from
    // `type_name` of a probe function declared at the `check!()` site, so an
    // unconditional wrapper would bake `__n_vm_guest_body` into that path
    // and make it churn whenever this macro's internals are renamed.
    let wrap_body = !body_attrs.is_empty();
    // The runtime shape is a value in the config, not a token this macro can
    // read, so it is passed through rather than branched on.  A const, so the
    // match inside `block_on_in_guest_with` folds away.
    let drive_async_block = || {
        quote! {
            ::n_vm::block_on_in_guest_with(#config_ident.runtime, async #block);
        }
    };

    let tier3_body = if wrap_body {
        let wrapped_block = if is_async {
            let drive = drive_async_block();
            quote! { { #drive } }
        } else {
            quote! { #block }
        };
        quote! {
            #(#body_attrs)*
            fn __n_vm_guest_body() #wrapped_block
            __n_vm_guest_body();
        }
    } else if is_async {
        // No attributes to route, so drive the body directly and leave the
        // call site's apparent path unchanged.
        drive_async_block()
    } else {
        quote! { #block }
    };

    quote! {
        // Built once; both tiers need it (VmConfig is Copy).  Tier 1 uses it
        // to resolve capability/ISA skips; tier 2 to configure the VM.
        //
        // `source_file` is always overridden rather than taken from
        // the base config, because it must name *this* test's file:
        // `file!()` expands where it is written, so a shared const would name
        // the const's own file and put the corpus directory beside the wrong
        // source.
        #(#cfg_attrs)*
        #[allow(non_upper_case_globals)]
        const #config_ident: ::n_vm::VmConfig = ::n_vm::VmConfig {
            source_file: #source_file,
            ..(#base_config)
        };

        // The backend/NIC check that used to run inside this macro runs here
        // instead.  A macro sees tokens, so it can never evaluate a config
        // named by path; rustc can, and a `const fn` assertion keeps the
        // failure at build time rather than deferring it to a VM that will
        // not boot.
        #(#cfg_attrs)*
        const _: () = #config_ident.assert_valid();

        #[test]
        #(#harness_attrs)*
        #vis #sig {
            #discovery
            // Tier 3: VM guest
            if ::n_vm::is_in_vm() {
                { #tier3_body }
                return;
            }

            // Tier 2: Docker container -> VM.  The backend and acceleration
            // mode were resolved by tier 1 and passed via the environment.
            if ::n_vm::is_in_test_container() {
                ::n_vm::run_container_tier(#ident, #config_ident);
                return;
            }

            // Tier 1: Host -> Docker container.  Resolves the requested
            // backend + capabilities against the host arch / Docker daemon.
            ::n_vm::run_host_tier(#ident, #config_ident);
        }
    }
    .into()
}

/// Marks the `const` in a test body that describes the VM, consumed by
/// [`test`].
///
/// ```ignore
/// #[n_vm::test]
/// fn drives_a_nic() {
///     #[n_vm::config]
///     const _: _ = n_vm::VmConfigBuilder::default()
///         .iommu(true)
///         .build();
///
///     // the test body follows
/// }
/// ```
///
/// [`test`] removes this before rustc resolves it, so the definition here
/// only ever runs when the marker is used somewhere [`test`] does not reach
/// -- which is the entire reason it exists rather than being left
/// unresolvable.
#[proc_macro_attribute]
pub fn config(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[n_vm::config] marks a `const` inside the body of a #[n_vm::test] \
         function, and is consumed by it; e.g.\n\n\
         #[n_vm::test]\n\
         fn my_test() {\n\
         \x20   #[n_vm::config]\n\
         \x20   const _: _ = n_vm::VmConfigBuilder::default().iommu(true).build();\n\n\
         \x20   // the test body follows\n\
         }\n\n\
         Only the top level of the body is searched, so a marker nested inside \
         an inner function, closure or block is not found.",
    )
    .to_compile_error();

    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}

/// Superseded by `.corpus(CorpusPolicy::Fuzz)` on the configuration.
///
/// Kept only so that the old spelling gets a compile error naming its
/// replacement.  It moved for the reason everything else moved out of this
/// macro: the grant now has to be visible to the *rest* of the
/// configuration -- a fuzz target declines the hugepage reservation, which
/// could not be decided while one half lived in an attribute and the other
/// in a `const`.
///
/// The grant is still opt-in and still spelled out at the call site.  The
/// guest is otherwise entirely read-only, which is much of the reason to
/// run a test in a VM at all: a fuzz target is deliberately trying to make
/// code misbehave against a real kernel, and it must not be able to damage
/// the developer's working tree.
#[proc_macro_attribute]
pub fn corpus(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[corpus] has been replaced by `.corpus(CorpusPolicy::Fuzz)` on \
         the config, e.g.\n\n\
         #[n_vm::config]\n\
         const _: _ = n_vm::VmConfigBuilder::default()\n\
         \u{20}   .corpus(n_vm::CorpusPolicy::Fuzz)\n\
         \u{20}   .build();",
    )
    .to_compile_error();

    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}
