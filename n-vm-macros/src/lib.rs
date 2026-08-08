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
//! order).  Use `#[n_vm::test]` for the default cloud-hypervisor backend or
//! `#[n_vm::test(qemu)]` for QEMU.
//!
//! # Configuring the VM
//!
//! The VM's shape comes from a `const VmConfig`, named by path:
//!
//! ```ignore
//! const DPDK_VM: n_vm::VmConfig = n_vm::VmConfig {
//!     iommu: true,
//!     host_page_size: n_vm::HostPageSize::Standard,
//!     guest_hugepages: n_vm::GuestHugePageConfig::Allocate {
//!         size: n_vm::GuestHugePageSize::Huge2M,
//!         count: 512,
//!     },
//!     nic_model: n_vm::NicModel::E1000,
//!     ..n_vm::VmConfig::DEFAULT
//! };
//!
//! #[n_vm::test(config = DPDK_VM)]
//! fn test_dpdk() {}
//! ```
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
//! An `async fn` runs on a tokio runtime in the guest.  The shape comes from
//! this attribute's own arguments -- a current-thread runtime by default, or
//! `#[n_vm::test(multi_thread)]` / `#[n_vm::test(multi_thread,
//! worker_threads = 4)]` for the multi-threaded scheduler.
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

const KNOWN_BACKENDS: &[(&str, &str)] = &[
    ("cloud_hypervisor", "::n_vm::CloudHypervisor"),
    ("qemu", "::n_vm::Qemu"),
];

const DEFAULT_BACKEND_NAME: &str = "cloud_hypervisor";

/// Options that used to be accepted here, and where they went.
///
/// Kept as errors rather than dropped: a stale option would otherwise read
/// as an unknown one, with no hint about the const that replaced it.
const MIGRATED_OPTIONS: &[(&str, &str)] = &[("iommu", "the `iommu` field of a `const VmConfig`")];

/// Companion attributes this macro used to consume, now replaced by the
/// `config = PATH` argument.
///
/// Detected explicitly because nothing consumes them any more: left alone,
/// `#[guest(...)]` would be an inert attribute and the VM would quietly boot
/// with the default configuration instead of the one the test appears to ask
/// for.
const RETIRED_ATTRS: &[&str] = &["hypervisor", "guest", "network"];

#[must_use]
fn known_backend_list() -> String {
    KNOWN_BACKENDS
        .iter()
        .map(|(name, _)| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[must_use]
fn resolve_backend(ident: &str) -> Option<(&'static str, &'static str)> {
    KNOWN_BACKENDS
        .iter()
        .find(|(name, _)| *name == ident)
        .copied()
}

#[must_use]
fn migration_hint(ident: &str) -> Option<&'static str> {
    MIGRATED_OPTIONS
        .iter()
        .find(|(name, _)| *name == ident)
        .map(|(_, hint)| *hint)
}

struct BackendInfo {
    /// The backend identifier (`cloud_hypervisor` or `qemu`).
    name: &'static str,
    /// Whether the test named a backend explicitly.  When `false` the
    /// backend was defaulted, which means it may fall back to QEMU under
    /// emulation rather than being skipped.
    explicit: bool,
}

/// Everything `#[n_vm::test(...)]` accepts in its own argument list: the
/// hypervisor backend plus the guest-tier tokio runtime shape.
///
/// The runtime options live here rather than on a companion
/// `#[tokio::test]` because this macro *is* the test attribute -- there is
/// no second attribute left to read them from.
struct TestArgs {
    backend: BackendInfo,
    runtime: RuntimeConfig,
    /// Path to the `const VmConfig` describing the VM, if the test named
    /// one.  A path rather than an arbitrary expression on purpose: the
    /// value is then written as a normal item, where an editor can help with
    /// it, and the attribute holds nothing an editor has to parse.
    config: Option<syn::Path>,
}

#[derive(Default)]
struct RuntimeConfig {
    multi_thread: bool,
    worker_threads: Option<usize>,
    /// Span of the option that asked for a multi-threaded runtime, so a
    /// `worker_threads` without `multi_thread` can be reported precisely.
    workers_span: Option<proc_macro2::Span>,
}

fn parse_test_args(attr: TokenStream) -> syn::Result<TestArgs> {
    let mut backend: Option<BackendInfo> = None;
    let mut runtime = RuntimeConfig::default();
    let mut config: Option<syn::Path> = None;

    if attr.is_empty() {
        return Ok(TestArgs {
            backend: BackendInfo {
                name: DEFAULT_BACKEND_NAME,
                explicit: false,
            },
            runtime,
            config,
        });
    }

    use syn::parse::Parser;
    let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
    let metas = parser.parse(attr).map_err(|_| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "#[n_vm::test] expects an optional backend identifier and \
                 runtime options; valid backends are: {}; runtime options \
                 are `current_thread`, `multi_thread`, `worker_threads = N`",
                known_backend_list(),
            ),
        )
    })?;

    for meta in metas {
        match &meta {
            syn::Meta::Path(path) => {
                let Some(ident) = path.get_ident() else {
                    return Err(syn::Error::new_spanned(path, unknown_option_msg("")));
                };
                let name = ident.to_string();

                match name.as_str() {
                    "current_thread" => runtime.multi_thread = false,
                    "multi_thread" => runtime.multi_thread = true,
                    _ => {
                        if let Some(hint) = migration_hint(&name) {
                            return Err(syn::Error::new_spanned(
                                ident,
                                format!(
                                    "`{name}` has moved out of #[n_vm::test(...)] -- \
                                     use {hint} instead",
                                ),
                            ));
                        }
                        let Some((resolved, _path)) = resolve_backend(&name) else {
                            return Err(syn::Error::new_spanned(ident, unknown_option_msg(&name)));
                        };
                        if let Some(prev) = &backend {
                            return Err(syn::Error::new_spanned(
                                ident,
                                format!(
                                    "duplicate backend in #[n_vm::test]: `{prev}` was \
                                     already selected; only one backend is allowed",
                                    prev = prev.name,
                                ),
                            ));
                        }
                        backend = Some(BackendInfo {
                            name: resolved,
                            explicit: true,
                        });
                    }
                }
            }
            syn::Meta::NameValue(nv) => {
                if nv.path.is_ident("config") {
                    if config.is_some() {
                        return Err(syn::Error::new_spanned(
                            &nv.path,
                            "duplicate `config` in #[n_vm::test]",
                        ));
                    }
                    // A path, not an arbitrary expression: the config is
                    // meant to be a named item so that an editor can help
                    // with it.  Rejecting an inline value here is what
                    // steers callers towards writing one.
                    let syn::Expr::Path(syn::ExprPath { path, .. }) = &nv.value else {
                        return Err(syn::Error::new_spanned(
                            &nv.value,
                            "`config` takes the path of a `const VmConfig`, not an \
                             inline value; declare it as an item and name it here, \
                             e.g.\n\n\
                             const FAST_VM: n_vm::VmConfig = \
                             n_vm::VmConfig { iommu: true, ..n_vm::VmConfig::DEFAULT };\n\n\
                             #[n_vm::test(config = FAST_VM)]",
                        ));
                    };
                    config = Some(path.clone());
                } else if nv.path.is_ident("worker_threads") {
                    let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(int),
                        ..
                    }) = &nv.value
                    else {
                        return Err(syn::Error::new_spanned(
                            &nv.value,
                            "worker_threads must be an integer literal",
                        ));
                    };
                    runtime.worker_threads = Some(int.base10_parse()?);
                    runtime.workers_span = Some(nv.path.segments[0].ident.span());
                } else {
                    let name = nv
                        .path
                        .get_ident()
                        .map(ToString::to_string)
                        .unwrap_or_default();
                    return Err(syn::Error::new_spanned(&nv.path, unknown_option_msg(&name)));
                }
            }
            syn::Meta::List(list) => {
                let name = list
                    .path
                    .get_ident()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                return Err(syn::Error::new_spanned(
                    &list.path,
                    unknown_option_msg(&name),
                ));
            }
        }
    }

    // `worker_threads` only means anything to the multi-threaded scheduler;
    // silently ignoring it on a current-thread runtime would misrepresent
    // what the test actually runs on.
    if runtime.worker_threads.is_some() && !runtime.multi_thread {
        return Err(syn::Error::new(
            runtime
                .workers_span
                .unwrap_or_else(proc_macro2::Span::call_site),
            "worker_threads requires `multi_thread`; a current-thread \
             runtime has no worker pool to size",
        ));
    }

    Ok(TestArgs {
        backend: backend.unwrap_or(BackendInfo {
            name: DEFAULT_BACKEND_NAME,
            explicit: false,
        }),
        runtime,
        config,
    })
}

fn unknown_option_msg(name: &str) -> String {
    format!(
        "unknown #[n_vm::test] option `{name}`; expected a backend ({}), \
         a runtime flavor (`current_thread`, `multi_thread`), \
         `worker_threads = N`, or `config = PATH`.  VM options live in a \
         `const VmConfig` named by `config = ...`",
        known_backend_list(),
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

/// Declares a test that runs inside an ephemeral VM.
///
/// This *is* the test attribute -- it injects `#[test]` itself, so do not
/// add one.  A `fn` runs its body directly in the guest; an `async fn`
/// runs on a tokio runtime whose shape comes from this attribute's own
/// arguments (`current_thread` by default).
///
/// ```ignore
/// #[n_vm::test]                                  // cloud-hypervisor, sync
/// fn plain() {}
///
/// const FANCY_VM: n_vm::VmConfig = n_vm::VmConfig {
///     iommu: true,
///     host_page_size: n_vm::HostPageSize::Standard,
///     ..n_vm::VmConfig::DEFAULT
/// };
///
/// #[n_vm::test(qemu, multi_thread, worker_threads = 4, config = FANCY_VM)]
/// async fn fancy() {}
/// ```
///
/// The decorated function must take no parameters and return `()`.  The VM
/// is configured by `config = PATH`, naming a `const VmConfig`; omitting it
/// uses `VmConfig::DEFAULT`.  `#[n_vm::corpus]` may be placed below this
/// attribute to grant the guest a writable corpus directory.
#[proc_macro_attribute]
pub fn test(attr: TokenStream, input: TokenStream) -> TokenStream {
    let TestArgs {
        backend,
        runtime,
        config,
    } = match parse_test_args(attr) {
        Ok(args) => args,
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

    // `#[corpus]` is a bare marker: its presence grants the guest write
    // access to the `__fuzz__` directory beside this test's source file.
    // The path itself is `file!()`, expanded at the call site rather than
    // here, because a proc macro sees only tokens -- rustc is what knows
    // which file it is compiling.
    let corpus_attr = match extract_unique_attr(&mut func.attrs, "corpus") {
        Ok(attr) => attr,
        Err(err) => return err.to_compile_error().into(),
    };
    if let Some(attr) = &corpus_attr
        && !matches!(attr.meta, syn::Meta::Path(_))
    {
        return syn::Error::new_spanned(attr, "#[corpus] takes no arguments")
            .to_compile_error()
            .into();
    }
    let corpus_source_file = if corpus_attr.is_some() {
        quote! { ::core::option::Option::Some(::core::file!()) }
    } else {
        quote! { ::core::option::Option::None }
    };

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

    // The requested backend is resolved against the host architecture at
    // run time by the host tier (see `n_vm::RequestedBackend::resolve`):
    // a defaulted backend falls back to QEMU/TCG for a cross-arch guest,
    // while an explicitly-pinned cloud-hypervisor test is skipped there.
    let requested_backend = if !backend.explicit {
        quote! { ::n_vm::RequestedBackend::Default }
    } else if backend.name == "qemu" {
        quote! { ::n_vm::RequestedBackend::Qemu }
    } else {
        quote! { ::n_vm::RequestedBackend::CloudHypervisor }
    };
    // The base configuration: whatever the test named, or the default.  This
    // macro never inspects it -- it is a path to a `const` whose value only
    // rustc can know -- which is exactly why the checks that used to live
    // here are now `const fn` assertions on the value itself.
    let base_config = match &config {
        Some(path) => quote! { #path },
        None => quote! { ::n_vm::VmConfig::DEFAULT },
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
    let config_ident = format_ident!("__N_VM_CONFIG_{}", ident);
    let cfg_attrs: Vec<_> = harness_attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .collect();

    // The guest body becomes a nested function so that body-level
    // attributes (`#[wrap(...)]`, `#[traced_test]`, ...) apply to it and
    // nowhere else.  `async` is preserved on the inner function and driven
    // by an explicit runtime, since the outer dispatch function is `fn`.
    //
    // Only wrap when there is something to route, because the wrapper is
    // observable: anything deriving a name from its own call site sees the
    // extra frame.  `bolero` builds its on-disk corpus directory from
    // `type_name` of a probe function declared at the `check!()` site, so an
    // unconditional wrapper would bake `__n_vm_guest_body` into that path
    // and make it churn whenever this macro's internals are renamed.
    let wrap_body = !body_attrs.is_empty();
    let asyncness = if is_async {
        quote! { async }
    } else {
        quote! {}
    };
    let invoke_guest_body = if is_async {
        if runtime.multi_thread {
            let workers = match runtime.worker_threads {
                Some(n) => quote! { ::core::option::Option::Some(#n) },
                None => quote! { ::core::option::Option::None },
            };
            quote! {
                ::n_vm::block_on_in_guest_multi_thread(
                    #workers,
                    __n_vm_guest_body(),
                );
            }
        } else {
            quote! { ::n_vm::block_on_in_guest(__n_vm_guest_body()); }
        }
    } else {
        quote! { __n_vm_guest_body(); }
    };

    let tier3_body = if wrap_body {
        quote! {
            #(#body_attrs)*
            #asyncness fn __n_vm_guest_body() #block
            #invoke_guest_body
        }
    } else if is_async {
        // No attributes to route, so drive the body directly and leave the
        // call site's apparent path unchanged.
        if runtime.multi_thread {
            let workers = match runtime.worker_threads {
                Some(n) => quote! { ::core::option::Option::Some(#n) },
                None => quote! { ::core::option::Option::None },
            };
            quote! {
                ::n_vm::block_on_in_guest_multi_thread(#workers, async #block);
            }
        } else {
            quote! { ::n_vm::block_on_in_guest(async #block); }
        }
    } else {
        quote! { #block }
    };

    quote! {
        // Built once; both tiers need it (VmConfig is Copy).  Tier 1 uses it
        // to resolve capability/ISA skips; tier 2 to configure the VM.
        //
        // `corpus_source_file` is always overridden rather than taken from
        // the base config, because it must name *this* test's file:
        // `file!()` expands where it is written, so a shared const would name
        // the const's own file and put the corpus directory beside the wrong
        // source.
        #(#cfg_attrs)*
        #[allow(non_upper_case_globals)]
        const #config_ident: ::n_vm::VmConfig = ::n_vm::VmConfig {
            corpus_source_file: #corpus_source_file,
            ..#base_config
        };

        // The backend/NIC check that used to run inside this macro runs here
        // instead.  A macro sees tokens, so it can never evaluate a config
        // named by path; rustc can, and a `const fn` assertion keeps the
        // failure at build time rather than deferring it to a VM that will
        // not boot.
        #(#cfg_attrs)*
        const _: () = #config_ident.assert_valid_for(#requested_backend);

        #[test]
        #(#harness_attrs)*
        #vis #sig {
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
            ::n_vm::run_host_tier(#ident, #requested_backend, #config_ident);
        }
    }
    .into()
}

/// Companion attribute opting a test in to a writable corpus directory,
/// consumed by [`test`].
///
/// Grants the guest write access to the `__fuzz__` directory beside the
/// test's own source file -- and to nothing else -- so that a fuzzer can
/// persist generated inputs and crash artifacts back to the source tree.
///
/// This is opt-in and spelled out at the call site on purpose.  The guest
/// is otherwise entirely read-only, which is much of the reason to run a
/// test in a VM at all: a fuzz target is deliberately trying to make code
/// misbehave against a real kernel, and it must not be able to damage the
/// developer's working tree.  Marking the tests that do write makes that
/// grant reviewable rather than ambient.
///
/// Takes no arguments.
#[proc_macro_attribute]
pub fn corpus(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[corpus] must be used together with #[n_vm::test] and must \
         appear below it on the same function; e.g.\n\n\
         #[n_vm::test]\n\
         #[corpus]\n\
         fn my_fuzz_test() { ... }",
    )
    .to_compile_error();

    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}
