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
//! `#[n_vm::test(qemu)]` for QEMU.  Companion attributes must sit below it
//! so this macro can consume them:
//!
//! ```ignore
//! #[n_vm::test(qemu)]
//! #[hypervisor(iommu, host_pages = "4k")]
//! #[guest(hugepage_size = "2m", hugepage_count = 512)]
//! #[network(nic_model = "e1000")]
//! fn test_dpdk() {}
//! ```
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
use quote::quote;
use syn::{ReturnType, parse_macro_input};

const KNOWN_BACKENDS: &[(&str, &str)] = &[
    ("cloud_hypervisor", "::n_vm::CloudHypervisor"),
    ("qemu", "::n_vm::Qemu"),
];

const DEFAULT_BACKEND_NAME: &str = "cloud_hypervisor";

const MIGRATED_OPTIONS: &[(&str, &str)] = &[("iommu", "#[hypervisor(iommu)]")];

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

    if attr.is_empty() {
        return Ok(TestArgs {
            backend: BackendInfo {
                name: DEFAULT_BACKEND_NAME,
                explicit: false,
            },
            runtime,
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
                if nv.path.is_ident("worker_threads") {
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
    })
}

fn unknown_option_msg(name: &str) -> String {
    format!(
        "unknown #[n_vm::test] option `{name}`; expected a backend ({}), \
         a runtime flavor (`current_thread`, `multi_thread`), or \
         `worker_threads = N`.  VM options live on companion attributes \
         (#[hypervisor(...)], #[guest(...)], #[network(...)])",
        known_backend_list(),
    )
}

struct HypervisorArgs {
    iommu: bool,
    host_page_size: proc_macro2::TokenStream,
}

impl Default for HypervisorArgs {
    fn default() -> Self {
        Self {
            iommu: false,
            host_page_size: quote! { ::n_vm::HostPageSize::Huge1G },
        }
    }
}

fn parse_hypervisor_attr(attr: &syn::Attribute) -> syn::Result<HypervisorArgs> {
    let mut args = HypervisorArgs::default();

    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(args);
    }

    let mut iommu_seen = false;
    let mut host_pages_seen = false;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("iommu") {
            if iommu_seen {
                return Err(meta.error("duplicate `iommu` option in #[hypervisor]"));
            }
            iommu_seen = true;
            args.iommu = true;
            Ok(())
        } else if meta.path.is_ident("host_pages") {
            if host_pages_seen {
                return Err(meta.error("duplicate `host_pages` option in #[hypervisor]"));
            }
            host_pages_seen = true;
            let value: syn::LitStr = meta.value()?.parse()?;
            args.host_page_size = match value.value().as_str() {
                "4k" => quote! { ::n_vm::HostPageSize::Standard },
                "2m" => quote! { ::n_vm::HostPageSize::Huge2M },
                "1g" => quote! { ::n_vm::HostPageSize::Huge1G },
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown host page size `{other}` in #[hypervisor]; \
                             valid values are: \"4k\", \"2m\", \"1g\"",
                        ),
                    ));
                }
            };
            Ok(())
        } else {
            let name = meta
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<path>".into());
            Err(meta.error(format!(
                "unknown #[hypervisor] option `{name}`; \
                 valid options are: `iommu`, `host_pages`",
            )))
        }
    })?;

    Ok(args)
}

struct GuestArgs {
    guest_hugepages: proc_macro2::TokenStream,
}

impl Default for GuestArgs {
    fn default() -> Self {
        Self {
            guest_hugepages: quote! {
                ::n_vm::GuestHugePageConfig::Allocate {
                    size: ::n_vm::GuestHugePageSize::Huge1G,
                    count: 1u32,
                }
            },
        }
    }
}

fn parse_guest_attr(attr: &syn::Attribute) -> syn::Result<GuestArgs> {
    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(GuestArgs::default());
    }

    let mut hugepage_size_seen = false;
    let mut hugepage_count_seen = false;

    let mut size_is_none = false;
    let mut size_tokens: Option<proc_macro2::TokenStream> = None;
    let mut count: u32 = 1;
    let mut count_span: Option<proc_macro2::Span> = None;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("hugepage_size") {
            if hugepage_size_seen {
                return Err(meta.error("duplicate `hugepage_size` option in #[guest]"));
            }
            hugepage_size_seen = true;
            let value: syn::LitStr = meta.value()?.parse()?;
            match value.value().as_str() {
                "none" => {
                    size_is_none = true;
                }
                "2m" => {
                    size_tokens = Some(quote! { ::n_vm::GuestHugePageSize::Huge2M });
                }
                "1g" => {
                    size_tokens = Some(quote! { ::n_vm::GuestHugePageSize::Huge1G });
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown hugepage size `{other}` in #[guest]; \
                             valid values are: \"none\", \"2m\", \"1g\"",
                        ),
                    ));
                }
            }
            Ok(())
        } else if meta.path.is_ident("hugepage_count") {
            if hugepage_count_seen {
                return Err(meta.error("duplicate `hugepage_count` option in #[guest]"));
            }
            hugepage_count_seen = true;
            let lit: syn::LitInt = meta.value()?.parse()?;
            count_span = Some(lit.span());
            count = lit.base10_parse()?;
            if count == 0 {
                return Err(syn::Error::new(
                    lit.span(),
                    "hugepage_count must be at least 1; \
                     use `hugepage_size = \"none\"` to disable guest hugepages entirely",
                ));
            }
            Ok(())
        } else {
            let name = meta
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<path>".into());
            Err(meta.error(format!(
                "unknown #[guest] option `{name}`; \
                 valid options are: `hugepage_size`, `hugepage_count`",
            )))
        }
    })?;

    if size_is_none && hugepage_count_seen {
        return Err(syn::Error::new(
            count_span.unwrap_or_else(proc_macro2::Span::call_site),
            "hugepage_count cannot be specified when \
             hugepage_size = \"none\"; hugepages are disabled",
        ));
    }

    if !hugepage_size_seen && !hugepage_count_seen {
        return Ok(GuestArgs::default());
    }
    if !hugepage_size_seen {
        return Err(syn::Error::new_spanned(
            attr,
            "#[guest] requires `hugepage_size`; e.g. \
             #[guest(hugepage_size = \"2m\", hugepage_count = 512)]",
        ));
    }

    let guest_hugepages = if size_is_none {
        quote! { ::n_vm::GuestHugePageConfig::None }
    } else {
        let sz = size_tokens.expect("size_tokens set when size_is_none is false");
        quote! {
            ::n_vm::GuestHugePageConfig::Allocate {
                size: #sz,
                count: #count,
            }
        }
    };

    Ok(GuestArgs { guest_hugepages })
}

struct NetworkArgs {
    nic_model: proc_macro2::TokenStream,
    requires_qemu: bool,
}

impl Default for NetworkArgs {
    fn default() -> Self {
        Self {
            nic_model: quote! { ::n_vm::NicModel::VirtioNet },
            requires_qemu: false,
        }
    }
}

fn parse_network_attr(attr: &syn::Attribute) -> syn::Result<NetworkArgs> {
    let mut args = NetworkArgs::default();

    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(args);
    }

    let mut nic_model_seen = false;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("nic_model") {
            if nic_model_seen {
                return Err(meta.error("duplicate `nic_model` option in #[network]"));
            }
            nic_model_seen = true;
            let value: syn::LitStr = meta.value()?.parse()?;
            match value.value().as_str() {
                "virtio_net" => {
                    args.nic_model = quote! { ::n_vm::NicModel::VirtioNet };
                    args.requires_qemu = false;
                }
                "e1000" => {
                    args.nic_model = quote! { ::n_vm::NicModel::E1000 };
                    args.requires_qemu = true;
                }
                "e1000e" => {
                    args.nic_model = quote! { ::n_vm::NicModel::E1000E };
                    args.requires_qemu = true;
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown NIC model `{other}` in #[network]; \
                             valid values are: \"virtio_net\", \"e1000\", \"e1000e\"",
                        ),
                    ));
                }
            }
            Ok(())
        } else {
            let name = meta
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<path>".into());
            Err(meta.error(format!(
                "unknown #[network] option `{name}`; \
                 valid options are: `nic_model`",
            )))
        }
    })?;

    Ok(args)
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

fn extract_and_parse<T: Default>(
    attrs: &mut Vec<syn::Attribute>,
    name: &str,
    parse: impl FnOnce(&syn::Attribute) -> syn::Result<T>,
) -> syn::Result<T> {
    match extract_unique_attr(attrs, name)? {
        Some(attr) => parse(&attr),
        None => Ok(T::default()),
    }
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
/// #[n_vm::test(qemu, multi_thread, worker_threads = 4)]
/// #[hypervisor(iommu, host_pages = "4k")]
/// async fn fancy() {}
/// ```
///
/// The decorated function must take no parameters and return `()`.
/// Companion attributes `#[hypervisor]`, `#[guest]`, and `#[network]`
/// configure the VM when placed below this one.
#[proc_macro_attribute]
pub fn test(attr: TokenStream, input: TokenStream) -> TokenStream {
    let TestArgs { backend, runtime } = match parse_test_args(attr) {
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

    let hypervisor_args =
        match extract_and_parse(&mut func.attrs, "hypervisor", parse_hypervisor_attr) {
            Ok(args) => args,
            Err(err) => return err.to_compile_error().into(),
        };

    let guest_args = match extract_and_parse(&mut func.attrs, "guest", parse_guest_attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };

    let network_args = match extract_and_parse(&mut func.attrs, "network", parse_network_attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };

    if network_args.requires_qemu && backend.name != "qemu" {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "the selected NIC model requires the QEMU backend, but the \
                 current backend is `{backend}`; use #[n_vm::test(qemu)] with \
                 emulated NIC models like e1000 or e1000e",
                backend = backend.name,
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
    let iommu = hypervisor_args.iommu;
    let host_page_size = &hypervisor_args.host_page_size;
    let guest_hugepages = &guest_args.guest_hugepages;
    let nic_model = &network_args.nic_model;

    // The guest body becomes a nested function so that body-level
    // attributes (`#[wrap(...)]`, `#[traced_test]`, ...) apply to it and
    // nowhere else.  `async` is preserved on the inner function and driven
    // by an explicit runtime, since the outer dispatch function is `fn`.
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

    let tier3_body = quote! {
        #(#body_attrs)*
        #asyncness fn __n_vm_guest_body() #block
        #invoke_guest_body
    };

    quote! {
        #[test]
        #(#harness_attrs)*
        #vis #sig {
            // Tier 3: VM guest
            if ::n_vm::is_in_vm() {
                { #tier3_body }
                return;
            }

            // Build once; both tiers need it (VmConfig is Copy).  Tier 1
            // uses it to resolve capability/ISA skips; tier 2 to configure
            // the VM.
            let __n_vm_config = ::n_vm::VmConfig {
                iommu: #iommu,
                host_page_size: #host_page_size,
                guest_hugepages: #guest_hugepages,
                nic_model: #nic_model,
            };

            // Tier 2: Docker container -> VM.  The backend and acceleration
            // mode were resolved by tier 1 and passed via the environment.
            if ::n_vm::is_in_test_container() {
                ::n_vm::run_container_tier(#ident, __n_vm_config);
                return;
            }

            // Tier 1: Host -> Docker container.  Resolves the requested
            // backend + capabilities against the host arch / Docker daemon.
            ::n_vm::run_host_tier(#ident, #requested_backend, __n_vm_config);
        }
    }
    .into()
}

/// Companion attribute for hypervisor options consumed by [`test`].
///
/// Supports `iommu` and `host_pages = "4k" | "2m" | "1g"`.
#[proc_macro_attribute]
pub fn hypervisor(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[hypervisor] must be used together with #[n_vm::test] and must \
         appear below it on the same function; e.g.\n\n\
         #[n_vm::test]\n\
         #[hypervisor(iommu, host_pages = \"4k\")]\n\
         fn my_test() { ... }",
    )
    .to_compile_error();

    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}

/// Companion attribute for guest kernel options consumed by [`test`].
///
/// Supports `hugepage_size = "none" | "2m" | "1g"` and
/// `hugepage_count = N`.
#[proc_macro_attribute]
pub fn guest(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[guest] must be used together with #[n_vm::test] and must \
         appear below it on the same function; e.g.\n\n\
         #[n_vm::test]\n\
         #[guest(hugepage_size = \"2m\", hugepage_count = 512)]\n\
         fn my_test() { ... }",
    )
    .to_compile_error();

    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}

/// Companion attribute for network options consumed by [`test`].
///
/// Supports `nic_model = "virtio_net" | "e1000" | "e1000e"`.
/// Emulated Intel NICs require `#[n_vm::test(qemu)]`.
#[proc_macro_attribute]
pub fn network(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[network] must be used together with #[n_vm::test] and must \
         appear below it on the same function; e.g.\n\n\
         #[n_vm::test(qemu)]\n\
         #[network(nic_model = \"e1000\")]\n\
         fn my_test() { ... }",
    )
    .to_compile_error();

    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}
