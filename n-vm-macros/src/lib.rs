// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![warn(missing_docs)]

//! Attribute macros for running tests inside the `n-vm` nested test
//! environment.
//!
//! `#[in_vm]` rewrites a `fn()` or `async fn()` test into a three-tier
//! dispatch:
//!
//! - host: start a Docker container;
//! - container: boot the selected hypervisor backend;
//! - VM guest: run the original test body under `n-it`.
//!
//! Use `#[in_vm]` for the default cloud-hypervisor backend or
//! `#[in_vm(qemu)]` for QEMU.  Companion attributes must sit below
//! `#[in_vm]` so this macro can consume them:
//!
//! ```ignore
//! #[in_vm(qemu)]
//! #[test]
//! #[hypervisor(iommu, host_pages = "4k")]
//! #[guest(hugepage_size = "2m", hugepage_count = 512)]
//! #[network(nic_model = "e1000")]
//! fn test_dpdk() {}
//! ```
//!
//! `#[tokio::test]` is accepted on async tests; the macro rewrites it to
//! `#[test]` and uses its `flavor` / `worker_threads` values when
//! constructing the guest-tier runtime.

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

fn parse_in_vm_backend(attr: TokenStream) -> syn::Result<BackendInfo> {
    if attr.is_empty() {
        return Ok(BackendInfo {
            name: DEFAULT_BACKEND_NAME,
            explicit: false,
        });
    }

    use syn::parse::Parser;
    let parser = syn::punctuated::Punctuated::<syn::Ident, syn::Token![,]>::parse_terminated;
    let punctuated = parser.parse(attr).map_err(|_| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "#[in_vm] expects an optional backend identifier; \
                 valid backends are: {}",
                known_backend_list(),
            ),
        )
    })?;

    let idents: Vec<syn::Ident> = punctuated.into_iter().collect();

    if idents.len() > 1 {
        return Err(syn::Error::new_spanned(
            &idents[1],
            "only one backend identifier is allowed in #[in_vm]; \
             VM options have moved to companion attributes \
             (#[hypervisor(...)], #[guest(...)], #[network(...)])",
        ));
    }

    let ident = &idents[0];
    let ident_str = ident.to_string();

    if let Some(hint) = migration_hint(&ident_str) {
        return Err(syn::Error::new_spanned(
            ident,
            format!(
                "`{ident_str}` has moved out of #[in_vm(...)] -- \
                 use {hint} instead",
            ),
        ));
    }

    if let Some((name, _path)) = resolve_backend(&ident_str) {
        Ok(BackendInfo {
            name,
            explicit: true,
        })
    } else {
        Err(syn::Error::new_spanned(
            ident,
            format!(
                "unknown #[in_vm] backend `{ident_str}`; \
                 valid backends are: {}",
                known_backend_list(),
            ),
        ))
    }
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

struct TokioTestConfig {
    multi_thread: bool,
    worker_threads: Option<usize>,
}

impl Default for TokioTestConfig {
    fn default() -> Self {
        Self {
            multi_thread: false,
            worker_threads: None,
        }
    }
}

fn parse_tokio_test_attr(attr: &syn::Attribute) -> syn::Result<TokioTestConfig> {
    let mut config = TokioTestConfig::default();

    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(config);
    }

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("flavor") {
            let value: syn::LitStr = meta.value()?.parse()?;
            match value.value().as_str() {
                "current_thread" => {
                    config.multi_thread = false;
                }
                "multi_thread" => {
                    config.multi_thread = true;
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown tokio runtime flavor `{other}`; \
                             expected \"current_thread\" or \"multi_thread\"",
                        ),
                    ));
                }
            }
            Ok(())
        } else if meta.path.is_ident("worker_threads") {
            let lit: syn::LitInt = meta.value()?.parse()?;
            config.worker_threads = Some(lit.base10_parse()?);
            Ok(())
        } else {
            if meta.input.peek(syn::Token![=]) {
                let _: syn::Expr = meta.value()?.parse()?;
            }
            Ok(())
        }
    })?;

    Ok(config)
}

fn is_tokio_test_attr(attr: &syn::Attribute) -> bool {
    let path = attr.path();
    let segs: Vec<_> = path.segments.iter().collect();
    segs.len() == 2 && segs[0].ident == "tokio" && segs[1].ident == "test"
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

/// Rewrites a `#[test]` or `#[tokio::test]` function to run inside an
/// ephemeral VM.
///
/// Accepts `#[in_vm]`, `#[in_vm(cloud_hypervisor)]`, or `#[in_vm(qemu)]`.
/// The decorated function must take no parameters and return `()`.
/// Companion attributes `#[hypervisor]`, `#[guest]`, and `#[network]`
/// configure the VM when placed below `#[in_vm]`.
#[proc_macro_attribute]
pub fn in_vm(attr: TokenStream, input: TokenStream) -> TokenStream {
    let backend = match parse_in_vm_backend(attr) {
        Ok(info) => info,
        Err(err) => return err.to_compile_error().into(),
    };

    let mut func = parse_macro_input!(input as syn::ItemFn);

    // `#[should_panic]` cannot compose with `#[in_vm]`: the test body runs
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
            "#[should_panic] is not supported with #[in_vm]: the test body runs \
             in a separate VM-guest process across three dispatch tiers, so panic \
             semantics do not compose.  Assert the failure condition inside the \
             test body instead (e.g. `assert!(result.is_err())`).",
        )
        .to_compile_error()
        .into();
    }

    let is_async = func.sig.asyncness.is_some();

    let tokio_config = if let Some(idx) = func.attrs.iter().position(is_tokio_test_attr) {
        let tokio_attr = func.attrs.remove(idx);
        let config = match parse_tokio_test_attr(&tokio_attr) {
            Ok(c) => c,
            Err(err) => return err.to_compile_error().into(),
        };

        let has_test_attr = func.attrs.iter().any(|a| a.path().is_ident("test"));
        if !has_test_attr {
            func.attrs.push(syn::parse_quote!(#[test]));
        }

        Some(config)
    } else {
        None
    };

    if !func.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &func.sig.inputs,
            "#[in_vm] functions must take no parameters; \
             the function is re-invoked by name as `fn()` inside the VM guest",
        )
        .to_compile_error()
        .into();
    }

    if !matches!(func.sig.output, ReturnType::Default) {
        return syn::Error::new_spanned(
            &func.sig.output,
            "#[in_vm] functions must return `()`; \
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
                 current backend is `{backend}`; use #[in_vm(qemu)] with \
                 emulated NIC models like e1000 or e1000e",
                backend = backend.name,
            ),
        )
        .to_compile_error()
        .into();
    }

    // A bare `#[in_vm]` with neither `#[test]` nor `#[tokio::test]` compiles
    // to an ordinary function that libtest never collects, so the test
    // silently never runs -- the worst failure mode for a test harness.
    // Require an explicit test attribute so the mistake is a clear error.
    // Checked last so the more specific diagnostics above take precedence.
    if tokio_config.is_none() && !func.attrs.iter().any(|a| a.path().is_ident("test")) {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[in_vm] requires a test attribute: add #[test] (or #[tokio::test]); \
             without one the generated function is never collected by libtest and \
             the test silently never runs",
        )
        .to_compile_error()
        .into();
    }

    let block = &func.block;
    let vis = &func.vis;
    let attrs = &func.attrs;
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

    let tier3_body = if is_async {
        match tokio_config {
            Some(TokioTestConfig {
                multi_thread: true,
                worker_threads,
            }) => {
                let workers = match worker_threads {
                    Some(n) => quote! { ::core::option::Option::Some(#n) },
                    None => quote! { ::core::option::Option::None },
                };
                quote! {
                    ::n_vm::block_on_in_guest_multi_thread(
                        #workers,
                        async { #block },
                    );
                }
            }
            _ => {
                quote! { ::n_vm::block_on_in_guest(async { #block }); }
            }
        }
    } else {
        quote! { #block }
    };

    quote! {
        #(#attrs)*
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

/// Companion attribute for hypervisor options consumed by [`in_vm`].
///
/// Supports `iommu` and `host_pages = "4k" | "2m" | "1g"`.
#[proc_macro_attribute]
pub fn hypervisor(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[hypervisor] must be used together with #[in_vm] and must \
         appear below it on the same function; e.g.\n\n\
         #[in_vm]\n\
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

/// Companion attribute for guest kernel options consumed by [`in_vm`].
///
/// Supports `hugepage_size = "none" | "2m" | "1g"` and
/// `hugepage_count = N`.
#[proc_macro_attribute]
pub fn guest(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[guest] must be used together with #[in_vm] and must \
         appear below it on the same function; e.g.\n\n\
         #[in_vm]\n\
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

/// Companion attribute for network options consumed by [`in_vm`].
///
/// Supports `nic_model = "virtio_net" | "e1000" | "e1000e"`.
/// Emulated Intel NICs require `#[in_vm(qemu)]`.
#[proc_macro_attribute]
pub fn network(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[network] must be used together with #[in_vm] and must \
         appear below it on the same function; e.g.\n\n\
         #[in_vm(qemu)]\n\
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
