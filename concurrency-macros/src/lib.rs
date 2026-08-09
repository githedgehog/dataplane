// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    Ident, Item, ItemFn,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// Resolve the consumer's name for `dataplane-concurrency`.
///
/// Workspace crates use `concurrency`; external users and this crate's integration tests use
/// `dataplane_concurrency`.
fn concurrency_crate_path() -> TokenStream2 {
    match crate_name("dataplane-concurrency") {
        Ok(FoundCrate::Itself) => {
            let ident = Ident::new("dataplane_concurrency", Span::call_site());
            quote! { ::#ident }
        }
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote! { ::#ident }
        }
        Err(_) => {
            let ident = Ident::new("dataplane_concurrency", Span::call_site());
            quote! { ::#ident }
        }
    }
}

struct ConcurrencyModeArgs {
    mode: Ident,
}

impl Parse for ConcurrencyModeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mode: Ident = input.parse()?;
        Ok(ConcurrencyModeArgs { mode })
    }
}

/// Attribute macro to conditionally enable an item based on concurrency mode.
///
/// Usage: #[concurrency_mode(shuttle)] or #[concurrency_mode(loom)] or #[concurrency_mode(std)]
///
/// # Example
/// ```no_compile
/// use concurrency::concurrency_mode;
/// #[concurrency_mode(std)]
/// fn test_shuttle() {
///     // code here
/// }
/// ```
#[proc_macro_attribute]
pub fn concurrency_mode(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as ConcurrencyModeArgs);
    let item = parse_macro_input!(item as Item);

    let mode = args.mode.to_string();
    let krate = concurrency_crate_path();

    let output = match mode.as_str() {
        "shuttle" => quote! {
            #krate::with_shuttle! {
                #item
            }
        },
        "loom" => quote! {
            #krate::with_loom! {
                #item
            }
        },
        "std" => quote! {
            #krate::with_std! {
                #item
            }
        },
        _ => {
            return syn::Error::new_spanned(
                args.mode,
                "Expected 'shuttle', 'loom', or 'std' as argument to #[concurrency_mode]",
            )
            .to_compile_error()
            .into();
        }
    };

    output.into()
}

/// Mark a backend-routed concurrency test.
///
/// The default backend emits a flat test. Model-checker tests get a backend-named leaf so nextest
/// can select them safely.
///
/// # Example
///
/// ```ignore
/// #[concurrency::test]
/// fn snapshot_observes_a_legal_value() {
///     // ... body uses concurrency::sync, concurrency::thread ...
/// }
/// ```
///
/// The function must take no arguments, return `()`, and work as an
/// `Fn() + Send + Sync + 'static` closure.
///
/// # Limitations
///
/// * **Single-threaded bodies fail under `shuttle`.** PCT is part of
///   the shuttle portfolio and requires real concurrent work.
/// * **Async bodies and arguments are rejected at parse time** with a
///   clear compile error.
#[proc_macro_attribute]
pub fn test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    let attrs = &func.attrs;
    let vis = &func.vis;
    let sig = &func.sig;
    let block = &func.block;
    let fn_name = &sig.ident;

    if let Some(asyncness) = sig.asyncness {
        return syn::Error::new_spanned(
            asyncness,
            "#[concurrency::test] does not support async functions yet",
        )
        .to_compile_error()
        .into();
    }
    if !sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &sig.inputs,
            "#[concurrency::test] functions must take no arguments",
        )
        .to_compile_error()
        .into();
    }

    let krate = concurrency_crate_path();
    // Backend-named leaves let nextest isolate tests that use model-checker primitives.
    quote! {
        #[cfg(not(any(feature = "loom", feature = "shuttle")))]
        #[::core::prelude::v1::test]
        #(#attrs)*
        #vis #sig {
            #krate::stress(|| #block);
        }

        #[cfg(any(feature = "loom", feature = "shuttle"))]
        #[allow(non_snake_case)]
        mod #fn_name {
            use super::*;
            mod concurrency_model {
                use super::*;

                #[cfg(feature = "loom")]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn loom() {
                    #krate::stress(|| #block);
                }

                #[cfg(feature = "shuttle")]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn shuttle() {
                    #krate::stress(|| #block);
                }

            }
        }
    }
    .into()
}

/// Give a test a backend-named leaf without wrapping its body in `stress`.
///
/// Use this when a generator is the outer loop and invokes `stress` per generated case:
///
/// ```ignore
/// bolero::check!().with_type().cloned().for_each(|scenario: Scenario| {
///     concurrency::stress(move || scenario.run());   // one exploration per generated shape
/// });
/// ```
///
/// The leaf is named `plain`, `loom`, or `shuttle`, allowing the same nextest filters used by
/// [`macro@test`].
#[proc_macro_attribute]
pub fn model_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    let attrs = &func.attrs;
    let sig = &func.sig;
    let block = &func.block;
    let fn_name = &sig.ident;

    if let Some(asyncness) = sig.asyncness {
        return syn::Error::new_spanned(
            asyncness,
            "#[concurrency::model_test] does not support async functions yet",
        )
        .to_compile_error()
        .into();
    }
    if !sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &sig.inputs,
            "#[concurrency::model_test] functions must take no arguments",
        )
        .to_compile_error()
        .into();
    }

    quote! {
        #[allow(non_snake_case)]
        mod #fn_name {
            use super::*;
            mod concurrency_model {
                use super::*;

                #[cfg(feature = "loom")]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn loom() #block

                #[cfg(feature = "shuttle")]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn shuttle() #block

                #[cfg(not(any(feature = "loom", feature = "shuttle")))]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn plain() #block
            }
        }
    }
    .into()
}
