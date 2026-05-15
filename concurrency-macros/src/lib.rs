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

/// Resolve a path prefix for `dataplane-concurrency` in the consumer's
/// `Cargo.toml`. Returns a token stream that resolves to the crate root,
/// so callers can append `::stress` or `::with_loom` etc.
///
/// * Workspace consumer with `concurrency = { package = "dataplane-concurrency", ... }`
///   in its `Cargo.toml`: returns `::concurrency`.
/// * External consumer with `dataplane-concurrency = "..."` directly:
///   returns `::dataplane_concurrency`.
/// * `dataplane-concurrency`'s own integration tests: returns
///   `::dataplane_concurrency` (which requires the test file to do
///   `extern crate dataplane_concurrency;` -- cargo doesn't let a crate
///   list itself as a regular dev-dep, but `extern crate` works in the
///   integration test).
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

/// Mark a function as a test that runs under whichever concurrency backend
/// is currently selected on `dataplane-concurrency`.
///
/// Under the default (production) backend, expands to a flat
/// `#[test] fn <name>() { concurrency::stress(|| { original }) }`,
/// which calls the body once.
///
/// Under any model-checker backend (`loom`, `shuttle`, `shuttle_pct`,
/// `shuttle_dfs`), expands to a nested module so the test's binary
/// path identifies the active backend in nextest reports / JUnit
/// output:
///
/// ```text
/// // #[concurrency::test] fn some_test() { body }
/// // under `--features loom`:
/// mod some_test {
///     mod concurrency_model {
///         #[test]
///         fn loom() { concurrency::stress(|| body) }
///     }
/// }
/// ```
///
/// The same shape applies for `shuttle` / `shuttle_pct` / `shuttle_dfs`,
/// each writing the function name that names the active backend.
/// Nextest filters like `-E 'test(/concurrency_model::loom$/)'` then
/// pick out the loom-backed runs cleanly without having to grep on
/// binary names.
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
/// The function must take no arguments and return `()`. The body is
/// captured as a closure, so it must be `Fn() + Send + Sync + 'static`
/// (no borrows of locals, no `FnOnce`-only constructs). This matches
/// what `loom::model` and `shuttle::check_*` require.
///
/// # Limitations
///
/// * **Single-threaded bodies fail under `shuttle_pct`.** Shuttle's PCT
///   scheduler panics at runtime if the test closure does not exercise
///   any concurrent atomic / thread operation (no `thread::spawn`, no
///   contended `Mutex`/`Arc`). The detection is dynamic, so the macro
///   cannot reject these statically; if you need such a test, gate it
///   with `#[cfg(not(feature = "shuttle_pct"))]` or use a regular
///   `#[test]` for the default-only smoke check.
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
    // Default backend: flat `#[test] fn <name>() { ... }`. No nested
    // module wrapping -- the production code path runs the body once,
    // and there is no second backend to disambiguate from.
    //
    // Model-checker backends: emit `mod <fn_name> { mod concurrency_model
    // { #[test] fn <backend>() { ... } } }`. The leaf function name
    // identifies the active backend, so a nextest report shows entries
    // like `some_test::concurrency_model::loom` and a filter like
    // `-E 'test(/concurrency_model::loom$/)'` picks them out
    // unambiguously.
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

                #[cfg(all(feature = "shuttle", not(feature = "shuttle_pct")))]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn shuttle() {
                    #krate::stress(|| #block);
                }

                #[cfg(all(feature = "shuttle_pct", not(feature = "shuttle_dfs")))]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn shuttle_pct() {
                    #krate::stress(|| #block);
                }

                #[cfg(feature = "shuttle_dfs")]
                #[::core::prelude::v1::test]
                #(#attrs)*
                fn shuttle_dfs() {
                    #krate::stress(|| #block);
                }
            }
        }
    }
    .into()
}
