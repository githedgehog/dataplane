// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, Item,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

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

    let output = match mode.as_str() {
        "shuttle" => quote! {
            ::concurrency::with_shuttle! {
                #item
            }
        },
        "loom" => quote! {
            ::concurrency::with_loom! {
                #item
            }
        },
        "std" => quote! {
            ::concurrency::with_std! {
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
