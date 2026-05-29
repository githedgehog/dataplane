// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{Ident, ItemFn, parse_macro_input, parse_quote};
fn dpdk_crate_path() -> TokenStream2 {
    match crate_name("dataplane-dpdk") {
        Ok(FoundCrate::Itself) => quote! { crate },
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote! { ::#ident }
        }
        Err(_) => {
            let ident = Ident::new("dataplane_dpdk", Span::call_site());
            quote! { ::#ident }
        }
    }
}

#[proc_macro_attribute]
pub fn with_eal(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        let err: TokenStream2 =
            syn::Error::new(Span::call_site(), "#[with_eal] takes no arguments").to_compile_error();
        return err.into();
    }

    let mut input_fn = parse_macro_input!(input as ItemFn);
    let dpdk = dpdk_crate_path();
    let init_stmt: syn::Stmt = parse_quote! {
        let _eal = #dpdk::test_support::start_eal();
    };
    input_fn.block.stmts.insert(0, init_stmt);

    quote! { #input_fn }.into()
}
