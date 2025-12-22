// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type, TypePath, parse_macro_input};

#[proc_macro_derive(Sample)]
pub fn derive_sample(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let field_inits = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => {
                let inits: Vec<_> = fields_named
                    .named
                    .iter()
                    .map(|f| {
                        let fname = f.ident.as_ref().unwrap();

                        match &f.ty {
                            Type::Path(TypePath { path, .. }) => {
                                quote! {
                                    #fname: <#path as Sample>::sample()
                                }
                            }
                            _ => panic!("Unsupported field type"),
                        }
                    })
                    .collect();

                quote! { #(#inits),* }
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    };

    let expanded = quote! {
        impl Sample for #name {
            fn sample() -> Self {
                Self { #field_inits }
            }
        }
    };

    // uncomment to debug
    // eprintln!("{}", expanded);

    TokenStream::from(expanded)
}
