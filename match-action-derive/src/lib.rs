// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, GenericParam, Ident, TypeParamBound,
    parse_macro_input, parse_quote, spanned::Spanned,
};
fn match_action_crate_path() -> TokenStream2 {
    match crate_name("dataplane-match-action") {
        Ok(FoundCrate::Itself) => {
            let ident = Ident::new("dataplane_match_action", Span::call_site());
            quote! { ::#ident }
        }
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote! { ::#ident }
        }
        Err(_) => {
            let ident = Ident::new("dataplane_match_action", Span::call_site());
            quote! { ::#ident }
        }
    }
}
#[derive(Debug, Copy, Clone)]
enum Kind {
    Prefix,
    Mask,
    Range,
    Exact,
}

impl Kind {
    fn variant_ident(self) -> Ident {
        let name = match self {
            Self::Prefix => "Prefix",
            Self::Mask => "Mask",
            Self::Range => "Range",
            Self::Exact => "Exact",
        };
        Ident::new(name, Span::call_site())
    }
    fn spec_ident(self) -> Ident {
        let name = match self {
            Self::Prefix => "PrefixSpec",
            Self::Mask => "MaskSpec",
            Self::Range => "RangeSpec",
            Self::Exact => "ExactSpec",
        };
        Ident::new(name, Span::call_site())
    }
}

#[proc_macro_derive(MatchKey, attributes(prefix, mask, range, exact))]
pub fn derive_match_key(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let crate_path = match_action_crate_path();
    let key_ident = &input.ident;
    let key_vis = &input.vis;
    let mut generics = input.generics.clone();
    let fixed_size_bound: TypeParamBound = parse_quote!(#crate_path::FixedSize);
    for param in &mut generics.params {
        if let GenericParam::Type(tp) = param {
            tp.bounds.push(fixed_size_bound.clone());
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let is_generic = input
        .generics
        .params
        .iter()
        .any(|p| matches!(p, GenericParam::Type(_) | GenericParam::Const(_)));

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            Fields::Unnamed(_) => {
                return Err(syn::Error::new(
                    input.span(),
                    "MatchKey derive requires named fields",
                ));
            }
            Fields::Unit => {
                return Err(syn::Error::new(
                    input.span(),
                    "MatchKey derive requires at least one field",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new(
                input.span(),
                "MatchKey derive only supports structs",
            ));
        }
    };

    if fields.is_empty() {
        return Err(syn::Error::new(
            input.span(),
            "MatchKey derive requires at least one field",
        ));
    }
    let kinds: Vec<Kind> = fields
        .iter()
        .map(parse_field_kind)
        .collect::<syn::Result<_>>()?;

    let n = fields.len();
    let n_literal = syn::Index::from(n);
    let size_exprs: Vec<TokenStream2> = fields
        .iter()
        .map(|f| {
            let ty = &f.ty;
            quote! { <#ty as #crate_path::FixedSize>::SIZE }
        })
        .collect();
    let mut boundaries: Vec<TokenStream2> = Vec::with_capacity(n + 1);
    boundaries.push(quote! { 0usize });
    let mut acc: Vec<TokenStream2> = Vec::new();
    for size in &size_exprs {
        acc.push(size.clone());
        boundaries.push(quote! { #(#acc)+* });
    }
    let key_size_expr = &boundaries[n];
    let mut spec_entries: Vec<TokenStream2> = Vec::with_capacity(n);
    for (i, field) in fields.iter().enumerate() {
        let name = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new(field.span(), "unnamed field"))?;
        let name_str = name.to_string();
        let off = &boundaries[i];
        let size = &size_exprs[i];
        let kind_variant = kinds[i].variant_ident();
        spec_entries.push(quote! {
            #crate_path::FieldSpec {
                name: #name_str,
                kind: #crate_path::FieldKind::#kind_variant,
                size: #size,
                offset: #off,
            }
        });
    }
    let mut writers: Vec<TokenStream2> = Vec::with_capacity(n);
    for (i, field) in fields.iter().enumerate() {
        let name = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new(field.span(), "unnamed field"))?;
        let ty = &field.ty;
        let start = &boundaries[i];
        let end = &boundaries[i + 1];
        writers.push(quote! {
            <#ty as #crate_path::FixedSize>::write_be(
                &self.#name,
                &mut out[#start..#end],
            );
        });
    }
    let rule_ident = Ident::new(&format!("{key_ident}Rule"), key_ident.span());
    let mut rule_fields: Vec<TokenStream2> = Vec::with_capacity(n);
    let mut rule_field_bounds: Vec<TokenStream2> = Vec::with_capacity(n);
    let mut rule_field_converts: Vec<TokenStream2> = Vec::with_capacity(n);
    let mut rule_field_accepts: Vec<TokenStream2> = Vec::with_capacity(n);
    let mut rule_field_universal: Vec<TokenStream2> = Vec::with_capacity(n);
    let mut rule_field_accept_bounds: Vec<TokenStream2> = Vec::with_capacity(n);
    let mut rule_field_universal_bounds: Vec<TokenStream2> = Vec::with_capacity(n);
    for (i, field) in fields.iter().enumerate() {
        let name = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new(field.span(), "unnamed field"))?;
        let ty = &field.ty;
        let spec = kinds[i].spec_ident();
        rule_fields.push(quote! {
            pub #name: #crate_path::#spec<#ty>
        });
        rule_field_bounds.push(quote! {
            #crate_path::#spec<#ty>: #crate_path::IntoBackendField<__MaB>
        });
        rule_field_converts.push(quote! {
            <#crate_path::#spec<#ty> as #crate_path::IntoBackendField<__MaB>>::into_backend_field(self.#name)
        });
        rule_field_accepts.push(quote! {
            <#crate_path::#spec<#ty> as #crate_path::Accepts<#ty>>::accepts(&self.#name, &key.#name)
        });
        rule_field_universal.push(quote! {
            <#crate_path::#spec<#ty> as #crate_path::IsUniversal>::is_universal(&self.#name)
        });
        rule_field_accept_bounds.push(quote! {
            #crate_path::#spec<#ty>: #crate_path::Accepts<#ty>
        });
        rule_field_universal_bounds.push(quote! {
            #crate_path::#spec<#ty>: #crate_path::IsUniversal
        });
    }
    let as_key_impl = if is_generic {
        quote! {}
    } else {
        quote! {
            impl #impl_generics #key_ident #ty_generics #where_clause {
                #[must_use]
                pub fn as_key(&self) -> [u8; <Self as #crate_path::MatchKey>::KEY_SIZE] {
                    let mut buf = [0u8; <Self as #crate_path::MatchKey>::KEY_SIZE];
                    <Self as #crate_path::MatchKey>::as_key_into(self, &mut buf);
                    buf
                }
            }
        }
    };
    let existing_predicates: Vec<_> = where_clause
        .map(|wc| wc.predicates.iter().collect())
        .unwrap_or_default();
    let merged_where_accepts = quote! {
        where
            #(#existing_predicates,)*
            #(#rule_field_accept_bounds,)*
    };
    let merged_where_universal = quote! {
        where
            #(#existing_predicates,)*
            #(#rule_field_universal_bounds,)*
    };

    let expanded = quote! {
        const _: () = {
            impl #impl_generics #key_ident #ty_generics #where_clause {
                pub const FIELD_SPECS: &'static [#crate_path::FieldSpec] = &[
                    #(#spec_entries),*
                ];
            }

            impl #impl_generics #crate_path::MatchKey for #key_ident #ty_generics #where_clause {
                const N: usize = #n_literal;
                const KEY_SIZE: usize = #key_size_expr;

                fn field_specs() -> &'static [#crate_path::FieldSpec] {
                    Self::FIELD_SPECS
                }

                fn as_key_into(&self, out: &mut [u8]) {
                    assert!(
                        out.len() >= Self::KEY_SIZE,
                        "as_key_into: output buffer shorter than KEY_SIZE",
                    );
                    #(#writers)*
                }
            }

            #as_key_impl
        };
        #[derive(::core::marker::Copy, ::core::clone::Clone, ::core::fmt::Debug)]
        #key_vis struct #rule_ident #generics {
            #(#rule_fields),*
        }
        impl #impl_generics #rule_ident #ty_generics #where_clause {
            pub fn into_backend_fields<__MaB>(self) -> ::std::vec::Vec<<__MaB as #crate_path::Backend>::Field>
            where
                __MaB: #crate_path::Backend,
                #(#rule_field_bounds),*
            {
                ::std::vec![
                    #(#rule_field_converts),*
                ]
            }
        }
        impl #impl_generics #rule_ident #ty_generics
        #merged_where_accepts
        {
            #[must_use]
            pub fn accepts(&self, key: &#key_ident #ty_generics) -> bool {
                #(#rule_field_accepts) && *
            }
        }
        impl #impl_generics #rule_ident #ty_generics
        #merged_where_universal
        {
            #[must_use]
            pub fn is_universal(&self) -> bool {
                #(#rule_field_universal) && *
            }
        }
    };

    Ok(expanded)
}
fn parse_field_kind(field: &Field) -> syn::Result<Kind> {
    let mut found: Option<(Kind, &Attribute)> = None;
    for attr in &field.attrs {
        let kind = if attr.path().is_ident("prefix") {
            Some(Kind::Prefix)
        } else if attr.path().is_ident("mask") {
            Some(Kind::Mask)
        } else if attr.path().is_ident("range") {
            Some(Kind::Range)
        } else if attr.path().is_ident("exact") {
            Some(Kind::Exact)
        } else {
            None
        };
        if let Some(k) = kind {
            if found.is_some() {
                return Err(syn::Error::new(
                    attr.span(),
                    "multiple match-flavor attributes on a single field; \
                     expected at most one of #[prefix], #[mask], #[range], #[exact]",
                ));
            }
            found = Some((k, attr));
        }
    }
    Ok(found.map_or(Kind::Exact, |(k, _)| k))
}
