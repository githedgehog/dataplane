// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2, TokenTree};
use quote::{ToTokens, quote};
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, GenericParam, Ident, Type, TypeParamBound,
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

#[proc_macro_derive(MatchKey, attributes(prefix, mask, range, exact, phantom))]
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
    let is_generic = input
        .generics
        .params
        .iter()
        .any(|p| matches!(p, GenericParam::Type(_) | GenericParam::Const(_)));

    let all_fields = match &input.data {
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

    // Partition fields into match fields (which drive the key layout, specs, and
    // rule) and phantom fields. A phantom field carries a compile-time constraint
    // only -- it is zero-sized at runtime and contributes nothing to the key.
    let mut fields: Vec<&Field> = Vec::new();
    let mut kinds: Vec<Kind> = Vec::new();
    let mut phantom_fields: Vec<&Field> = Vec::new();
    for field in all_fields {
        match parse_field_role(field)? {
            FieldRole::Match(kind) => {
                fields.push(field);
                kinds.push(kind);
            }
            FieldRole::Phantom => phantom_fields.push(field),
        }
    }

    if fields.is_empty() {
        return Err(syn::Error::new(
            input.span(),
            "MatchKey derive requires at least one match field (fields carrying \
             #[phantom] or of type PhantomData do not count)",
        ));
    }

    // Only bound the type parameters actually used by a match field with
    // `FixedSize`. Parameters used solely by phantom fields keep whatever
    // compile-time constraint the author wrote and must not be forced to be
    // `FixedSize` -- forcing it would defeat the point of a phantom marker.
    let mut match_param_idents: HashSet<String> = HashSet::new();
    for field in &fields {
        collect_idents(field.ty.to_token_stream(), &mut match_param_idents);
    }
    let mut generics = input.generics.clone();
    let fixed_size_bound: TypeParamBound = parse_quote!(#crate_path::FixedSize);
    for param in &mut generics.params {
        if let GenericParam::Type(tp) = param
            && match_param_idents.contains(&tp.ident.to_string())
        {
            tp.bounds.push(fixed_size_bound.clone());
        }
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

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
    // Phantom fields are carried through to the rule verbatim so that any generic
    // parameter used solely by a phantom field still appears in the rule struct
    // (otherwise it would be an unused-parameter error). They are constructed with
    // `PhantomData` and never participate in matching.
    let rule_phantom_fields: Vec<TokenStream2> = phantom_fields
        .iter()
        .map(|field| {
            let name = field
                .ident
                .as_ref()
                .ok_or_else(|| syn::Error::new(field.span(), "unnamed field"))?;
            let ty = &field.ty;
            // Represent the field as `PhantomData<..>` in the rule: this consumes
            // any generic parameter the field referenced while staying `Copy`,
            // `Clone`, and `Debug` regardless of the marker's own bounds (a bare
            // marker type would otherwise fail the derives below). A field that is
            // already `PhantomData` is kept verbatim to avoid double-wrapping.
            if is_phantom_data_type(ty) {
                Ok(quote! { pub #name: #ty })
            } else {
                Ok(quote! { pub #name: ::core::marker::PhantomData<#ty> })
            }
        })
        .collect::<syn::Result<_>>()?;
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
            #(#rule_fields,)*
            #(#rule_phantom_fields,)*
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
/// The role a struct field plays in the derived key.
enum FieldRole {
    /// A real match field, contributing bytes and a rule column.
    Match(Kind),
    /// A compile-time-only marker: zero-sized at runtime, skipped everywhere but
    /// the rule struct (where it keeps its generic parameter alive).
    Phantom,
}

/// True if `ty` is spelled as `PhantomData<..>` (in any path form).
fn is_phantom_data_type(ty: &Type) -> bool {
    if let Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        return seg.ident == "PhantomData";
    }
    false
}

fn parse_field_role(field: &Field) -> syn::Result<FieldRole> {
    let mut has_phantom_attr = false;
    let mut found: Option<(Kind, &Attribute)> = None;
    for attr in &field.attrs {
        if attr.path().is_ident("phantom") {
            has_phantom_attr = true;
            continue;
        }
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
    if has_phantom_attr || is_phantom_data_type(&field.ty) {
        if let Some((_, attr)) = found {
            return Err(syn::Error::new(
                attr.span(),
                "match-flavor attribute on a phantom field; phantom fields \
                 (marked #[phantom] or of type PhantomData) carry no runtime data \
                 and cannot be matched on",
            ));
        }
        return Ok(FieldRole::Phantom);
    }
    Ok(FieldRole::Match(found.map_or(Kind::Exact, |(k, _)| k)))
}

/// Collect every identifier appearing in `tokens` into `out`. Used to discover
/// which generic type parameters a match field's type actually references.
fn collect_idents(tokens: TokenStream2, out: &mut HashSet<String>) {
    for tt in tokens {
        match tt {
            TokenTree::Ident(id) => {
                out.insert(id.to_string());
            }
            TokenTree::Group(g) => collect_idents(g.stream(), out),
            _ => {}
        }
    }
}
