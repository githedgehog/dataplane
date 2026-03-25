// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Declarative macros for the `Try*` / `Try*Mut` header accessor trait pattern.
//!
//! | Macro                           | Purpose                                                      |
//! |---------------------------------|--------------------------------------------------------------|
//! | [`define_field_accessor!`]      | Trait pair + impl for a plain `Option<T>` field              |
//! | [`define_variant_accessor!`]    | Trait pair + impl extracting one variant of `Option<Enum>`   |
//! | [`impl_delegated_accessors!`]   | Blanket `impl<T>` forwarding through a provider trait        |
//!
//! [`TryIcmpAny`] / [`TryIcmpAnyMut`] remain hand-written because their
//! return types and multi-variant match arms don't fit these patterns.

/// Defines a read/write accessor trait pair for a plain `Option<T>` field.
///
/// ```ignore
/// define_field_accessor! {
///     TryEth::try_eth / TryEthMut::try_eth_mut => Eth,
///     for Headers => self.eth
/// }
/// ```
macro_rules! define_field_accessor {
    (
        $Trait:ident :: $method:ident / $TraitMut:ident :: $method_mut:ident => $T:ty,
        for $Struct:ty => self.$field:ident
    ) => {
        /// Attempt to borrow the inner header by reference.
        pub trait $Trait {
            /// Returns `Some` if the header is present, `None` otherwise.
            fn $method(&self) -> Option<&$T>;
        }

        /// Attempt to borrow the inner header by mutable reference.
        pub trait $TraitMut {
            /// Returns `Some` if the header is present, `None` otherwise.
            fn $method_mut(&mut self) -> Option<&mut $T>;
        }

        impl $Trait for $Struct {
            fn $method(&self) -> Option<&$T> {
                self.$field.as_ref()
            }
        }

        impl $TraitMut for $Struct {
            fn $method_mut(&mut self) -> Option<&mut $T> {
                self.$field.as_mut()
            }
        }
    };
}

/// Defines a read/write accessor trait pair that extracts a specific variant
/// from an `Option<Enum>` field.
///
/// ```ignore
/// define_variant_accessor! {
///     TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut => Ipv4,
///     for Headers => self.net, match Net::Ipv4
/// }
/// ```
macro_rules! define_variant_accessor {
    (
        $Trait:ident :: $method:ident / $TraitMut:ident :: $method_mut:ident => $T:ty,
        for $Struct:ty => self.$field:ident, match $Variant:path
    ) => {
        /// Attempt to borrow the inner header by reference.
        pub trait $Trait {
            /// Returns `Some` if the header variant is present, `None` otherwise.
            fn $method(&self) -> Option<&$T>;
        }

        /// Attempt to borrow the inner header by mutable reference.
        pub trait $TraitMut {
            /// Returns `Some` if the header variant is present, `None` otherwise.
            fn $method_mut(&mut self) -> Option<&mut $T>;
        }

        impl $Trait for $Struct {
            fn $method(&self) -> Option<&$T> {
                match &self.$field {
                    Some($Variant(header)) => Some(header),
                    _ => None,
                }
            }
        }

        impl $TraitMut for $Struct {
            fn $method_mut(&mut self) -> Option<&mut $T> {
                match &mut self.$field {
                    Some($Variant(header)) => Some(header),
                    _ => None,
                }
            }
        }
    };
}

/// Generates blanket `impl<T>` delegation impls that forward accessor trait
/// methods through a provider trait.
///
/// Direct delegation (provider returns a reference):
///
/// ```ignore
/// impl_delegated_accessors! {
///     via TryHeaders::headers / TryHeadersMut::headers_mut {
///         TryEth::try_eth / TryEthMut::try_eth_mut => Eth,
///     }
/// }
/// ```
///
/// Option-chaining delegation (provider returns `Option<&impl ...>`):
///
/// ```ignore
/// impl_delegated_accessors! {
///     try via TryEmbeddedHeaders::embedded_headers
///          / TryEmbeddedHeadersMut::embedded_headers_mut
///     {
///         TryInnerIpv4::try_inner_ipv4 / TryInnerIpv4Mut::try_inner_ipv4_mut => Ipv4,
///     }
/// }
/// ```
macro_rules! impl_delegated_accessors {
    // Direct delegation: provider returns a reference.
    (
        via $Provider:ident :: $provider:ident
          / $ProviderMut:ident :: $provider_mut:ident
        {
            $( $Trait:ident :: $method:ident
             / $TraitMut:ident :: $method_mut:ident
            => $T:ty ),* $(,)?
        }
    ) => {
        $(
            impl<__T: $Provider> $Trait for __T {
                fn $method(&self) -> Option<&$T> {
                    self.$provider().$method()
                }
            }

            impl<__T: $ProviderMut> $TraitMut for __T {
                fn $method_mut(&mut self) -> Option<&mut $T> {
                    self.$provider_mut().$method_mut()
                }
            }
        )*
    };

    // Option-chaining delegation: provider returns Option<&impl ...>.
    (
        try via $Provider:ident :: $provider:ident
              / $ProviderMut:ident :: $provider_mut:ident
        {
            $( $Trait:ident :: $method:ident
             / $TraitMut:ident :: $method_mut:ident
            => $T:ty ),* $(,)?
        }
    ) => {
        $(
            impl<__T: $Provider> $Trait for __T {
                fn $method(&self) -> Option<&$T> {
                    self.$provider()?.$method()
                }
            }

            impl<__T: $ProviderMut> $TraitMut for __T {
                fn $method_mut(&mut self) -> Option<&mut $T> {
                    self.$provider_mut()?.$method_mut()
                }
            }
        )*
    };
}
