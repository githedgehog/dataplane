// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Declarative macros for the `Try*` / `Try*Mut` header accessor pattern.
//!
//! The headers module defines many trait pairs of the form:
//!
//! ```ignore
//! pub trait TryFoo {
//!     fn try_foo(&self) -> Option<&Foo>;
//! }
//! pub trait TryFooMut {
//!     fn try_foo_mut(&mut self) -> Option<&mut Foo>;
//! }
//! ```
//!
//! Each pair is then implemented on a concrete struct (`Headers` or
//! `EmbeddedHeaders`) and also given a blanket delegation impl so that any
//! wrapper holding a `Headers` (e.g. `Packet<Buf>`) inherits the accessor
//! for free.
//!
//! These macros factor out the mechanical parts of that pattern.
//!
//! # What these macros cover
//!
//! | Macro                           | Purpose                                                      |
//! |---------------------------------|--------------------------------------------------------------|
//! | [`define_field_accessor!`]      | Trait pair + impl for a plain `Option<T>` field              |
//! | [`define_variant_accessor!`]    | Trait pair + impl extracting one variant of `Option<Enum>`   |
//! | [`impl_delegated_accessors!`]   | Blanket `impl<T>` forwarding through a provider trait        |
//!
//! # What stays hand-written
//!
//! The [`TryIcmpAny`] / [`TryIcmpAnyMut`] traits don't fit this pattern
//! because:
//!
//! - Their return types are `Option<IcmpAny<'_>>` / `Option<IcmpAnyMut<'_>>`
//!   rather than `Option<&T>` / `Option<&mut T>`.
//! - Their implementations match *multiple* enum variants and wrap the result
//!   in a secondary enum.
//!
//! These remain hand-written (4 trait defs + 4 impls total across both files).

/// Defines a read/write accessor trait pair and implements them on a concrete
/// type by accessing an `Option<T>` field.
///
/// # Syntax
///
/// ```ignore
/// define_field_accessor! {
///     TraitName::method_name / TraitMutName::method_mut_name -> ReturnType,
///     for ConcreteType => self.field_name
/// }
/// ```
///
/// # Generated code
///
/// For `define_field_accessor!(TryEth::try_eth / TryEthMut::try_eth_mut -> Eth, for Headers => self.eth)`:
///
/// ```ignore
/// pub trait TryEth {
///     fn try_eth(&self) -> Option<&Eth>;
/// }
///
/// pub trait TryEthMut {
///     fn try_eth_mut(&mut self) -> Option<&mut Eth>;
/// }
///
/// impl TryEth for Headers {
///     fn try_eth(&self) -> Option<&Eth> {
///         self.eth.as_ref()
///     }
/// }
///
/// impl TryEthMut for Headers {
///     fn try_eth_mut(&mut self) -> Option<&mut Eth> {
///         self.eth.as_mut()
///     }
/// }
/// ```
macro_rules! define_field_accessor {
    (
        $Trait:ident :: $method:ident / $TraitMut:ident :: $method_mut:ident -> $T:ty,
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

/// Defines a read/write accessor trait pair and implements them on a concrete
/// type by extracting a specific enum variant from an `Option<Enum>` field.
///
/// # Syntax
///
/// ```ignore
/// define_variant_accessor! {
///     TraitName::method_name / TraitMutName::method_mut_name -> ReturnType,
///     for ConcreteType => self.field_name, match Enum::Variant
/// }
/// ```
///
/// # Generated code
///
/// For `define_variant_accessor!(TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut -> Ipv4, for Headers => self.net, match Net::Ipv4)`:
///
/// ```ignore
/// pub trait TryIpv4 {
///     fn try_ipv4(&self) -> Option<&Ipv4>;
/// }
///
/// pub trait TryIpv4Mut {
///     fn try_ipv4_mut(&mut self) -> Option<&mut Ipv4>;
/// }
///
/// impl TryIpv4 for Headers {
///     fn try_ipv4(&self) -> Option<&Ipv4> {
///         match &self.net {
///             Some(Net::Ipv4(header)) => Some(header),
///             _ => None,
///         }
///     }
/// }
///
/// impl TryIpv4Mut for Headers {
///     fn try_ipv4_mut(&mut self) -> Option<&mut Ipv4> {
///         match &mut self.net {
///             Some(Net::Ipv4(header)) => Some(header),
///             _ => None,
///         }
///     }
/// }
/// ```
macro_rules! define_variant_accessor {
    (
        $Trait:ident :: $method:ident / $TraitMut:ident :: $method_mut:ident -> $T:ty,
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

// ---------------------------------------------------------------------------
// Blanket delegation macro
// ---------------------------------------------------------------------------

/// Generates blanket `impl<T>` delegation impls that forward accessor trait
/// methods through a provider trait.
///
/// Two forms are supported, selected by the presence of the `try` keyword:
///
/// ## Direct delegation
///
/// Used when the provider method returns a **direct reference**
/// (e.g. `TryHeaders::headers()` -> `&impl AbstractHeaders`).
///
/// ```ignore
/// impl_delegated_accessors! {
///     via TryHeaders::headers / TryHeadersMut::headers_mut {
///         TryEth::try_eth / TryEthMut::try_eth_mut -> Eth,
///         TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut -> Ipv4,
///         TryIpv6::try_ipv6 / TryIpv6Mut::try_ipv6_mut -> Ipv6,
///         // ...
///     }
/// }
/// ```
///
/// Each entry generates:
///
/// ```ignore
/// impl<T: TryHeaders> TryEth for T {
///     fn try_eth(&self) -> Option<&Eth> {
///         self.headers().try_eth()
///     }
/// }
/// impl<T: TryHeadersMut> TryEthMut for T {
///     fn try_eth_mut(&mut self) -> Option<&mut Eth> {
///         self.headers_mut().try_eth_mut()
///     }
/// }
/// ```
///
/// ## Option-chaining delegation (`try via`)
///
/// Used when the provider method returns an **`Option`**
/// (e.g. `TryEmbeddedHeaders::embedded_headers()` -> `Option<&impl AbstractEmbeddedHeaders>`).
///
/// ```ignore
/// impl_delegated_accessors! {
///     try via TryEmbeddedHeaders::embedded_headers
///          / TryEmbeddedHeadersMut::embedded_headers_mut
///     {
///         TryInnerIpv4::try_inner_ipv4 / TryInnerIpv4Mut::try_inner_ipv4_mut -> Ipv4,
///         // ...
///     }
/// }
/// ```
///
/// Each entry generates the same shape, but with `?` to chain through the
/// `Option`:
///
/// ```ignore
/// impl<T: TryEmbeddedHeaders> TryInnerIpv4 for T {
///     fn try_inner_ipv4(&self) -> Option<&Ipv4> {
///         self.embedded_headers()?.try_inner_ipv4()
///     }
/// }
/// impl<T: TryEmbeddedHeadersMut> TryInnerIpv4Mut for T {
///     fn try_inner_ipv4_mut(&mut self) -> Option<&mut Ipv4> {
///         self.embedded_headers_mut()?.try_inner_ipv4_mut()
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
            -> $T:ty ),* $(,)?
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
            -> $T:ty ),* $(,)?
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
