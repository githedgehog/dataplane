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

// ---------------------------------------------------------------------------
// Trait definition + concrete impl macros
// ---------------------------------------------------------------------------

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
///
/// # Applicable instances
///
/// **In `mod.rs`** (`Headers`):
/// - `TryEth` → `self.eth`
/// - `TryIp` → `self.net`
/// - `TryTransport` → `self.transport`
///
/// **In `embedded.rs`** (`EmbeddedHeaders`):
/// - `TryInnerIp` → `self.net`
/// - `TryEmbeddedTransport` → `self.transport`
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
///
/// # Applicable instances
///
/// **In `mod.rs`** (`Headers`):
/// - `TryIpv4` → `self.net`, match `Net::Ipv4`
/// - `TryIpv6` → `self.net`, match `Net::Ipv6`
/// - `TryTcp` → `self.transport`, match `Transport::Tcp`
/// - `TryUdp` → `self.transport`, match `Transport::Udp`
/// - `TryIcmp4` → `self.transport`, match `Transport::Icmp4`
/// - `TryIcmp6` → `self.transport`, match `Transport::Icmp6`
/// - `TryVxlan` → `self.udp_encap`, match `UdpEncap::Vxlan`
///
/// **In `embedded.rs`** (`EmbeddedHeaders`):
/// - `TryInnerIpv4` → `self.net`, match `Net::Ipv4`
/// - `TryInnerIpv6` → `self.net`, match `Net::Ipv6`
/// - `TryTruncatedTcp` → `self.transport`, match `EmbeddedTransport::Tcp`
/// - `TryTruncatedUdp` → `self.transport`, match `EmbeddedTransport::Udp`
/// - `TryTruncatedIcmp4` → `self.transport`, match `EmbeddedTransport::Icmp4`
/// - `TryTruncatedIcmp6` → `self.transport`, match `EmbeddedTransport::Icmp6`
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
/// (e.g. `TryHeaders::headers()` → `&impl AbstractHeaders`).
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
/// (e.g. `TryEmbeddedHeaders::embedded_headers()` → `Option<&impl AbstractEmbeddedHeaders>`).
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

// ---------------------------------------------------------------------------
// Reference: intended call sites
// ---------------------------------------------------------------------------
//
// Below is the intended macro usage that would replace the hand-written code.
//
// ## headers/mod.rs — trait definitions + impls on `Headers`
//
//     // Field accessors (Option<T> → &T)
//     define_field_accessor!(TryEth::try_eth / TryEthMut::try_eth_mut -> Eth, for Headers => self.eth);
//     define_field_accessor!(TryIp::try_ip / TryIpMut::try_ip_mut -> Net, for Headers => self.net);
//     define_field_accessor!(TryTransport::try_transport / TryTransportMut::try_transport_mut -> Transport, for Headers => self.transport);
//
//     // Variant accessors (Option<Enum> → match variant → &T)
//     define_variant_accessor!(TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut -> Ipv4, for Headers => self.net, match Net::Ipv4);
//     define_variant_accessor!(TryIpv6::try_ipv6 / TryIpv6Mut::try_ipv6_mut -> Ipv6, for Headers => self.net, match Net::Ipv6);
//     define_variant_accessor!(TryTcp::try_tcp / TryTcpMut::try_tcp_mut -> Tcp, for Headers => self.transport, match Transport::Tcp);
//     define_variant_accessor!(TryUdp::try_udp / TryUdpMut::try_udp_mut -> Udp, for Headers => self.transport, match Transport::Udp);
//     define_variant_accessor!(TryIcmp4::try_icmp4 / TryIcmp4Mut::try_icmp4_mut -> Icmp4, for Headers => self.transport, match Transport::Icmp4);
//     define_variant_accessor!(TryIcmp6::try_icmp6 / TryIcmp6Mut::try_icmp6_mut -> Icmp6, for Headers => self.transport, match Transport::Icmp6);
//     define_variant_accessor!(TryVxlan::try_vxlan / TryVxlanMut::try_vxlan_mut -> Vxlan, for Headers => self.udp_encap, match UdpEncap::Vxlan);
//
//     // TryIcmpAny / TryIcmpAnyMut — hand-written (irregular return type + multi-variant match)
//
// ## headers/mod.rs — blanket delegation via TryHeaders / TryHeadersMut
//
//     impl_delegated_accessors! {
//         via TryHeaders::headers / TryHeadersMut::headers_mut {
//             TryEth::try_eth / TryEthMut::try_eth_mut -> Eth,
//             TryIpv4::try_ipv4 / TryIpv4Mut::try_ipv4_mut -> Ipv4,
//             TryIpv6::try_ipv6 / TryIpv6Mut::try_ipv6_mut -> Ipv6,
//             TryIp::try_ip / TryIpMut::try_ip_mut -> Net,
//             TryTcp::try_tcp / TryTcpMut::try_tcp_mut -> Tcp,
//             TryUdp::try_udp / TryUdpMut::try_udp_mut -> Udp,
//             TryIcmp4::try_icmp4 / TryIcmp4Mut::try_icmp4_mut -> Icmp4,
//             TryIcmp6::try_icmp6 / TryIcmp6Mut::try_icmp6_mut -> Icmp6,
//             TryTransport::try_transport / TryTransportMut::try_transport_mut -> Transport,
//             TryVxlan::try_vxlan / TryVxlanMut::try_vxlan_mut -> Vxlan,
//         }
//     }
//
//     // TryIcmpAny / TryIcmpAnyMut delegation — hand-written (irregular return type)
//
// ## headers/embedded.rs — trait definitions + impls on `EmbeddedHeaders`
//
//     // Field accessors
//     define_field_accessor!(TryInnerIp::try_inner_ip / TryInnerIpMut::try_inner_ip_mut -> Net, for EmbeddedHeaders => self.net);
//     define_field_accessor!(TryEmbeddedTransport::try_embedded_transport / TryEmbeddedTransportMut::try_embedded_transport_mut -> EmbeddedTransport, for EmbeddedHeaders => self.transport);
//
//     // Variant accessors
//     define_variant_accessor!(TryInnerIpv4::try_inner_ipv4 / TryInnerIpv4Mut::try_inner_ipv4_mut -> Ipv4, for EmbeddedHeaders => self.net, match Net::Ipv4);
//     define_variant_accessor!(TryInnerIpv6::try_inner_ipv6 / TryInnerIpv6Mut::try_inner_ipv6_mut -> Ipv6, for EmbeddedHeaders => self.net, match Net::Ipv6);
//     define_variant_accessor!(TryTruncatedTcp::try_truncated_tcp / TryTruncatedTcpMut::try_truncated_tcp_mut -> TruncatedTcp, for EmbeddedHeaders => self.transport, match EmbeddedTransport::Tcp);
//     define_variant_accessor!(TryTruncatedUdp::try_truncated_udp / TryTruncatedUdpMut::try_truncated_udp_mut -> TruncatedUdp, for EmbeddedHeaders => self.transport, match EmbeddedTransport::Udp);
//     define_variant_accessor!(TryTruncatedIcmp4::try_truncated_icmp4 / TryTruncatedIcmp4Mut::try_truncated_icmp4_mut -> TruncatedIcmp4, for EmbeddedHeaders => self.transport, match EmbeddedTransport::Icmp4);
//     define_variant_accessor!(TryTruncatedIcmp6::try_truncated_icmp6 / TryTruncatedIcmp6Mut::try_truncated_icmp6_mut -> TruncatedIcmp6, for EmbeddedHeaders => self.transport, match EmbeddedTransport::Icmp6);
//
// ## headers/embedded.rs — blanket delegation via TryEmbeddedHeaders / TryEmbeddedHeadersMut
//
//     impl_delegated_accessors! {
//         try via TryEmbeddedHeaders::embedded_headers
//              / TryEmbeddedHeadersMut::embedded_headers_mut
//         {
//             TryInnerIpv4::try_inner_ipv4 / TryInnerIpv4Mut::try_inner_ipv4_mut -> Ipv4,
//             TryInnerIpv6::try_inner_ipv6 / TryInnerIpv6Mut::try_inner_ipv6_mut -> Ipv6,
//             TryInnerIp::try_inner_ip / TryInnerIpMut::try_inner_ip_mut -> Net,
//             TryTruncatedTcp::try_truncated_tcp / TryTruncatedTcpMut::try_truncated_tcp_mut -> TruncatedTcp,
//             TryTruncatedUdp::try_truncated_udp / TryTruncatedUdpMut::try_truncated_udp_mut -> TruncatedUdp,
//             TryTruncatedIcmp4::try_truncated_icmp4 / TryTruncatedIcmp4Mut::try_truncated_icmp4_mut -> TruncatedIcmp4,
//             TryTruncatedIcmp6::try_truncated_icmp6 / TryTruncatedIcmp6Mut::try_truncated_icmp6_mut -> TruncatedIcmp6,
//             TryEmbeddedTransport::try_embedded_transport / TryEmbeddedTransportMut::try_embedded_transport_mut -> EmbeddedTransport,
//         }
//     }
//
// ## Summary
//
// | Category                  | Hand-written items | Macro-generated items | LOC saved (approx) |
// |---------------------------|--------------------|----------------------|---------------------|
// | Trait definitions         | 4 (IcmpAny)        | 36                   | ~130                |
// | Impls on concrete type    | 4 (IcmpAny)        | 36                   | ~200                |
// | Blanket delegation impls  | 4 (IcmpAny)        | 36                   | ~200                |
// | **Total**                 | **12**              | **108**              | **~530**            |
