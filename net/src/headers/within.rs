// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Layer-ordering constraints for the network header stack.
//!
//! [`Within<T>`] encodes which header type may directly follow which other
//! header type in a well-formed packet.  The trait serves two purposes:
//!
//! 1. **Compile-time ordering** -- used as a bound on generic builder and
//!    matcher methods so that invalid layer transitions are compile errors.
//! 2. **Parent conformance** -- [`Within::conform`] adjusts structural fields
//!    on a parent header to be consistent with a given child (e.g. setting
//!    `EthType::IPV4` on an Ethernet header when IPv4 is stacked on top).
//!
//! Absence of an `impl Within<T> for U` means "U cannot directly follow T",
//! which the compiler enforces automatically.

use super::{Net, Transport};
use crate::checksum::Checksum;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ip::NextHeader;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::Tcp;
use crate::udp::{Udp, UdpChecksum};
use crate::vlan::Vlan;
use crate::vxlan::Vxlan;

/// Declares that `Self` is a valid child of layer `T`.
///
/// This trait serves two purposes:
///
/// 1. **Compile-time ordering** -- used as a bound on builder and matcher
///    methods so that invalid layer transitions are compile errors.
/// 2. **Parent conformance** -- [`conform`](Within::conform) adjusts
///    structural fields on the parent to be consistent with the child
///    (e.g. setting `EthType::IPV4` on an Ethernet header when IPv4 is
///    stacked on top).
///
/// Conformance is called automatically by `HeaderStack::stack` before
/// the parent is installed into [`Headers`](super::Headers).
///
/// # Enum-level impls
///
/// Some impls exist for enum types ([`Net`], [`Transport`],
/// [`EmbeddedTransport`]) with no-op [`conform`](Within::conform) bodies.
/// These serve the pattern matcher ([`pat`](super::pat)) only -- they let
/// callers write `.net().tcp()` to match "any IP version followed by TCP"
/// without committing to IPv4 vs IPv6.
///
/// The builder is safe from these impls because `HeaderStack::stack`
/// additionally requires `Blank`, which is not implemented for enum
/// types.  Attempting to stack `Net` or `Transport` directly in the
/// builder is a compile error.
pub trait Within<T> {
    /// Adjust `parent` so its protocol/type fields are consistent with `Self`.
    fn conform(parent: &mut T);
}

// ---- Eth (entry layer) ----------------------------------------------------

impl Within<()> for Eth {
    fn conform(_parent: &mut ()) {}
}

// ---- Vlan -----------------------------------------------------------------

impl Within<Eth> for Vlan {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::VLAN);
    }
}

impl Within<Vlan> for Vlan {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::VLAN);
    }
}

// ---- Ipv4 -----------------------------------------------------------------

impl Within<Eth> for Ipv4 {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::IPV4);
    }
}

impl Within<Vlan> for Ipv4 {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::IPV4);
    }
}

// ---- Ipv6 -----------------------------------------------------------------

impl Within<Eth> for Ipv6 {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::IPV6);
    }
}

impl Within<Vlan> for Ipv6 {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::IPV6);
    }
}

// ---- Transport after IP ---------------------------------------------------

impl Within<Ipv4> for Tcp {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv6> for Tcp {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv4> for Udp {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv6> for Udp {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4> for Icmp4 {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::ICMP);
    }
}

impl Within<Ipv6> for Icmp6 {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

// ---- UDP encapsulation ----------------------------------------------------

impl Within<Udp> for Vxlan {
    fn conform(parent: &mut Udp) {
        let _ = parent.set_checksum(UdpChecksum::ZERO);
        parent.set_destination(Vxlan::PORT);
    }
}

// ---------------------------------------------------------------------------
// IPv6 extension headers (RFC 8200 section 4.1 ordering)
// ---------------------------------------------------------------------------
//
// Recommended order:
//   IPv6 -> HopByHop -> DestOpts -> Routing -> Fragment -> AH -> DestOpts -> upper
//
// HopByHop MUST immediately follow IPv6 when present.
// DestOpts may appear in two positions (before Routing, and after AH).
// The `Within` bounds encode valid parent->child transitions; absence of
// an impl = compile error = invalid ordering.

// -- HopByHop: only after Ipv6 --

impl Within<Ipv6> for HopByHop {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::HOP_BY_HOP);
    }
}

// -- DestOpts: after Ipv6, HopByHop, Routing, Fragment, or Ipv6Auth --
// RFC 8200 section 4.1 allows DestOpts in two positions: before Routing
// (first occurrence) and as the final extension before the upper layer.

impl Within<Ipv6> for DestOpts {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<HopByHop> for DestOpts {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<Routing> for DestOpts {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<Fragment> for DestOpts {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<Ipv6Auth> for DestOpts {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

// -- Routing: after Ipv6, HopByHop, or DestOpts --

impl Within<Ipv6> for Routing {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::ROUTING);
    }
}

impl Within<HopByHop> for Routing {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::ROUTING);
    }
}

impl Within<DestOpts> for Routing {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::ROUTING);
    }
}

// -- Fragment: after Ipv6, HopByHop, DestOpts, or Routing --

impl Within<Ipv6> for Fragment {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

impl Within<HopByHop> for Fragment {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

impl Within<DestOpts> for Fragment {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

impl Within<Routing> for Fragment {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

// -- Ipv4Auth: after Ipv4 only --

impl Within<Ipv4> for Ipv4Auth {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

// -- Ipv6Auth: after Ipv6, HopByHop, DestOpts, Routing, or Fragment --

impl Within<Ipv6> for Ipv6Auth {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<HopByHop> for Ipv6Auth {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<DestOpts> for Ipv6Auth {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<Routing> for Ipv6Auth {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<Fragment> for Ipv6Auth {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

// -- Transport after extension headers --
// Tcp, Udp, Icmp6 can follow any IPv6 extension header.
// Icmp4 can follow Ipv4Auth (IPv4 context).

impl Within<HopByHop> for Tcp {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<DestOpts> for Tcp {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Routing> for Tcp {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Fragment> for Tcp {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv4Auth> for Tcp {
    fn conform(parent: &mut Ipv4Auth) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv6Auth> for Tcp {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<HopByHop> for Udp {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<DestOpts> for Udp {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Routing> for Udp {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Fragment> for Udp {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4Auth> for Udp {
    fn conform(parent: &mut Ipv4Auth) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv6Auth> for Udp {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4Auth> for Icmp4 {
    fn conform(parent: &mut Ipv4Auth) {
        parent.set_next_header(NextHeader::ICMP);
    }
}

impl Within<HopByHop> for Icmp6 {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<DestOpts> for Icmp6 {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Routing> for Icmp6 {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Fragment> for Icmp6 {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Ipv6Auth> for Icmp6 {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

// ---------------------------------------------------------------------------
// EmbeddedHeaders -- follows ICMP error messages
// ---------------------------------------------------------------------------

use super::{EmbeddedHeaders, EmbeddedTransport};
use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::TruncatedIcmp6;
use crate::tcp::TruncatedTcp;
use crate::udp::TruncatedUdp;

/// Marker type for the starting position of an [`crate::headers::pat::EmbeddedMatcher`].
///
/// Embedded headers begin at the network layer (no Eth, no VLAN), so
/// `Within<EmbeddedStart>` is implemented for Ipv4, Ipv6, and Net.
pub struct EmbeddedStart;

impl Within<EmbeddedStart> for Ipv4 {
    fn conform(_parent: &mut EmbeddedStart) {}
}
impl Within<EmbeddedStart> for Ipv6 {
    fn conform(_parent: &mut EmbeddedStart) {}
}
impl Within<EmbeddedStart> for Net {
    fn conform(_parent: &mut EmbeddedStart) {}
}

impl Within<Icmp4> for EmbeddedHeaders {
    fn conform(_parent: &mut Icmp4) {}
}

impl Within<Icmp6> for EmbeddedHeaders {
    fn conform(_parent: &mut Icmp6) {}
}

// -- Truncated transport types (inside EmbeddedHeaders) --
// Same Within graph as the full transport types, but for TruncatedTcp etc.
// conform is no-op (these are never used in the builder).

macro_rules! impl_truncated_within {
    ($T:ty, [$($Parent:ty),*]) => {$(
        impl Within<$Parent> for $T {
            fn conform(_parent: &mut $Parent) {}
        }
    )*};
}

impl_truncated_within!(
    TruncatedTcp,
    [
        Ipv4, Ipv6, Net, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    ]
);
impl_truncated_within!(
    TruncatedUdp,
    [
        Ipv4, Ipv6, Net, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    ]
);
impl_truncated_within!(TruncatedIcmp4, [Ipv4, Ipv4Auth]);
impl_truncated_within!(
    TruncatedIcmp6,
    [Ipv6, HopByHop, DestOpts, Routing, Fragment, Ipv6Auth]
);

// EmbeddedTransport enum -- same positions as Transport
impl_truncated_within!(
    EmbeddedTransport,
    [
        Ipv4, Ipv6, Net, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    ]
);

// ---------------------------------------------------------------------------
// Enum-level impls for the pattern matcher
// ---------------------------------------------------------------------------
//
// These allow the pattern matcher to return `&Net` or `&Transport` directly
// so callers can branch on the variant themselves (e.g. `.net().tcp()`
// matches "any IP version followed by TCP").
//
// The `conform` bodies are no-ops because the correct protocol field
// depends on the runtime variant, which is unavailable in the static
// `conform` context.
//
// Safety from builder misuse: `HeaderStack::stack` requires `Blank`,
// which is NOT implemented for these enum types.  Attempting to stack
// `Net` or `Transport` in the builder is a compile error.

// -- Net: valid after Eth or Vlan (same positions as Ipv4/Ipv6) --

impl Within<Eth> for Net {
    fn conform(_parent: &mut Eth) {}
}

impl Within<Vlan> for Net {
    fn conform(_parent: &mut Vlan) {}
}

// -- Transport: valid after any IP or extension header --

impl Within<Ipv4> for Transport {
    fn conform(_parent: &mut Ipv4) {}
}

impl Within<Ipv6> for Transport {
    fn conform(_parent: &mut Ipv6) {}
}

impl Within<Net> for Transport {
    fn conform(_parent: &mut Net) {}
}

impl Within<HopByHop> for Transport {
    fn conform(_parent: &mut HopByHop) {}
}

impl Within<DestOpts> for Transport {
    fn conform(_parent: &mut DestOpts) {}
}

impl Within<Routing> for Transport {
    fn conform(_parent: &mut Routing) {}
}

impl Within<Fragment> for Transport {
    fn conform(_parent: &mut Fragment) {}
}

impl Within<Ipv4Auth> for Transport {
    fn conform(_parent: &mut Ipv4Auth) {}
}

impl Within<Ipv6Auth> for Transport {
    fn conform(_parent: &mut Ipv6Auth) {}
}

// -- Concrete transport types after Net (valid for both IPv4 and IPv6) --
// Icmp4 and Icmp6 are NOT Within<Net> because they are version-specific.

impl Within<Net> for Tcp {
    fn conform(_parent: &mut Net) {}
}

impl Within<Net> for Udp {
    fn conform(_parent: &mut Net) {}
}

/// What [`Within::conform`] is for, checked against the parser.
///
/// `conform` writes the parent's protocol field so it names the child: `EthType::IPV6` on an
/// Ethernet header carrying IPv6, `NextHeader::ROUTING` on an IPv6 header carrying a routing
/// extension. It is the only reason this trait has a method at all -- the ordering half of the
/// contract is enforced by the compiler, by the presence or absence of an impl, and needs no test.
///
/// Thirty-two of these bodies had never run. Every one of them was an IPv6 extension header
/// transition or `Vlan` inside `Vlan`, which is to say: the whole extension region, plus the second
/// tag of a double-tagged frame. The reason is that `conform` is reached only through
/// [`HeaderStack::stack`](crate::headers::builder::HeaderStack::stack), and while the builder has had
/// `.hop_by_hop()`, `.dest_opts()`, `.routing()`, `.fragment()`, `.ipv4_auth()` and `.ipv6_auth()`
/// all along, no test ever called one. The generators reach the extension region constantly, but
/// they assemble [`Headers`](crate::headers::Headers) field by field and never go through the
/// builder, so they never conform anything.
///
/// # The oracle
///
/// A test that builds a packet and then reads back the field `conform` just wrote would be checking
/// the implementation against itself. So the check is deparse-then-parse: the parser decides what
/// follows an IPv6 header by reading its next-header field, which is the field `conform` sets, so a
/// `conform` that names the wrong protocol produces bytes the parser reads as a different packet --
/// or as no valid packet at all.
///
/// # Scrambling
///
/// Each layer's next-header field is set to a fuzzed byte *before* the next layer is stacked, so
/// `conform` is always overwriting a wrong value rather than filling in a blank one.
///
/// That is not a precaution, it is load-bearing, and the case that proves it is `Ipv4` inside `Eth`.
/// [`Blank`] for `Eth` produces `EthType::IPV4`, so on a blank Ethernet header the conform that sets
/// `EthType::IPV4` has nothing to do: delete its body and every packet still round-trips. Scrambled,
/// the same deletion fails two chains. `Vlan` has the same blank and the same exposure.
///
/// # What is left, and why it stays uncovered
///
/// Nineteen no-op `conform` bodies remain unrun: the enum-level impls, the `EmbeddedStart` impls and
/// everything `impl_truncated_within!` generates. They are not merely untested, they are unreachable
/// through the builder, and the compiler says so twice -- writing
/// `HeaderStack::new().eth(..).stack::<Net>(..)` fails with both `Net: Blank is not satisfied` and
/// `Headers: Install<Net> is not satisfied`. Either bound alone would be enough.
///
/// They exist to give the pattern matcher its `Within` edges, which need the trait but not the
/// method. `conform` is a public trait method, so they are callable in principle by anyone holding
/// the parent; nothing in the tree does. Whether nineteen uncallable bodies are worth keeping is a
/// question for whoever owns the trait, not something a test can settle.
///
/// [`Blank`]: crate::headers::builder::Blank
#[cfg(test)]
mod conform_properties {
    use crate::eth::Eth;
    use crate::eth::ethtype::EthType;
    use crate::headers::builder::HeaderStack;
    use crate::headers::test::parse_back_test;
    use crate::headers::{Headers, Transport};
    use crate::icmp4::{
        Icmp4, Icmp4DestUnreachable, Icmp4EchoReply, Icmp4EchoRequest, Icmp4ParamProblem,
        Icmp4Redirect, Icmp4TimeExceeded, Icmp4Type,
    };
    use crate::icmp6::{
        Icmp6, Icmp6DestUnreachable, Icmp6EchoReply, Icmp6EchoRequest, Icmp6PacketTooBig,
        Icmp6ParamProblem, Icmp6TimeExceeded, Icmp6Type,
    };
    use crate::ip::NextHeader;
    use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
    use crate::ipv4::Ipv4;
    use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
    use crate::tcp::Tcp;
    use crate::udp::Udp;
    use crate::vlan::Vlan;

    /// Put a wrong protocol number in the field `conform` is responsible for.
    ///
    /// Implemented for every layer the builder can stack. The transport types are the leaves of
    /// every chain -- nothing is ever stacked on top of one, so nothing ever conforms one -- and
    /// their impls are deliberately empty rather than absent, so that the chain macro does not have
    /// to know which layers are interior.
    trait Scramble {
        /// Overwrite the protocol field with something derived from `seed`.
        fn scramble(&mut self, seed: u8);
    }

    macro_rules! scramble_next_header {
        ($($T:ty),+ $(,)?) => {$(
            impl Scramble for $T {
                fn scramble(&mut self, seed: u8) {
                    self.set_next_header(NextHeader::new(seed));
                }
            }
        )+};
    }

    macro_rules! scramble_leaf {
        ($($T:ty),+ $(,)?) => {$(
            impl Scramble for $T {
                fn scramble(&mut self, _seed: u8) {}
            }
        )+};
    }

    scramble_next_header!(
        Ipv4, Ipv6, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    );
    scramble_leaf!(Tcp, Udp);
    // The ICMP subtypes are the only layers that can sit on top of an ICMP header, and nothing sits
    // on top of them.
    scramble_leaf!(
        Icmp4DestUnreachable,
        Icmp4Redirect,
        Icmp4TimeExceeded,
        Icmp4ParamProblem,
        Icmp4EchoRequest,
        Icmp4EchoReply,
        Icmp6DestUnreachable,
        Icmp6PacketTooBig,
        Icmp6TimeExceeded,
        Icmp6ParamProblem,
        Icmp6EchoRequest,
        Icmp6EchoReply,
    );

    // ICMP is the one place where `conform` writes a message type rather than a protocol number, so
    // `Unknown` is the scramble: it is the one variant matching no subtype, which makes it wrong for
    // every chain below rather than accidentally right for one of them.
    //
    // The type byte is fixed rather than fuzzed, and has to be. `Unknown` stores the raw byte, so
    // `Unknown { type_u8: 3 }` deparses to the same three bytes a destination-unreachable message
    // does and parses back as one -- a header the round-trip is right to reject, and nothing to do
    // with `conform`. 253 for v4 and 200 for v6 are reserved for experimentation and belong to no
    // variant, so they survive the round trip as themselves. The rest of the message stays fuzzed.
    impl Scramble for Icmp4 {
        fn scramble(&mut self, seed: u8) {
            self.set_type(crate::icmp4::Icmp4Type::Unknown {
                type_u8: 253,
                code_u8: seed,
                bytes5to8: [seed; 4],
            });
        }
    }

    impl Scramble for Icmp6 {
        fn scramble(&mut self, seed: u8) {
            self.set_type(crate::icmp6::Icmp6Type::Unknown {
                type_u8: 200,
                code_u8: seed,
                bytes5to8: [seed; 4],
            });
        }
    }

    impl Scramble for Eth {
        fn scramble(&mut self, seed: u8) {
            self.set_ether_type(EthType::new(u16::from(seed)));
        }
    }

    impl Scramble for Vlan {
        fn scramble(&mut self, seed: u8) {
            self.set_inner_ethtype(EthType::new(u16::from(seed)));
        }
    }

    /// Build the named chain through the builder, scrambling as it goes, and round-trip it.
    ///
    /// The chain is a list of `HeaderStack` method names, and the closures are written here rather
    /// than at the call site: a closure written at the call site could not name the `seed` this
    /// macro binds, macro hygiene being what it is, and every call site would then have to repeat
    /// the same closure once per layer.
    macro_rules! conform_chain {
        ($name:ident, $($layer:ident),+ $(,)?) => {
            conform_chain!(@build $name, |_| {}, $($layer),+);
        };
        (specialized $name:ident, $($layer:ident),+ $(,)?) => {
            conform_chain!(@build $name, icmp_type_was_specialized, $($layer),+);
        };
        (@build $name:ident, $check:expr, $($layer:ident),+) => {
            #[test]
            fn $name() {
                bolero::check!().with_type().for_each(|seed: &u8| {
                    let seed = *seed;
                    let built = HeaderStack::new()
                        $(.$layer(|l| l.scramble(seed)))+
                        .build_headers();
                    let headers = built.unwrap_or_else(|e| {
                        unreachable!("a blank {} chain does not overflow: {e:?}", stringify!($name))
                    });
                    parse_back_test(&headers);
                    $check(&headers);
                });
            }
        };
    }

    /// The scrambled ICMP type did not survive into the built packet.
    ///
    /// Only for chains that end in a subtype layer. A chain ending at a bare `.icmp4()` has nothing
    /// above it to conform it, so the scramble is *supposed* to survive there, and round-tripping is
    /// the only thing to check.
    ///
    /// Worth stating why this is separate from the round trip rather than folded into it: the
    /// scrambled type is a well-formed ICMP message, so a packet still carrying it deparses and
    /// parses back perfectly. The round trip cannot tell that the specialization never happened.
    fn icmp_type_was_specialized(headers: &Headers) {
        match headers.transport() {
            Some(Transport::Icmp4(icmp)) => assert!(
                !matches!(icmp.icmp_type(), Icmp4Type::Unknown { type_u8: 253, .. }),
                "the scrambled ICMPv4 type survived the build, so nothing specialized it"
            ),
            Some(Transport::Icmp6(icmp)) => assert!(
                !matches!(icmp.icmp_type(), Icmp6Type::Unknown { type_u8: 200, .. }),
                "the scrambled ICMPv6 type survived the build, so nothing specialized it"
            ),
            other => unreachable!("a subtype chain builds an ICMP transport, got {other:?}"),
        }
    }

    // Seventeen chains, chosen to cover all thirty-two unreached transitions between them. Three
    // extension headers is the ceiling -- `MAX_NET_EXTENSIONS` -- so the deeper regions of the graph
    // have to be reached by several chains rather than one long one.
    conform_chain!(
        double_tag_then_three_extensions,
        eth,
        vlan,
        vlan,
        ipv6,
        dest_opts,
        routing,
        fragment,
        tcp
    );
    conform_chain!(
        hop_by_hop_routing_dest_opts,
        eth,
        ipv6,
        hop_by_hop,
        routing,
        dest_opts,
        udp
    );
    conform_chain!(
        routing_fragment_auth,
        eth,
        ipv6,
        routing,
        fragment,
        ipv6_auth,
        tcp
    );
    conform_chain!(
        fragment_then_dest_opts,
        eth,
        ipv6,
        fragment,
        dest_opts,
        icmp6
    );
    conform_chain!(
        hop_by_hop_then_fragment,
        eth,
        ipv6,
        hop_by_hop,
        fragment,
        udp
    );
    conform_chain!(
        dest_opts_then_fragment,
        eth,
        ipv6,
        dest_opts,
        fragment,
        icmp6
    );
    conform_chain!(auth_then_dest_opts, eth, ipv6, ipv6_auth, dest_opts, udp);
    conform_chain!(
        hop_by_hop_then_auth,
        eth,
        ipv6,
        hop_by_hop,
        ipv6_auth,
        icmp6
    );
    conform_chain!(dest_opts_then_auth, eth, ipv6, dest_opts, ipv6_auth, tcp);
    conform_chain!(routing_then_auth, eth, ipv6, routing, ipv6_auth, udp);
    conform_chain!(hop_by_hop_then_udp, eth, ipv6, hop_by_hop, udp);
    conform_chain!(routing_then_udp, eth, ipv6, routing, udp);
    conform_chain!(
        hop_by_hop_then_routing_then_tcp,
        eth,
        ipv6,
        hop_by_hop,
        routing,
        tcp
    );
    conform_chain!(hop_by_hop_then_icmp6, eth, ipv6, hop_by_hop, icmp6);
    conform_chain!(routing_then_icmp6, eth, ipv6, routing, icmp6);
    // The IPv4 authentication header is the only extension that belongs on a v4 packet.
    conform_chain!(v4_auth_then_udp, eth, ipv4, ipv4_auth, udp);
    conform_chain!(v4_auth_then_icmp4, eth, ipv4, ipv4_auth, icmp4);

    // The ICMP message subtypes, which the builder can specialize into and which no test had ever
    // asked for. Ten of the twelve `Blank` impls behind them had never been called either -- the two
    // that had were what made the shared macro bodies look covered, since a `macro_rules!` line
    // counts as run once any one of its expansions runs. Worth knowing generally: a table of twelve
    // generated impls reports as covered when one of the twelve is exercised, and only the
    // hand-written part of each -- here `blank()` -- shows the difference.
    conform_chain!(specialized icmp4_dest_unreachable, eth, ipv4, icmp4, dest_unreachable);
    conform_chain!(specialized icmp4_redirect, eth, ipv4, icmp4, redirect);
    conform_chain!(specialized icmp4_time_exceeded, eth, ipv4, icmp4, time_exceeded);
    conform_chain!(specialized icmp4_param_problem, eth, ipv4, icmp4, param_problem);
    conform_chain!(specialized icmp4_echo_request, eth, ipv4, icmp4, echo_request);
    conform_chain!(specialized icmp4_echo_reply, eth, ipv4, icmp4, echo_reply);
    conform_chain!(specialized icmp6_dest_unreachable, eth, ipv6, icmp6, dest_unreachable6);
    conform_chain!(specialized icmp6_packet_too_big, eth, ipv6, icmp6, packet_too_big6);
    conform_chain!(specialized icmp6_time_exceeded, eth, ipv6, icmp6, time_exceeded6);
    conform_chain!(specialized icmp6_param_problem, eth, ipv6, icmp6, param_problem6);
    conform_chain!(specialized icmp6_echo_request, eth, ipv6, icmp6, echo_request6);
    conform_chain!(specialized icmp6_echo_reply, eth, ipv6, icmp6, echo_reply6);

    /// A subtype the caller customized, which is what separates the two writers of the ICMP type.
    ///
    /// The chains above cannot tell `Within::conform` from `Install` for these layers, and no test
    /// could, because both write the same value: `conform` sets `DestUnreachable(blank())` and
    /// `Install` sets `DestUnreachable(value)`, and `value` is `blank()` whenever the caller does not
    /// change it. Empty either one alone and the other still produces the right packet.
    ///
    /// Choosing a code other than the blank one separates them, and the answer is that `conform` is
    /// the redundant half. `Install` runs unconditionally from `build_headers`, after `conform`, and
    /// overwrites whatever `conform` wrote -- so all twelve of these `conform` bodies could be empty
    /// with no observable change. Nothing can be stacked on a subtype, so there is no arrangement in
    /// which `conform` gets the last word.
    ///
    /// Pinned here rather than acted on: emptying them is a call for whoever owns the builder.
    #[test]
    fn a_customized_subtype_survives_the_build() {
        let headers = HeaderStack::new()
            .eth(|l| l.scramble(0))
            .ipv4(|l| l.scramble(0))
            .icmp4(|l| l.scramble(0))
            .dest_unreachable(|d| *d = Icmp4DestUnreachable::Port)
            .build_headers()
            .unwrap_or_else(|e| unreachable!("a blank chain does not overflow: {e:?}"));

        let Some(Transport::Icmp4(icmp)) = headers.transport() else {
            unreachable!("the chain builds an ICMPv4 transport")
        };
        assert_eq!(
            icmp.icmp_type(),
            Icmp4Type::DestUnreachable(Icmp4DestUnreachable::Port),
            "the code the caller chose did not reach the built packet"
        );
        parse_back_test(&headers);
    }
}
