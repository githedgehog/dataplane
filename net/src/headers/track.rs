// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What has changed in a [`Headers`](super::Headers) since it was parsed.
//!
//! Parsing leaves the original header bytes in the buffer, just before the payload. If a stage
//! changes only some layers and nothing changes length, serializing need only rewrite those layers
//! in place: everything else already says what it should. [`Track`] records what that takes: the
//! length of the header bytes as parsed, one dirty bit per [`Headers`](super::Headers) slot, and a
//! *shape* bit for changes that make an in-place rewrite pointless (a layer added or removed, a
//! VLAN pushed or popped).
//!
//! # The contract
//!
//! Every way to mutate a slot of [`Headers`](super::Headers) marks that slot's bit (or the shape
//! bit) before handing anything out. The fields are private to the `headers` module, so outside it
//! the accessors are the only way in; inside it, every `&mut` to a field goes through a marking
//! accessor or marks by hand.
//!
//! Lengths are not tracked per layer. A layer can still change length in place (new TCP options,
//! or `*tcp = other`), and the shape bit cannot see that. Serializing checks it instead: when the
//! total length is unchanged, every layer before the first dirty one and after the last dirty one
//! sits where it did, so rewriting the span between them is enough, whatever changed inside it.
//!
//! A layout belongs to the buffer it was parsed from. A clone does not get one ([`Clone`] gives an
//! empty track), nor does a [`Headers`](super::Headers) built any other way than parsing.

/// One bit per [`Headers`](super::Headers) slot, in serialization order.
pub(crate) mod slot {
    pub(crate) const ETH: u8 = 1 << 0;
    pub(crate) const VLAN: u8 = 1 << 1;
    pub(crate) const NET: u8 = 1 << 2;
    pub(crate) const NET_EXT: u8 = 1 << 3;
    pub(crate) const TRANSPORT: u8 = 1 << 4;
    pub(crate) const UDP_ENCAP: u8 = 1 << 5;
    /// Every slot that has a dirty bit.
    pub(crate) const ALL: u8 = ETH | VLAN | NET | NET_EXT | TRANSPORT | UDP_ENCAP;
    /// The layers changed shape: rewrite everything. Also marks embedded headers and LLDP, which
    /// have no dirty bit of their own.
    pub(crate) const SHAPE: u8 = 1 << 7;
}

/// See the [module documentation](self).
#[derive(Debug, Default)]
pub(crate) struct Track {
    bits: u8,
    /// Length of the header bytes as parsed; zero when there is no layout to rewrite in place.
    original_len: u16,
}

impl Track {
    /// A freshly parsed layout of `len` header bytes, all clean.
    pub(crate) fn parsed(len: u16) -> Track {
        Track {
            bits: 0,
            original_len: len,
        }
    }

    /// Mark the slots in `bits` (see [`slot`]) as changed.
    #[inline]
    pub(crate) fn mark(&mut self, bits: u8) {
        self.bits |= bits;
    }

    /// The layout no longer describes the buffer (it moved, or was replaced).
    pub(crate) fn forget(&mut self) {
        self.original_len = 0;
    }

    /// The headers were written back: what the buffer holds is what they say again.
    pub(crate) fn clean(&mut self) {
        self.bits = 0;
    }

    /// The parsed length and dirty bits, if the headers can still be rewritten in place: there is
    /// a layout and nothing changed shape.
    #[inline]
    pub(crate) fn in_place(&self) -> Option<(u16, u8)> {
        if self.original_len == 0 || self.bits & slot::SHAPE != 0 {
            None
        } else {
            Some((self.original_len, self.bits))
        }
    }
}

/// A copy does not sit in the buffer its original was parsed from.
impl Clone for Track {
    fn clone(&self) -> Self {
        Track::default()
    }
}

/// Bookkeeping, not content: two [`Headers`](super::Headers) that say the same thing are equal
/// however they came about.
impl PartialEq for Track {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Track {}

/// How the accessor macros mark what they hand out `&mut` to, by field name.
pub(crate) trait MarkDirty {
    /// Mark the slot named `field` as changed.
    fn mark_field(&mut self, field: &'static str);
}

impl MarkDirty for super::Headers {
    #[inline]
    fn mark_field(&mut self, field: &'static str) {
        // A constant after inlining: the macros pass a literal.
        let bits = match field {
            "eth" => slot::ETH,
            "vlan" => slot::VLAN,
            "net" => slot::NET,
            "net_ext" => slot::NET_EXT,
            "transport" => slot::TRANSPORT,
            "udp_encap" => slot::UDP_ENCAP,
            _ => slot::SHAPE,
        };
        self.track.mark(bits);
    }
}

/// Embedded headers are reached through [`Headers::embedded_ip_mut`](super::Headers) or
/// [`Headers::pat_mut`](super::Headers), which mark the shape bit for them.
impl MarkDirty for super::EmbeddedHeaders {
    #[inline]
    fn mark_field(&mut self, _: &'static str) {}
}
