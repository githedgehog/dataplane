# Match the chain you act on

A stage that makes a decision about a packet must match the **shape of its header chain**, not
reach into the headers for the fields it happens to want. `Headers::pat` in
[`net/src/headers/pat.rs`](../../net/src/headers/pat.rs) is what that looks like, and it exists for
this reason: a pattern that does not name a layer *misses* when that layer is present, so a stage
cannot silently act on a packet whose shape it never considered.

This is not a statement about which protocols we support. It is a statement about the difference
between "this stage handles this packet" and "this stage found the two fields it was looking for".

## What reaching in costs, measured twice

Two defects in the same week, from the same habit, failing in opposite directions.

**Reading a field that means something else.** `Net::next_header()` is the IP header's next-header
field. For IPv6 that names the *first extension header*, not the transport. `acl-filter` matched
rules against it, so a Deny rule naming TCP stopped applying to any TCP packet with one Hop-by-Hop
header in front of it -- and the sender chooses whether there is one. `flow-filter` made the same
mistake and it failed the other way, dropping traffic a protocol-restricted expose was configured
to carry. That one had been written down as a characterization test rather than recognised as a
defect.

**Not reading a field at all.** Both stages found the IP and transport headers of a VLAN-tagged
frame and reached their normal verdict. That is not an evasion -- tags sit ahead of the IP header,
so the protocol and ports were right -- but the verdict was reached without anybody considering
the tag, and nothing downstream considers it either. A tag chosen by whoever built the inner frame
of a tunnelled packet would be carried out onto whatever segment it names.

The first is a bug in a field's meaning; the second is a bug in a field's absence. A pattern catches
both, because it is a claim about the whole chain rather than about the parts a stage remembered.

## The gap-check policy

Set by `ExtGapCheck` and the VLAN cursor in `pat.rs`, and worth knowing before writing a pattern:

- **VLANs are always strict.** A pattern that does not name a VLAN misses on a tagged frame.
- **IPv6 extension headers are skipped** when the pattern goes straight from the network layer to
  the transport, and **strict** once the pattern has entered the extension region. Skipping is the
  right default: an extension header is not a layer most stages have an opinion about.

Because extensions are skipped, a pattern cannot tell you that the chain *ended* somewhere sensible.
A chain longer than `MAX_NET_EXTENSIONS` stops mid-parse and still matches. `Headers::upper_layer_proto`
is the complement: it walks to the end of the chain and returns `None` when it cannot get there. Use
both -- they answer different questions.

## Adding a layer we do not handle yet

Today the overlay refuses VLAN-tagged frames, at the decapsulation boundary in `IpForwarder`. That
is a statement about what this dataplane is currently equipped to do, **not** an architectural
position. VLAN inside VXLAN is logically valid traffic. So is MPLS, and so is whatever we have not
thought of; the parser already has somewhere to put a tag, and decapsulation already hands one on.

The reason a strict pattern is the right way to say "not yet" is that it makes the eventual "yes"
explicit and local: you name the layer in the pattern, and every stage that has not been taught
about it keeps refusing, loudly, instead of quietly guessing.

What teaching a stage about a new layer takes, as of this writing:

1. **Parse it.** `Headers` needs somewhere to put it and `pat` needs a combinator for it. VLANs
   have both. A new encapsulation would need both added, and `MAX_VLANS` / `MAX_NET_EXTENSIONS`
   have an analogue to decide: what happens to a chain longer than we will walk.
2. **Decide whether it distinguishes flows.** `FlowKey` carries the source VPC discriminant, the
   address pair and the protocol key, and nothing else -- so two frames differing only in a tag are
   one flow, and share one NAT translation.
3. **Decide what configuration expresses the policy.** There is none for VLANs today:
   `InterfaceType::Vlan(IfVlanConfig)` exists in the config model and nothing constructs it or
   matches on it.
4. **Decide what egress does.** `Egress::interface_egress_ethernet` rewrites the source and
   destination MAC and leaves everything else; re-encapsulation puts the outer headers in front of
   whatever is there. Preserve, rewrite or strip is a decision nobody has made.
5. **Name it in every pattern that should now accept it.** This is the step the strictness buys:
   the stages that should keep refusing do so without anybody having to remember them.

## Cost

One `ArrayVec::len` comparison, on the classify path of both filters. The combinators over layers a
stage already read are `Option` maps, `ext_gap_ok` for a network-layer position is a constant
`true`, the accumulator is a compile-time tuple, and `step` is `#[inline]`. Measure it if you doubt
it -- see the [benchmarking note](./benchmarking.md) -- but do not reach into the headers to save it.
