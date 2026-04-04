# DPDK ACL input buffer: raw bytes vs parsed Headers

## Problem

DPDK ACL's `rte_acl_classify()` takes `&[*const u8]` — pointers to
raw packet data in network byte order.  The classifier reads fields
at the byte offsets specified in `FieldDef`.

Our `Classifier::classify()` takes `&Headers` — a parsed, host-byte-
order, aligned representation of the packet.  Bridging between these
two representations is required for the DPDK ACL backend.

## Options

### Option 1: Raw buffer passthrough (zero-copy)

The existing `Parse` mechanics in `dataplane-net` don't consume the
raw buffer bytes.  They advance a headroom counter and copy fields
into owned Rust structs.  The raw buffer remains intact after
parsing.

If the packet has been parsed but not mutated, the original bytes
are exactly what DPDK ACL needs — network byte order, correct
offsets, untouched.

**Requirements:**
- A way to prove the buffer hasn't been mutated.  Either a runtime
  `dirty` flag or a compile-time phantom type:

  ```rust
  struct Packet<Buf, State> { ... }
  struct Parsed;   // only reads have happened
  struct Mutated;  // a field was modified

  // DPDK ACL can only use the raw buffer if State = Parsed
  impl<Buf> Packet<Buf, Parsed> {
      fn raw_ptr(&self) -> *const u8 { ... }
  }
  ```

- Access to the raw buffer pointer from the classification call
  site.  The `Classifier::classify()` API currently takes `&Headers`,
  not `&Packet`.

**Cost:** Zero per-packet overhead (just pointer dereference).
**Complexity:** Requires changes to `Packet` type, `Headers`
creation, and the `Classifier` API.
**Risk:** Mutation tracking adds complexity to the entire packet
processing pipeline, not just the ACL system.

### Option 2: Assemble input from parsed Headers (v1 approach)

Build a fresh byte buffer from the parsed `Headers` values.  Copy
each field into the correct offset in network byte order.

```rust
fn assemble_acl_input(
    headers: &Headers,
    offsets: &impl OffsetProvider,
) -> [u8; MAX_ACL_INPUT_SIZE] {
    let mut buf = [0u8; MAX_ACL_INPUT_SIZE];
    if let Some(Net::Ipv4(ip)) = headers.net() {
        let src: [u8; 4] = ip.source().into().octets();
        buf[offsets.ipv4_src_offset()..][..4].copy_from_slice(&src);
        // ... etc
    }
    buf
}
```

**Cost:** ~20-60 bytes of copy + endianness conversion per packet.
Negligible compared to DPDK ACL trie traversal (~100-500ns).
**Complexity:** Low.  Self-contained function in `acl-dpdk`.
No changes to `Headers`, `Packet`, or the `Classifier` API.
**Risk:** Minimal.  Correct by construction — assembles from
known-good parsed values.

This also solves concerns about:
- **Alignment:** The assembled buffer is stack-allocated and
  naturally aligned.
- **Sub-byte fields:** VID (12 bits), DSCP (6 bits) etc. are
  handled during assembly, not at classification time.
- **Mutation safety:** The buffer is built from the current
  `Headers` state, regardless of whether the raw packet was
  modified.

### Option 3: Type-space vector + window (future)

The type-space vector (computed from parsing or from NIC metadata)
determines all field offsets at once.  A "window" struct provides
typed accessor/mutation methods scoped to the matched fields.

```rust
struct PacketWindow<'pkt> {
    buf: &'pkt mut [u8],
    offsets: FieldOffsets,  // derived from type-space vector
}

impl PacketWindow<'_> {
    fn ipv4_src(&self) -> Ipv4Addr { ... }      // read at known offset
    fn set_ipv4_src(&mut self, a: Ipv4Addr) { ... } // write at offset
}
```

The window is NOT a full replacement for the parser:
- It provides direct byte-level access to known fields.
- It cannot push/pop headers or change the protocol stack
  (that would change the type-space vector, invalidating the
  offsets).
- Structural mutations (push VLAN, encap/decap) must be
  **consuming operations** on the window — they take ownership,
  invalidate the old offsets, and require either a new window
  or a full re-parse.

For DPDK ACL input: the window's `buf` pointer IS the raw buffer
at the right offsets.  Zero copy, type-safe, and the offsets are
validated by the type-space vector.

**Cost:** Zero per-packet (offsets precomputed from type-space vector).
**Complexity:** High — requires type-space vector infrastructure.
**Risk:** The type-space vector is a significant design and
implementation investment.  Documented but not yet built.

## Recommendation

**V1:** Option 2 (assemble from Headers).  Low effort, correct,
testable, no architectural changes.  The ~40 bytes of copy per
packet is invisible in the profile.

**V2:** Option 1 (raw buffer passthrough) for packets that haven't
been mutated.  Requires mutation tracking on the packet type.

**V3:** Option 3 (type-space vector + window) for the full
zero-copy, type-safe, hardware-acceleratable path.

Each option builds on the previous — option 2's assembly logic
validates the field layout that option 3's window will use.
Option 1's mutation tracking is useful independently of DPDK ACL.
