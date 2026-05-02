# tc-flower backend tractability assessment

## Summary

A tc-flower ACL backend is **highly tractable**.  The existing netlink
bindings (`hh/tc-actions3` branch of `githedgehog/rtnetlink` +
`pr/daniel-noland/swing4` branch of `githedgehog/netlink-packet-route`)
cover the full match-action space we need, including features that
rte_flow lacks (native port ranges, conntrack state matching).

## Match field coverage

The `TcFilterFlowerOption` enum in netlink-packet-route covers 100+
NLA types.  Every ACL match field we've defined maps directly:

| ACL field | tc-flower NLA | Notes |
|---|---|---|
| `EthMatch.src_mac` | `EthSrc` + `EthSrcMask` | 6-byte MAC + mask |
| `EthMatch.dst_mac` | `EthDst` + `EthDstMask` | Same |
| `EthMatch.ether_type` | `EthType` | u16, network order |
| `VlanMatch.vid` | `VlanId` | u16 |
| `VlanMatch.pcp` | `VlanPrio` | u8 |
| `VlanMatch.inner_ether_type` | `VlanEthType` | u16 |
| QinQ (2nd VLAN) | `CvlanId`, `CvlanPrio`, `CvlanEthType` | Full QinQ support |
| `Ipv4Match.src` | `Ipv4Src` + `Ipv4SrcMask` | Prefix → addr + mask |
| `Ipv4Match.dst` | `Ipv4Dst` + `Ipv4DstMask` | Same |
| `Ipv4Match.protocol` | `IpProto` | u8 |
| `Ipv6Match.src` | `Ipv6Src` + `Ipv6SrcMask` | 128-bit + mask |
| `Ipv6Match.dst` | `Ipv6Dst` + `Ipv6DstMask` | Same |
| `TcpMatch.src` | `TcpSrc`+`TcpSrcMask` OR `PortSrcMin`+`PortSrcMax` | Exact or range |
| `TcpMatch.dst` | `TcpDst`+`TcpDstMask` OR `PortDstMin`+`PortDstMax` | Same |
| `UdpMatch` | Same pattern as TCP | Full parity |
| `Icmp4Match.icmp_type` | `Icmpv4Type` + `Icmpv4TypeMask` | u8 + mask |
| `Icmp4Match.icmp_code` | `Icmpv4Code` + `Icmpv4CodeMask` | u8 + mask |

### Advantages over rte_flow

- **Native port range matching** via `PortSrcMin`/`PortSrcMax`/
  `PortDstMin`/`PortDstMax`.  No ternary decomposition needed.
  Our `PortRange<u16>` compiles directly.

- **Conntrack state matching** via `CtState`, `CtZone`, `CtMark`,
  `CtLabels`.  This is critical for the generation-tagged update
  strategy with stateful rules (NAT) — the compiler can match on
  conntrack state to distinguish established vs new connections.

- **DSCP/TOS matching** via `IpTos` + `IpTosMask`.

- **TCP flags matching** via `TcpFlags` + `TcpFlagsMask`.

- **ARP matching** via `ArpSip`, `ArpTip`, `ArpOp`, `ArpSha`, `ArpTha`
  with masks.  Useful for ARP inspection / spoofing prevention.

- **Encap header matching** (tunnel outer headers) via `EncKey*`
  variants.  Matches on tunnel key ID, outer IP src/dst, outer UDP
  port — all with masks.

### Match types NOT in our current ACL model but available in tc-flower

These are extension opportunities:

- SCTP ports (`SctpSrc`, `SctpDst`)
- ICMPv6 type/code
- IP TTL matching (useful for TTL-based filtering)
- MPLS labels, BOS, TC, TTL
- Conntrack state/zone/mark/labels
- Flow hash (`KeyHash`)

## Action coverage

The interface-manager tc module implements three action families:

| Action | tc type | Maps to ACL |
|---|---|---|
| Drop | `GenericAction(Drop)` | `Fate::Drop` |
| Pass | `GenericAction(Pass)` | `Fate::Forward` |
| Jump to chain | `GenericAction(Jump(chain))` | `Fate::Jump(TableId)` |
| Goto chain | `GenericAction(Goto(chain))` | `Fate::Jump(TableId)` |
| Mirror/redirect | `Mirred` | Future `Step::Redirect` |
| VXLAN encap | `TunnelKey(Set)` | Future `Step::Encap` |
| VXLAN decap | `TunnelKey(Unset)` | Future `Step::Decap` |

### Missing action types (can be added to rtnetlink)

- `skbedit` — needed for `Step::Mark` (set packet mark/priority)
- `police` — needed for rate limiting
- `pedit` — packet editing (set field values)
- `conntrack` — conntrack action for stateful offload
- `ct_clear` — clear conntrack state

## Architecture: how the compiler maps

```
AclRule
  → AclMatchFields → Vec<TcFilterFlowerOption>   (match compilation)
  → ActionSequence → Vec<TcAction>                (action lowering)
  → Priority       → filter priority (u16)
  → chain ID       → tc chain index

AclTable
  → tc chain on a qdisc (clsact ingress or egress)
  → or tc chain on a shared block (multi-interface)
```

The compilation structure is identical to acl-rte-flow:
translate match fields to flower options, lower actions to tc
actions, set priority.

### Rekon integration

The existing rekon framework handles desired-state reconciliation:

1. Compiler produces desired `FilterSpec` + actions
2. Rekon `Create` installs via netlink
3. For updates: rekon `Observe` reads current state, `Reconcile`
   computes diff, applies create/update/remove

Filter `Reconcile` is currently not implemented (only `Create`).
This is the main gap for the generation-tagged update strategy —
we need full lifecycle management (observe, compare, remove).

## Effort estimate

| Task | Effort | Blocking? |
|---|---|---|
| Match compilation (flower options) | Low | No — same pattern as rte_flow |
| Action lowering (gact, mirred, tunnel_key) | Low | No — actions exist |
| Filter creation via rekon | Done | N/A |
| Filter observation + reconciliation | Medium | Yes — needed for updates |
| skbedit action (for Step::Mark) | Low | Not for v1 |
| Port range compilation | Trivial | No — native support |
| Prefix → addr + mask compilation | Trivial | No — Ipv4Prefix has .mask() |
| Generation-tagged updates | Medium-High | Not for v1 |
| Conntrack integration | High | Not for v1 |

A minimal tc-flower backend (same scope as acl-rte-flow — exact and
prefix matches, drop/forward/jump fates) is **low effort**.  The
bindings are substantially more complete than rte_flow's, with native
range support as a bonus.

## Open questions

1. **Rekon vs direct netlink for the compiler output.**  The compiler
   could produce `FilterSpec` (rekon types) or raw `TcMessage`
   (netlink types).  Rekon adds lifecycle management but couples to
   the interface-manager.  For v1, producing `Vec<TcFilterFlowerOption>`
   + `Vec<TcAction>` is sufficient — the caller wires them into
   whatever lifecycle framework they use.

2. **Shared blocks vs per-interface chains.**  Hardware offload via
   tc-flower works best with shared blocks (one set of rules for all
   ports on the same ASIC).  The `Block` abstraction exists in the
   tc module.  The compiler should target blocks when available.

3. **Hardware offload flags.**  tc-flower supports `TCA_FLOWER_FLAGS`
   with `TCA_CLS_FLAGS_SKIP_SW` (hardware only) and
   `TCA_CLS_FLAGS_SKIP_HW` (software only).  The cascade compiler
   should use these to control where rules execute — analogous to
   the hardware/software assignment in `CompilationPlan`.
