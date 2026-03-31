# ACL plan

## Step 0 -- clarify scope and refine plan

## High level goals

We need a general purpose ACL / match-action table construct for our dataplane.

This library must present itself to downstream crates (e.g. routing, nat) as a coherent abstraction.
The "mental model" for the end user of this library should be an ordered list of "matches", each of which is associated with one or more "actions".
The matches should be flexibly (ideally generic) constructs in one of three basic flavors:

1. exact match
2. LPM match
3. range match

The end user should be able to express a subset of packet fields (or metadata fields from outside of the parsed packet header) on which to match.
Ideally this would be a compile time choice, but runtime programming is acceptable if that is impractical.
More, the user should be able to express disjoint possibilities; e.g. a match which covers ipv4 and ipv6 based on the ethertype.
I expect determining the means by which the user expresses this matching pattern to be a significant portion of the required work for this phase.

To the extent practical, the actions associated with these matches should be decoupled from the match table.
For example, it would (ideally) be possible to use the same action (e.g. a counter) on more than one match in the table.

Additionally, the "backend" of the ACL / match-action construct _must be generic_.
Ideally we would be able to adjust or extend the actual implementation of the match-action table construct without the end user needing to re-write any significant volume of code.
More, not all "backends" are expected to be sufficient to express the set of possible behaviors.
Thus, the match-action backend's need to "cascade" or fall back to a more flexible implementation when the preferred implementation is unable to address the concern.
For example, not all network cards support the full range of options provided by the tc-flower or DPDK's rte_flow constructs.
In these cases the system should gracefully degrade to a generic software implementation.
Ideally you would be able to "cascade" or "degrade" (or some other term to be decided) through any sequence of implementations, alghough 2 is the minimum which can be accepted for the first pass at implementation.
Even if we only have one actual backend (the dpdk ACL library), it is essential to prove that the cascade mechanic functions or we risk pushing the wrong abstraction to downstream engineers.

Some (very rough and possibly impractical) draft ideas for expressing matches follow.

### Theory 1 - proc macro driven match defn

```rust
// Imagine a proc macro which decorates a rust structure
#[match]
struct MyMatch {
    #[exact]
    vni: Vni,
    #[exact]
    ethtype: Ethtype,
    #[lpm]
    src_ip: Ipv4Prefix,
    #[lpm]
    dst_ip: Ipv4Prefix,
    #[exact]
    proto: IpNumber,
    #[range]
    dst_port: Range<TcpPort>
}
```

The immediate limit I see in this proposal is that it gives both too much and too little power to the user.
The base reading suggests that you could set Ethtype to anything and still match on Ipv4 (which is confusing).
Similar for IpNumber vs Tcp.

More, the DPDK acl library actually requires us to copy packet header values into a flat array with alignment constraints.
Copy of the packet header into the `MyMatch` structure only to copy it back into a flat array is wasteful on the hot path.
This may not be a huge issue (we could define an API which skips that step).
It is just something the user would need to understand.

Additionally, a likely performance goal is to minimize the number of acttually required lookups on the hot path.
The DPDK ACL library allows disperate match criteria to be expressed in a table.
So we may want something more along the lines of a "union" of this type of construction.

```rust
// I expect this pattern would require additional metadata to be viable
#[match]
enum MyUnionMatch {
    Ipv4(MyMatch1),
    Ipv6(MyMatch2),
}

#[match]
struct MyMatch1 {
    #[exact]
    vni: Vni,
    #[exact]
    ethtype: Ethtype,
    #[lpm]
    src_ip: Ipv4Prefix,
    #[lpm]
    dst_ip: Ipv4Prefix,
    #[exact]
    proto: IpNumber,
    #[range]
    dst_port: Range<TcpPort>
}

#[match]
struct MyMatch2 {
    #[exact]
    vni: Vni,
    #[exact]
    ethtype: Ethtype,
    #[lpm]
    src_ip: Ipv6Prefix,
    #[lpm]
    dst_ip: Ipv6Prefix,
    #[exact]
    proto: IpNumber,
    #[range]
    dst_port: Range<TcpPort>
}

```

### Theory 2 - typestate driven defn

Craft some kind of type safe builder pattern

The `net` crate in this workspace actually has (work in progress) typestate driven packet builders.

It may well be completely practical to recycle some of that logic to make "symmetrical" typestate driven match builders.
This has significant upshot in that it would (in theory) reuse a lot of carefully tested logic.
It would also (to a large extent) eliminate some of the cognative load on the library user; they are already familiar with `net`.

The most immediate downside is that I'm less confident in the viability of expressing the matches at compile time in the same way as the proc-macro driven approach.
Perhaps the combination of `const fn` and generics can do it.
That said, bounding the table defn to compile time is less important than type safety (which is functionally mandatory).

One other downside is that it isn't immediately clear how metadata matching (such as `Vni` in the previous example) would fit into this pattern.

One other downside is that `net` is designed explicitly to reject nonsense packets (e.g. packets with multicast source addresses).
But matching on illegal frames actually is quite useful, especially to reject those frames in hardware.
This would require extra care.

One upside of this kind of abstraction is that (potentially) improvements in `net` would propagate to improvements in the ACL / match-action library.
