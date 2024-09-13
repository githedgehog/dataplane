# Hardware selection

## Options:

### The 2x "big box solution"

- Processor: 32 core, Genoa X (9384X 3.10GHz, 768MB L3 cache) (320W)
- Memory: 16GB x 12 DDR5 (4800MT/s)
- NIC: 2x cards per box @ 2x100Gbps ConnectX-7 (??? which SKU ???, MCX755106AS-HEAT ???)

Two of these boxes take:

- 4U of space
- The current quote is
    - $12,904.23/box,
    - **$25,810** total _before tax and shipping_,
    - $28,273.54 after tax and shipping

### The 4x-8x "small box solution"

- Processor: AMD EPYC 4584PX Processor 16-Core 4.20GHz 128MB Cache (120W)
- Memory: 16GB x 4 DDR5 (4800MT/s)
- NIC: 1x cards per blade @ 2x100Gbps ConnectX-7 (MCX755106AS-HEAT) (ideally would add crypto offload but not quoted here)

#### The 4x "small box solution" takes:

- 3U of space
- The current quote is
    - $4,497.89 / blade (amortized over 4 blades),
    - **$17,991** total _before tax and shipping_,
    - Taxes TBD

#### The 5x "small box solution" takes:

- 3U of space
- The current quote is
    - $4,147.23 / blade (amortized over 5 blades),
    - **$20,736** total _before tax and shipping_,
    - Taxes TBD

#### The 8x "small box solution" takes:

- 3U of space
- The current quote is
    - $3,621.25 / blade (amortized over 8 blades),
    - **$28,970** total _before tax and shipping_,
    - Taxes TBD

**Both options are quoted as shipping in ~1 week**

## Reasons to pick the big box option:

You think the solution will

- will benefit from a _very_ large L3 cache (pretty likely)
- require a lot of cores (entirely possible)
- require a lot of PCIe lanes (unlikely)

**I think these are reasonable assumptions if you expect that the solution we reach is implemented mostly in software.**

# Reasons to pick the small box option:

You think the solution will

- Benefit from a lot of SRAM and/or TCAM in the NIC
- Need to scale horizontally
- Require only one NIC per blade
- Will not need a massive L3 cache

**I think these are reasonable assumptions if you expect that the solution we reach uses a lot of hardware offloads**
(software processing would still work obviously, but the L3 cache is decidedly smaller)
