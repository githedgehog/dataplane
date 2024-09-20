# Things I could have done better the last time I built something like this:

## In terms of hardware

1. **CABLE MANAGEMENT!** This was a much more serious problem than I thought it would be at the time.
    1. DAC cables are **not a great idea**™
    2. Two network cards per host didn't work out well!
    3. Rear facing I/O (power is fine on the back, but network and management should be on the front).
2. Two CPU socket hosts. **Just don't**™
3. Too much dram memory. We never used anywhere near the amount we had.
4. Too few nodes with too many cores each (this was more minor).

## In terms of software

1. **We didn't let Linux do it.**
    * One of the very few things I can promise you is that you don't have the time to reimplement Linux's network stack.
    * Our first pass fundamentally failed to deal with control plane realities: ARP resolution and ICMP neighbor discovery were by far the biggest culprits.
2. We didn't use the hardware enough
    * We were preoccupied with making our solution portable to the point that we wasted effective answers.
3. Telemetry was an afterthought
   * Nobody is buying a gateway they can't monitor.
   * You need this for debugging anyway.
4. We never really got rate limiting right
   * CX5 was not enough for our needs.  We should have jumped to CX6-DX or better.
5. We let Kubernetes boss us around.
   * Don't let Kubernetes boss you around!
