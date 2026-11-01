# vni-limit

Rate limit VXLAN traffic per VNI, and optionally per inner destination prefix, in the NIC, in front of a dataplane
that uses the kernel driver.

The kernel driver reads its ports with `AF_PACKET` sockets, which see every frame before tc or netfilter ingress can
drop it, so a limit in the kernel comes too late.
`vni-limit` puts the limits in the NIC instead: it opens each port's DPDK side in isolated mode, so the kernel keeps
every packet it does not ask for, and installs hardware rules that meter the configured traffic, return what conforms
to the kernel, and drop the rest.

## Requirements

- An NVIDIA/Mellanox NIC with hardware steering (`dv_flow_en=2`): ConnectX-7 or BlueField-3; tested on a BlueField-3.
- The `mlx5_ib` and `ib_uverbs` kernel modules loaded (`/dev/infiniband/uverbs*` present).
- Root (running with fewer privileges is untested).
- No hugepages: DPDK uses ordinary memory unless `--hugepages` is given.

## Running

```sh
vni-limit --config limits.yaml --pci 0000:3b:00.0 &
vni-limit --config limits.yaml --pci 0000:3b:00.1 &
```

`--pci` names a port by PCI address (`ethtool -i <interface>` shows it).
Run one process per port: with two ports in one process, rule tables on the first port fail to create once the second is
configured (mlx5, not yet understood).
Each port enforces every limit on its own, so traffic spread over two uplinks can pass at twice the configured rate.

`--check` validates the configuration and prints the limits without touching a NIC.

The limits last as long as the process.
It removes its rules on `SIGINT` or `SIGTERM`; if it dies, the NIC drops its rules and traffic is no longer limited.
Run it under a supervisor that restarts it, after the dataplane has configured the interfaces.

## Configuration

```yaml
vxlan_port: 4789            # optional, the default
limits:
  - vni: 100
    rate_bps: 100000000     # bits per second
  - vni: 100
    inner_dst: 10.1.0.0/24  # optional: only traffic to this inner destination
    rate_bps: 20000000
    burst_bytes: 262144     # optional, defaults to 10 ms at the rate (at least 32 KiB)
```

- A packet is limited by the most specific limit that matches it, and only by that one: above, traffic of VNI 100 to
  `10.1.0.0/24` counts against the 20 Mbit/s limit and not the 100 Mbit/s one.
- Rates count outer IP bytes, including the VXLAN encapsulation, for both IPv4 and IPv6 underlays.
- The hardware stays within about half a percent of the configured rate.

## Checking

Every ten seconds (`--stats-interval`), and once more on exit, the process prints a table per port on standard output;
`--stats-file <path>` also writes each one to a file, replaced whole, so `watch cat <path>` follows it.
Logs go to standard error.

```text
port 0000:02:00.0, last 5.0 s
traffic                              limit Mb/s   passed pps  passed Mb/s  dropped pps dropped Mb/s  dropped total   passed total
vni 100 to 198.18.0.0/24                 20.000        26062       20.015        13914       10.686          85765         161599
vni 100                                   5.000         6515        5.004        33460       25.697         206707          40656
all VXLAN                                             159902      122.805            -            -              -         989453
VXLAN no limit matched                                 39976       30.701            -            -              -         247363
```

- Rates are over the last interval; totals are since the process installed its rules, and restart with it.
- Mbit/s count outer IP bytes, as the limits do.
- `all VXLAN` is every VXLAN packet the port received; `VXLAN no limit matched` went to the kernel untouched.

## Limitations

- A flood beyond what the NIC can classify (about 100 Mpps of small frames on a BlueField-3) makes the NIC push back
  with pause frames, which slows the whole link: the limits protect the host, not the link.
- The process sets the DPDK port's MTU to the kernel interface's MTU when it starts, because mlx5 applies the DPDK MTU
  to the kernel interface. Start it after the dataplane has set the MTU.
