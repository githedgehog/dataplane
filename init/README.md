# dataplane-init

Init prepares the configured NICs, separates the datapath and control plane into network namespaces,
and supervises the gateway processes. Driver and interface selection must be explicit.

DPDK devices that require [vfio-pci] are rebound to it. Bifurcated devices, including [mlx5], retain their kernel
driver. Init does not restore driver bindings on exit. Dropping elevated privileges remains future work.

The dataplane refuses to start without the descriptors init passes it, so init is the container's entrypoint and
takes the dataplane's command line unchanged.

## Hugepages

The DPDK driver requires hugepages. Init checks the process's hugetlb cgroup allowance, including current usage
and visible ancestor limits, before preparing the pools. It tries 1 GiB pages, then 2 MiB pages; startup fails
if neither can supply the full 4 GiB requirement per NIC NUMA node. Ordinary 4 KiB pages are not a fallback.

Init leaves a sufficient pool alone. Otherwise it requests the shortfall and checks the free count again;
unreadable controls, a refused write, or insufficient pages reject that page size. Cgroup limits are never
changed. `DATAPLANE_HUGEPAGE_RESERVE=off` disables pool growth but still requires existing pages and quota.

These checks do not allocate pages. EAL performs the allocation and startup fails if it cannot obtain them.

NIC NUMA affinity must agree with the hardware scan. Unknown affinity (`-1`) is accepted only when the scan
identifies a single NUMA node; its OS node ID selects the pool. Unknown affinity on a multi-node system,
unreadable or invalid affinity, and missing topology are fatal before pool growth or device rebinding.

## Network namespaces

Init moves the selected interfaces into a datapath namespace held only by descriptors. When the gateway stops, the
kernel destroys it and returns physical devices to the host; virtual interfaces (veth, VLAN and the like) are
destroyed with it instead. Both the DPDK and kernel drivers use a control-plane bridge: one tap per configured
interface, carrying the configured name in the control namespace. The drivers exchange control traffic with these
taps.

When `--supervise-frr` is set, init creates a private control namespace. Otherwise the control plane stays
in the caller's namespace so it can share the taps with external FRR. `--control-netns` selects an existing
control namespace.

```text
init:       prepare NICs -> move NICs -> enter control namespace -> start children
dataplane:  main + management runtime     control namespace (taps, netlink, FRR IPC)
            packet-processing threads     datapath namespace
            host runtime                  original namespace (Kubernetes, metrics, Pyroscope)
FRR:                                      control namespace
```

Move NICs before leaving their original namespace so their devlink instances remain reachable. Init then enters
the control namespace, mounts a matching sysfs, and brings up loopback. Children inherit that placement.
The dataplane receives validated descriptors for its datapath namespace and the original namespace, and runs a
separate host runtime only when the original namespace is not its own.

For externally managed FRR in an existing namespace:

```console
$ ip netns add gwctl
$ ip netns exec gwctl <start frr>
$ dataplane-init --driver dpdk --interface dp0=pci@0000:03:00.0 \
      --control-netns /run/netns/gwctl --config-dir /dpconf
```

Taps are nonpersistent and disappear when their last descriptor closes. This prevents stale taps from taking
names needed by physical devices returning to the host namespace.

## Supervision

Init supervises the dataplane and, with `--supervise-frr`, foreground `watchfrr` and `frr-agent`.
Any startup failure or unexpected exit of these children is fatal. Init stops the remaining children and exits
with failure, even if the child returned zero, so Kubernetes can restart the gateway. SIGTERM and SIGINT request
a normal shutdown, including during startup.

FRR manages its individual daemons through `watchfrr`, preserving its startup scripts and configuration pass.
Init supervises `watchfrr` itself and reaps orphans it inherits as PID 1.

Before spawning children, init removes the old dataplane control-plane socket and, when it supervises FRR,
FRR's stale sockets and status files plus the configured agent socket. Init requires exclusive ownership of
these endpoints during startup. Unexpected file types and cleanup failures are fatal.

With supervised FRR, startup waits for each new Unix socket in order: dataplane control plane, zebra VTY, then
FRR agent. This confirms that each endpoint was bound; it does not establish full service health.

## Current limitations

- Physical link changes are not propagated to the taps, so FRR can see a tap as up after its DPDK port goes down.
- A host-namespace `prometheus-frr-exporter` cannot reach FRR in a private control namespace; metrics need a proxy
  or an exporter in that namespace.
- Fresh control namespaces discard old zebra nexthops. Explicitly reused namespaces and FRR daemon restarts
  within a surviving namespace do not receive that cleanup.

## Privileges

Init needs elevated privileges to configure devices and namespaces. Its sysfs writes must address the intended
device; sysfs contains symlinks, so path validation matters.

[vfio-pci]: https://docs.kernel.org/driver-api/vfio.html
[mlx5]: https://docs.kernel.org/networking/device_drivers/ethernet/mellanox/mlx5/index.html
