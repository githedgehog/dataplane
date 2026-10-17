# dataplane-init

This program is responsible for initializing the dataplane.

The primary steps of this program are to:

1. Drive the NIC into the configuration needed by DPDK to use the NIC
2. Put the packet path and the control plane into network namespaces of their own
3. (TODO) Drop some hazardous privileges (especially [`CAP_SYS_ADMIN`])
4. `exec` the dataplane process, passing it the sealed configuration and the namespace descriptor

The dataplane refuses to start without this handoff, so this program is the container's entrypoint and takes the
dataplane's command line unchanged.

The datapath namespace is new and owned only by its descriptor.
With the DPDK driver, bifurcated devices (mlx5) are moved into it; with the kernel driver, the configured interfaces
are. When the dataplane exits the kernel destroys the namespace and returns physical devices to the host; virtual
interfaces (veth, VLAN and the like) are destroyed with it instead.

For most network cards, this configuration step involves unbinding the NIC from the kernel driver and re-binding it to
the [vfio-pci] driver.

**Note**: Not all NICs should be bound to [vfio-pci].
Some network cards use the so-called bifurcated driver and must remain bound to the kernel driver.
In particular, all network cards which use the mlx5 driver must remain bound to the [mlx5] kernel driver.

**Warning**: This program is _not_ responsible for full life cycle management of the NIC.
In particular, it makes no attempt to rebind the NIC back to the kernel driver.
Thus, expect this program to make network cards disappear from the perspective of tooling like [iproute2] and [ethtool].

Only a very limited set of network cards are currently supported, although this set can easily be expanded over time.

## Network namespaces

Init moves the selected interfaces into a datapath namespace held only by descriptors. Both the DPDK and kernel drivers use a control-plane bridge: one tap per configured
interface, carrying the configured name in the control namespace. The drivers exchange control traffic with these
taps.

Init creates a private control namespace unless `--control-netns` selects an existing one.

```text
init  (host ns)   prepare NICs -> create datapath ns -> move NICs into it
                  -> open/create control ns -> lo up -> setns(control) -> exec dataplane
dataplane         main + mgmt runtime            : control ns  (taps, rtnetlink, FRR IPC, BMP)
                  datapath thread                : datapath ns (setns + fresh sysfs)
FRR               control ns
```

The order is not a preference. DPDK devices are moved with a **devlink reload**, and a PCI device's devlink instance
belongs to the namespace the device is in, which at that point is the host's; entering the control namespace first
would put this process somewhere those instances are not. Conversely `setns` on the main thread is what `exec`
carries over, so it has to be last.

### Why the control plane needs a namespace at all

The kernel in the control namespace has no NIC: the netdevs went into the datapath namespace, and on [vfio-pci]
there is no netdev to begin with. So the kernel's end of every port is a **tap**, created by the
dataplane, and every control frame — BGP, BFD, ARP, LLDP — is carried across by the dataplane between that tap and
the port.

Those taps are named **exactly** the configured interface name, because that is the name FRR's configuration, the
routing tables and the ACLs all use. The physical device wants that name too, and in the host's namespace the two
collide: a leftover tap on `dp0` makes udev's rename of the returning physical device fail, which strands the real
device under a name nothing is looking for. A private namespace removes the collision, because the physical device
is never in it.

`lo` is brought up in the new namespace before `exec`. FRR binds its vty to `127.0.0.1` and the dataplane's
`frr-agent` connects to it there; a fresh namespace's loopback is down, and the resulting failure looks like an agent
that will not connect rather than an interface that is down.

Nothing holds the control namespace open by descriptor. A namespace with a process in it does not go away, and after
`exec` the dataplane is that process.

For externally managed FRR in an existing namespace:

```console
$ ip netns add gwctl
$ ip netns exec gwctl <start frr>
$ dataplane-init --driver dpdk --interface dp0=pci@0000:03:00.0 \
      --control-netns /run/netns/gwctl --config-dir /dpconf
```

Taps are nonpersistent and disappear when their last descriptor closes. This prevents stale taps from taking
names needed by physical devices returning to the host namespace.

## Current limitations

- Physical link changes are not propagated to the taps, so FRR can see a tap as up after its DPDK port goes down.
- A host-namespace `prometheus-frr-exporter` cannot reach FRR in a private control namespace; metrics need a proxy
  or an exporter in that namespace.
- Fresh control namespaces discard old zebra nexthops. Explicitly reused namespaces and FRR daemon restarts
  within a surviving namespace do not receive that cleanup.

## Privileges

This program is, by necessity, run with elevated privileges.
As such, we need to take special caution when writing to files.

Because [sysfs] is basically a maze of symlinks, it is important to be careful when manipulating paths under [sysfs].
Mistakes can lead you to write data in highly unexpected places, with totally unknown consequences.
Some care has been taken in the design of the types used here to discourage programmer errors which might lead to
unintended writes by a privileged process.

<!-- links -->
[iproute2]: https://www.kernel.org/pub/linux/utils/net/iproute2/
[ethtool]: https://www.kernel.org/pub/linux/utils/net/ethtool/
[sysfs]: https://www.kernel.org/doc/Documentation/filesystems/sysfs.txt
[vfio-pci]: https://docs.kernel.org/driver-api/vfio.html
[mlx5]: https://docs.kernel.org/networking/device_drivers/ethernet/mellanox/mlx5/index.html
[`CAP_SYS_ADMIN`]: <https://www.man7.org/linux/man-pages/man7/capabilities.7.html#:~:text=user_namespaces(7)).-,CAP_SYS_ADMIN,-Note%3A%20this%20capability>
