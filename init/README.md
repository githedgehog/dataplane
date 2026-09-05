# dataplane-init

This program is responsible for initializing the dataplane.

The primary steps of this program are to:

1. Drive the NIC into the configuration needed by DPDK to use the NIC
2. Put the packet path and the control plane into network namespaces of their own
3. (TODO) Drop some hazardous privileges (especially [`CAP_SYS_ADMIN`])
4. Start the processes a gateway is made of, and supervise them until one stops

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

With `--driver dpdk --datapath-netns`, this program leaves the dataplane spanning **two** network namespaces, and
neither of them is the host's:

```text
init  (host ns)   prepare NICs -> create datapath ns -> devlink reload NICs into it
                  -> open/create control ns -> lo up -> setns(control) -> start and supervise
dataplane         main + mgmt runtime            : control ns  (taps, rtnetlink, FRR IPC, BMP)
                  dpdk-datapath thread           : datapath ns (setns + fresh sysfs)
FRR               control ns
```

The order is not a preference. The devices are moved with a **devlink reload**, and a PCI device's devlink instance
belongs to the namespace the device is in, which at that point is the host's; entering the control namespace first
would put this process somewhere those instances are not. Conversely a child inherits the namespaces of the thread
that forked it, so `setns` on the main thread has to happen before anything is started, which puts it last.

### Why the control plane needs a namespace at all

In DPDK mode the kernel has no NIC: on a bifurcated driver the netdev went into the datapath namespace, and on
[vfio-pci] there is no netdev to begin with. So the kernel's end of every port is a **tap**, created by the
dataplane, and every control frame — BGP, BFD, ARP, LLDP — is carried across by the dataplane between that tap and
the port.

Those taps are named **exactly** the configured interface name, because that is the name FRR's configuration, the
routing tables and the ACLs all use. The physical device wants that name too, and in the host's namespace the two
collide: a leftover tap on `dp0` makes udev's rename of the returning physical device fail, which strands the real
device under a name nothing is looking for. A private namespace removes the collision, because the physical device
is never in it.

`lo` is brought up in the new namespace before anything is started. FRR binds its vty to `127.0.0.1` and the
dataplane's `frr-agent` connects to it there; a fresh namespace's loopback is down, and the resulting failure looks
like an agent that will not connect rather than an interface that is down.

Nothing holds the control namespace open by descriptor. A namespace with a process in it does not go away, and this
process is in it.

### `--control-netns`

Given a path, this program enters that namespace instead of making one. That is the lever for running FRR by hand:

```console
$ ip netns add gwctl
$ ip netns exec gwctl <start frr>
$ dataplane-init --driver dpdk --interface dp0=pci@0000:03:00.0 \
      --datapath-netns --control-netns /run/netns/gwctl --config-dir /dpconf
```

It requires `--datapath-netns`, and is rejected without it: taps named after the configured interfaces can only exist
somewhere the physical devices are not. The kernel driver never gets a control namespace at all — its `AF_PACKET`
sockets are opened on the real interfaces.

## Supervision

A gateway is not one program. The dataplane forwards packets, FRR decides where they should go, and `frr-agent`
carries configuration between them. This process starts them and stays as their parent, which is what `exec`ing the
dataplane made impossible: namespaces are inherited at `fork`, so once this process had been replaced there was
nobody left to fork a second one from.

Every supervised process is **fatal**. When one exits, for any reason and with any status, the rest are brought down
and this process exits with a status derived from whichever went first. Nothing is restarted in place. That is a
stronger coupling than three containers, and it is deliberate: a dataplane forwarding on a FIB whose author has died
is its own kind of wrong, and the orchestrator above knows better than we do whether restarting beats continuing.

### `--supervise-frr`

Off by default, because FRR still ships as a container of its own. Given it, this program also starts:

```text
watchfrr <daemons from /etc/frr/daemons>    # which starts zebra, bgpd, ...
frr-agent --sock-path <--frr-agent-path>
```

which is what `/libexec/frr/docker-start` used to do. Two things that script did are gone. The `wait -n` is replaced
by the shared fate above. The sweep of stale zebra nexthops is unnecessary, because it was cleanup after a _previous_
container in a namespace that outlived it — and the control namespace is now created per start.

Startup is ordered rather than raced: the dataplane is waited for until its control-plane socket exists, because
zebra's `hh_dplane` module connects to it as it loads and a zebra that starts first finds nothing there. `frr-agent`
is started last and waited for at its own socket.

`watchfrr` rather than the daemons individually, which was tried and does not reproduce FRR faithfully — enough of
the startup lives in `watchfrr.sh` and `frrcommon.sh` (per-daemon options, config file creation, the `vtysh -b` pass)
that launching the binaries by hand produced an FRR which never applied the interface address it was given.

### What this costs, for now

- `prometheus-frr-exporter` cannot reach FRR from the host's namespace any more. It needs a proxy through the
  dataplane's metrics endpoint.
- Kubernetes mode is unavailable: the k8s client and the metrics endpoint are outbound from the host's namespace, and
  they have not been split onto a runtime of their own yet. This configuration is `--config-dir` only.
- Physical link state does not reach FRR. The DPDK driver knows it; nothing yet propagates it onto the tap, so a port
  going down looks to FRR like a link that is still up.

## Error Handling Strategy

As a short-lived program which is only run once per gateway initialization, this program has significantly different
error handling requirements from the other software in this workspace.

Essentially, it will either succeed or fail, and if it fails it will likely require outside intervention to recover.
There is little we can or should attempt to do in terms of sophisticated error handling beyond logging clear error
messages.

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
