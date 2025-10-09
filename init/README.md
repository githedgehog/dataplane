# dataplane-init

This program is responsible for initializing the dataplane.

The primary steps of this program are to:

1. Drive the NIC into the configuration needed by DPDK to use the NIC
2. (TODO) Drop some hazardous privileges (especially [`CAP_SYS_ADMIN`])
3. (TODO) `exec` the dataplane process on success

For most network cards, this configuration step involves unbinding the NIC from the kernel driver and re-binding it to
the [vfio-pci] driver.

**Note**: Not all NICs should be bound to [vfio-pci].
Some network cards use the so-called bifurcated driver and must remain bound to the kernel driver.
In particular, all network cards which use the mlx5 driver must remain bound to the [mlx5] kernel driver.

**Warning**: This program is _not_ responsible for full life cycle management of the NIC.
In particular, it makes no attempt to rebind the NIC back to the kernel driver.
Thus, expect this program to make network cards disappear from the perspective of tooling like [iproute2] and [ethtool].

Only a very limited set of network cards are currently supported, although this set can easily be expanded over time.

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
