# Dataplane + vlab

## 1. Host Hugepage Backing (VM memory)

This controls how QEMU allocates the VM's RAM on the host independent of what the guest kernel does.

| Host Page Size       | QEMU `-object` flag                                                                     |
| -------------------- | --------------------------------------------------------------------------------------- |
| **Standard (4 KiB)** | `memory-backend-memfd,id=mem0,size=$MEMORY,share=on`                                    |
| **Huge2M (2 MiB)**   | `memory-backend-file,id=mem0,size=$MEMORY,mem-path=/dev/hugepages,share=on,prealloc=on` |
| **Huge1G (1 GiB)**   | `memory-backend-file,id=mem0,size=$MEMORY,mem-path=/dev/hugepages,share=on,prealloc=on` |

## 2. Guest Kernel Hugepage Reservation

| Config                      | Kernel cmdline fragment                            |
| --------------------------- | -------------------------------------------------- |
| **None**                    | _(empty — DPDK must use `--no-huge --in-memory`)_  |
| **Allocate { 1GiB, `$N` }** | `default_hugepagesz=1G hugepagesz=1G hugepages=$N` |
| **Allocate { 2MiB, `$N` }** | `default_hugepagesz=2M hugepagesz=2M hugepages=$N` |

Host backing and guest reservation are orthogonal.
You can back the VM with 4k host hugepages while the guest reserves 2MiB hugepages (or even 1GiB).

## 3. Virtual IOMMU

It affects both machine type and iommu device args:

**Machine type**:

| iommu   | Machine arg                                                                                    |
| ------- | ---------------------------------------------------------------------------------------------- |
| virtual | `-machine q35,accel=kvm,kernel-irqchip=split` (split irqchip required for interrupt remapping) |
| none    | `-machine q35,accel=kvm`                                                                       |

**IOMMU device**:

| iommu   | device arg                                                        |
| ------- | ----------------------------------------------------------------- |
| virtual | `-device intel-iommu,intremap=on,device-iotlb=on,caching-mode=on` |
| none    | N/A                                                               |

`caching-mode=on` is specifically needed for vhost-user devices (e.g. virtiofsd) that perform DMA from a separate
userspace process. It might not strictly be needed for vlab but it shouldn't hurt anything either.

**Kernel cmdline**:

| iommu   | add to cmdline                         |
| ------- | -------------------------------------- |
| virtual | `iommu=on intel_iommu=on amd_iommu=on` |
| none    | `vfio.enable_unsafe_noiommu_mode=1`    |

**Per-device impact** — this is where PCIe topology matters:

- **Virtio devices** (e.g. virtio-net) support `iommu_platform=on,ats=on` flags, which opt them into explicit IOMMU-aware DMA.
- **Emulated devices** (e1000, e1000e) do **not** support `iommu_platform`/`ats`; However, their DMA is still remapped because the Intel IOMMU covers the entire PCI topology.

## 4. Network Card Type

| NIC Model     | QEMU `-device`                    | IOMMU flags                                    | Backend restriction      |
| ------------- | --------------------------------- | ---------------------------------------------- | ------------------------ |
| **VirtioNet** | `virtio-net-pci-non-transitional` | `iommu_platform=on,ats=on` when vIOMMU enabled | QEMU or cloud-hypervisor |
| **E1000**     | `e1000`                           | None (no virtio IOMMU support)                 | QEMU only                |
| **E1000E**    | `e1000e`                          | None (no virtio IOMMU support)                 | QEMU only                |

> [!NOTE]
> virtio-net uses the "non-transitional" (virtio 1.0+) variant and can explicitly cooperate with the IOMMU via ATS
> (Address Translation Services). The emulated Intel NICs rely on the IOMMU intercepting their DMA at the PCI bus level;
> no device-side cooperation.

## Example qemu launch command

This is very similar to the launch command used by `n-vm` to validate DPDK tx/rx.

This is suitable for vlab where no hugepages are available and performance is of no concern.

- virtual iommu
- e1000 nics
- 2m hugepages in the vm
- no hugepages on the host

```sh
qemu-system-x86_64 \
  -enable-kvm \
  -machine q35,accel=kvm,kernel-irqchip=split \
  -cpu host \
  -smp 6,sockets=1,dies=3,cores=1,threads=2 \
  -m 8192M \
  -object memory-backend-memfd,id=mem0,size=8192M,share=on \
  -numa node,memdev=mem0 \
  -device intel-iommu,intremap=on,device-iotlb=on,caching-mode=on \
  -kernel /bzImage \
  -append "ro rootfstype=virtiofs root=root iommu=on intel_iommu=on amd_iommu=on default_hugepagesz=2M hugepagesz=2M hugepages=64 $whatever" \
  -chardev socket,id=virtiofs0,path=/vm/virtiofsd.sock \
  -device vhost-user-fs-pci,queue-size=1024,chardev=virtiofs0,tag=root \
  -device vhost-vsock-pci-non-transitional,guest-cid=123456,iommu_platform=on,ats=on \
  -netdev tap,id=nd-mgmt,ifname=mgmt,script=no,downscript=no \
  -device e1000,netdev=nd-mgmt,mac=02:DE:AD:BE:EF:01 \
  -netdev tap,id=nd-fabric1,ifname=fabric1,script=no,downscript=no \
  -device e1000,netdev=nd-fabric1,mac=02:CA:FE:BA:BE:01 \
  -netdev tap,id=nd-fabric2,ifname=fabric2,script=no,downscript=no \
  -device e1000,netdev=nd-fabric2,mac=02:CA:FE:BA:BE:02 \
  -serial unix:/vm/kernel.sock,server=on,wait=off \
  -chardev socket,id=qmp0,path=/vm/hypervisor.sock,server=on,wait=off \
  -mon chardev=qmp0,mode=control \
  -display none \
  -no-reboot \
  -no-shutdown \
  -device pvpanic
```

Of special import here is

- `-machine q35,accel=kvm,kernel-irqchip=split`
- `-device intel-iommu,intremap=on,device-iotlb=on,caching-mode=on`
- the append includes `"iommu=on intel_iommu=on amd_iommu=on default_hugepagesz=2M hugepagesz=2M hugepages=64"`

## If you want more plausible performance

```sh
qemu-system-x86_64 \
  -enable-kvm \
  -machine q35,accel=kvm \
  -cpu host \
  -smp 6,sockets=1,dies=3,cores=1,threads=2 \
  -m 16384M \
  -object memory-backend-file,id=mem0,size=16384M,mem-path=/dev/hugepages,share=on,prealloc=on \
  -numa node,memdev=mem0 \
  -kernel /bzImage \
  -append "vfio.enable_unsafe_noiommu_mode=1 ro rootfstype=virtiofs root=root default_hugepagesz=1G hugepagesz=1G hugepages=8 $whatever" \
  -chardev socket,id=virtiofs0,path=/vm/virtiofsd.sock \
  -device vhost-user-fs-pci,queue-size=1024,chardev=virtiofs0,tag=root \
  -device vhost-vsock-pci-non-transitional,guest-cid=123456 \
  -netdev tap,id=nd-mgmt,ifname=mgmt,script=no,downscript=no \
  -device virtio-net-pci-non-transitional,netdev=nd-mgmt,mac=02:DE:AD:BE:EF:01 \
  -netdev tap,id=nd-fabric1,ifname=fabric1,script=no,downscript=no \
  -device virtio-net-pci-non-transitional,netdev=nd-fabric1,mac=02:CA:FE:BA:BE:01 \
  -netdev tap,id=nd-fabric2,ifname=fabric2,script=no,downscript=no \
  -device virtio-net-pci-non-transitional,netdev=nd-fabric2,mac=02:CA:FE:BA:BE:02 \
  -serial unix:/vm/kernel.sock,server=on,wait=off \
  -chardev socket,id=qmp0,path=/vm/hypervisor.sock,server=on,wait=off \
  -mon chardev=qmp0,mode=control \
  -display none \
  -no-reboot \
  -no-shutdown \
  -device pvpanic
```

Of special import here is

- `-machine q35,accel=kvm` WITHOUT `kernel-irqchip=split`
- `-object memory-backend-file,id=mem0,size=16384M,mem-path=/dev/hugepages,share=on,prealloc=on` \
- we did NOT pass in a virtual iommu device
- the append includes `"vfio.enable_unsafe_noiommu_mode=1 default_hugepagesz=1G hugepagesz=1G hugepages=8"`
- we aren't using hopelessly antiquated e1000 virtual nics.
- yes, this configuration really really does need physical huge pages pre-allocated on the physical host.

My understanding is that we would do PCIe passthrough of a ConnectX-7 port, which should be fine
**so long as you DON'T need firmware level control of the NIC.**
