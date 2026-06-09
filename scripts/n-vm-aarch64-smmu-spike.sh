#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# EXPERIMENTAL validation spike for aarch64 virtual IOMMU (move 4).
#
# Answers, empirically and in isolation, whether a virtual IOMMU works for
# an aarch64 guest under TCG before any of it is wired into the n-vm
# backend:
#
#   1. does `qemu-system-aarch64 -M virt,iommu=smmuv3` present an SMMUv3
#      that the guest kernel's CONFIG_ARM_SMMU_V3 driver probes?
#   2. does it populate /sys/kernel/iommu_groups (so VFIO passthrough,
#      which DPDK needs, would have groups to bind)?
#   3. does a virtio-net-pci with `iommu_platform=on` actually DMA through
#      the SMMU (its driver binds and the device lands in an IOMMU group)?
#
# Requires a kernel built WITH CONFIG_ARM_SMMU_V3 (add it to
# nix/pkgs/linux/fragments/aarch64-virt.config).  Console-based: the init
# prints findings to ttyAMA0 and the kernel's own SMMU probe shows on the
# console too; no vsock, to keep the SMMU the only variable.
#
# Usage:  KERNEL=/path/Image QEMU=/path/qemu-system-aarch64 scripts/n-vm-aarch64-smmu-spike.sh

set -euo pipefail

readonly BOOT_TIMEOUT="${BOOT_TIMEOUT:-180}"
readonly BOOT_MARKER="N-VM-SMMU: boot ok"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"; [[ -n "${qemu_pid:-}" ]] && kill "${qemu_pid}" 2>/dev/null || true' EXIT
log() { printf '>>> %s\n' "$*" >&2; }

# -- Resolve kernel + emulator --------------------------------------------
if [[ -z "${KERNEL:-}" ]]; then
  log "building aarch64 guest kernel (must have CONFIG_ARM_SMMU_V3) ..."
  kdir="$(nix build -f default.nix pkgs.linux-fancy \
    --argstr platform aarch64 --argstr libc musl --no-link --print-out-paths)"
  KERNEL="${kdir}/Image"
fi
[[ -f "${KERNEL}" ]] || { log "kernel image not found: ${KERNEL}"; exit 1; }
if [[ -z "${QEMU:-}" ]]; then
  qdir="$(nix build -f default.nix pkgs.pkgsBuildHost.qemu \
    --argstr platform aarch64 --argstr libc musl --no-link --print-out-paths)"
  QEMU="${qdir}/bin/qemu-system-aarch64"
fi
[[ -x "${QEMU}" ]] || { log "qemu-system-aarch64 not found: ${QEMU}"; exit 1; }
log "kernel: ${KERNEL}"; log "qemu: ${QEMU}"

# -- Tiny init: report SMMU / IOMMU-group / NIC-binding state -------------
cat > "${workdir}/init.rs" <<'RUST'
use std::io::Write;
use std::os::raw::{c_char, c_int, c_ulong, c_void};

unsafe extern "C" {
    fn mount(src: *const c_char, tgt: *const c_char, fst: *const c_char,
        flags: c_ulong, data: *const c_void) -> c_int;
    fn reboot(cmd: c_int) -> c_int;
}
const RB_POWER_OFF: c_int = 0x4321_fedc_u32 as c_int;

fn out(msg: &str) {
    let _ = std::io::stdout().write_all(msg.as_bytes());
    let _ = std::io::stdout().flush();
}

fn list(dir: &str) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn main() {
    let r = unsafe {
        mount(b"sysfs\0".as_ptr() as *const c_char, b"/sys\0".as_ptr() as *const c_char,
              b"sysfs\0".as_ptr() as *const c_char, 0, core::ptr::null())
    };
    if r != 0 { out("N-VM-SMMU: sysfs mount FAILED\n"); }

    let base = |p: std::path::PathBuf| p.file_name().map(|f| f.to_string_lossy().into_owned());
    let link_base = |p: String| std::fs::read_link(p).ok().and_then(base);

    out(&format!("SMMU-DEVICES: {:?}\n", list("/sys/class/iommu")));
    out(&format!("IOMMU-GROUPS: {}\n", list("/sys/kernel/iommu_groups").len()));

    // Which PCI devices does the SMMU actually claim?  A device must be in
    // an IOMMU group for vfio-pci (DPDK) to bind it.
    for bdf in list("/sys/bus/pci/devices") {
        let group = link_base(format!("/sys/bus/pci/devices/{bdf}/iommu_group"))
            .unwrap_or_else(|| "<none>".into());
        let drv = link_base(format!("/sys/bus/pci/devices/{bdf}/driver"))
            .unwrap_or_else(|| "<unbound>".into());
        out(&format!("PCI: {bdf} iommu_group={group} driver={drv}\n"));
    }

    out("N-VM-SMMU: boot ok\n");
    unsafe { reboot(RB_POWER_OFF); }
    loop { std::hint::spin_loop(); }
}
RUST

log "compiling aarch64 init ..."
rustc -O --target aarch64-unknown-linux-musl \
  -C target-feature=+crt-static -C link-self-contained=yes -C linker=rust-lld \
  "${workdir}/init.rs" -o "${workdir}/init"
( cd "${workdir}" && mkdir -p iroot/sys && cp init iroot/init && \
  ( cd iroot && find . | cpio -o -H newc 2>/dev/null ) > initramfs.cpio )

# -- Boot with the SMMUv3 and an iommu_platform virtio NIC ----------------
log "booting guest (virt,iommu=smmuv3, TCG) ... [${BOOT_TIMEOUT}s timeout]"
set +e
timeout "${BOOT_TIMEOUT}" "${QEMU}" \
  -machine virt,gic-version=max,iommu=smmuv3 -cpu max -accel tcg \
  -smp 4 -m 1024 \
  -kernel "${KERNEL}" -initrd "${workdir}/initramfs.cpio" \
  -append "console=ttyAMA0 earlycon rdinit=/init panic=1" \
  -netdev user,id=n0 -device virtio-net-pci-non-transitional,netdev=n0,iommu_platform=on,ats=on \
  -netdev user,id=n1 -device e1000,netdev=n1 \
  -nographic -no-reboot \
  > "${workdir}/console.out" 2>&1 &
qemu_pid=$!
wait "${qemu_pid}" || true
set -e

echo "================= console ================="; cat "${workdir}/console.out" || true
echo "==========================================="

# -- Verdict --------------------------------------------------------------
boot_ok=1; smmu_probe=1; smmu_dev=1; groups=1; pci_grouped=1
grep -q "${BOOT_MARKER}" "${workdir}/console.out" && boot_ok=0
grep -qiE "arm-smmu-v3" "${workdir}/console.out" && smmu_probe=0
grep -qE "SMMU-DEVICES: \[.*smmu" "${workdir}/console.out" && smmu_dev=0
grep -qE "IOMMU-GROUPS: [1-9]" "${workdir}/console.out" && groups=0
# At least one PCI device (NIC) must be in an IOMMU group for vfio-pci/DPDK.
grep -qE "PCI: .* iommu_group=[0-9]+" "${workdir}/console.out" && pci_grouped=0

p() { [[ $1 -eq 0 ]] && echo PASS || echo FAIL; }
printf 'BOOT (reached init):                          %s\n' "$(p ${boot_ok})"
printf 'SMMU probed (arm-smmu-v3 on console):         %s\n' "$(p ${smmu_probe})"
printf 'SMMU registered (/sys/class/iommu):           %s\n' "$(p ${smmu_dev})"
printf 'IOMMU groups populated:                       %s\n' "$(p ${groups})"
printf 'PCI device(s) behind SMMU (vfio-able):        %s\n' "$(p ${pci_grouped})"

[[ ${boot_ok} -eq 0 && ${smmu_probe} -eq 0 && ${smmu_dev} -eq 0 && ${groups} -eq 0 && ${pci_grouped} -eq 0 ]]
