#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Standalone boot spike for the aarch64 in-VM test path.
#
# This validates the three assumptions the `#[in_vm]` cross-arch path rests
# on, decoupled from Docker / nextest / the full n-vm pipeline:
#
#   1. the aarch64 guest kernel (built from the nix config fragments) boots
#      on QEMU's `virt` machine under TCG;
#   2. the PL011 console (`ttyAMA0` + `earlycon`) actually produces output;
#   3. guest -> host `vhost-vsock-pci` works under TCG -- the linchpin the
#      whole verdict/stdout channel depends on, and which the qemu-user
#      AF_VSOCK spike did NOT cover.
#
# It uses the SAME QEMU arguments the QEMU backend emits for aarch64 (see
# `n_vm::Arch` / `push_machine_args`), so a pass here means the real path
# should work.  Because the kernel uses an allnoconfig base, expect to
# iterate on `nix/pkgs/linux/fragments/aarch64-virt.config`: each boot that
# stalls names the missing subsystem, and `merge_config.sh` warnings (in
# the kernel build log) list symbols dropped for unmet dependencies.
#
# Usage:
#   scripts/n-vm-aarch64-boot-spike.sh            # build kernel+qemu, boot
#   KERNEL=/path/Image QEMU=/path/qemu-system-aarch64 scripts/...  # reuse
#
# Must be run from a host with /dev/vhost-vsock and KVM-less TCG QEMU.

set -euo pipefail

readonly VSOCK_PORT=9999
readonly GUEST_CID=42
readonly BOOT_MARKER="N-VM-SPIKE: boot ok"
readonly VSOCK_MARKER="N-VM-SPIKE: vsock ok"
readonly BOOT_TIMEOUT="${BOOT_TIMEOUT:-180}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"; [[ -n "${qemu_pid:-}" ]] && kill "${qemu_pid}" 2>/dev/null || true; [[ -n "${listener_pid:-}" ]] && kill "${listener_pid}" 2>/dev/null || true' EXIT

log() { printf '>>> %s\n' "$*" >&2; }

# ── 1. Resolve the kernel image and emulator ─────────────────────────────
if [[ -z "${KERNEL:-}" ]]; then
  log "building aarch64 guest kernel (nix) ..."
  kdir="$(nix build -f default.nix pkgs.linux-fancy \
    --argstr platform aarch64 --argstr libc musl --no-link --print-out-paths)"
  KERNEL="${kdir}/Image"
fi
[[ -f "${KERNEL}" ]] || { log "kernel image not found: ${KERNEL}"; exit 1; }
log "kernel: ${KERNEL}"

if [[ -z "${QEMU:-}" ]]; then
  log "building qemu-system-aarch64 (nix, build-native) ..."
  qdir="$(nix build -f default.nix pkgs.pkgsBuildHost.qemu \
    --argstr platform aarch64 --argstr libc musl --no-link --print-out-paths)"
  QEMU="${qdir}/bin/qemu-system-aarch64"
fi
[[ -x "${QEMU}" ]] || { log "qemu-system-aarch64 not found: ${QEMU}"; exit 1; }
log "qemu: ${QEMU}"

# ── 2. Build a tiny static aarch64 init (PID 1) ──────────────────────────
# Prints a boot marker to the console, connects AF_VSOCK to the host
# (CID 2) on VSOCK_PORT, writes a marker, then powers off via PSCI.
cat > "${workdir}/init.rs" <<RUST
use std::io::Write;
use std::os::raw::{c_int, c_uint, c_ushort};

#[repr(C)]
struct SockaddrVm { svm_family: c_ushort, svm_reserved1: c_ushort,
    svm_port: c_uint, svm_cid: c_uint, svm_zero: [u8; 4] }

unsafe extern "C" {
    fn socket(d: c_int, t: c_int, p: c_int) -> c_int;
    fn connect(fd: c_int, a: *const SockaddrVm, l: c_uint) -> c_int;
    fn write(fd: c_int, buf: *const u8, n: usize) -> isize;
    fn reboot(cmd: c_int) -> c_int;
}
const AF_VSOCK: c_int = 40;
const SOCK_STREAM: c_int = 1;
const VMADDR_CID_HOST: c_uint = 2;
const RB_POWER_OFF: c_int = 0x4321_fedc_u32 as c_int;

fn console(msg: &str) { let _ = std::io::stdout().write_all(msg.as_bytes());
    let _ = std::io::stdout().flush(); }

fn main() {
    console("${BOOT_MARKER}\n");
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd >= 0 {
        let addr = SockaddrVm { svm_family: AF_VSOCK as c_ushort, svm_reserved1: 0,
            svm_port: ${VSOCK_PORT}, svm_cid: VMADDR_CID_HOST, svm_zero: [0; 4] };
        let r = unsafe { connect(fd, &addr, core::mem::size_of::<SockaddrVm>() as c_uint) };
        if r == 0 {
            let m = b"${VSOCK_MARKER}\n";
            unsafe { write(fd, m.as_ptr(), m.len()); }
            console("${VSOCK_MARKER}\n");
        } else {
            console("N-VM-SPIKE: vsock connect FAILED\n");
        }
    } else {
        console("N-VM-SPIKE: AF_VSOCK socket() FAILED\n");
    }
    // PID 1 must not return; power off cleanly via PSCI.
    unsafe { reboot(RB_POWER_OFF); }
    loop { std::hint::spin_loop(); }
}
RUST

log "compiling aarch64 init ..."
rustc -O --target aarch64-unknown-linux-musl \
  -C target-feature=+crt-static -C link-self-contained=yes -C linker=rust-lld \
  "${workdir}/init.rs" -o "${workdir}/init"

# Wrap the init in a minimal initramfs (single static binary as /init).
# Uncompressed cpio: the kernel always supports the raw newc format, so we
# don't depend on any RD_<compressor> config (the guest kernel here has no
# gzip/zstd initramfs support -- the real n-vm path boots via virtiofs, not
# an initrd, so that's fine).
( cd "${workdir}" && mkdir -p iroot && cp init iroot/init && \
  ( cd iroot && find . | cpio -o -H newc 2>/dev/null ) > initramfs.cpio )

# ── 3. Host-side AF_VSOCK listener ───────────────────────────────────────
# Confirms the guest's vhost-vsock connection actually reached the host.
cat > "${workdir}/listen.py" <<PY
import socket, sys
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.bind((socket.VMADDR_CID_ANY, ${VSOCK_PORT}))
s.listen(1)
s.settimeout(${BOOT_TIMEOUT})
try:
    conn, _ = s.accept()
    data = conn.recv(256)
    sys.stdout.write("HOST-LISTENER got: " + data.decode(errors="replace"))
    sys.exit(0)
except socket.timeout:
    sys.stderr.write("HOST-LISTENER: timed out waiting for guest vsock\n")
    sys.exit(1)
PY

log "starting host vsock listener (CID ANY, port ${VSOCK_PORT}) ..."
python3 "${workdir}/listen.py" > "${workdir}/listener.out" 2>&1 &
listener_pid=$!
sleep 1

# ── 4. Boot the guest (args mirror the aarch64 QEMU backend) ─────────────
log "booting guest (TCG, virt) ... [${BOOT_TIMEOUT}s timeout]"
set +e
timeout "${BOOT_TIMEOUT}" "${QEMU}" \
  -machine virt,gic-version=max -cpu max -accel tcg \
  -smp 4 -m 1024 \
  -kernel "${KERNEL}" \
  -initrd "${workdir}/initramfs.cpio" \
  -append "console=ttyAMA0 earlycon rdinit=/init panic=1" \
  -device vhost-vsock-pci,guest-cid=${GUEST_CID} \
  -nographic -no-reboot \
  > "${workdir}/console.out" 2>&1 &
qemu_pid=$!
# The verdict comes from the console / listener output below, not these
# exit codes (QEMU exits non-zero on the timeout kill; that's expected).
wait "${qemu_pid}" || true
wait "${listener_pid}" || true
set -e

# ── 5. Verdict ───────────────────────────────────────────────────────────
echo "================= console ================="; cat "${workdir}/console.out" || true
echo "================ listener ================="; cat "${workdir}/listener.out" || true
echo "==========================================="

boot_ok=1; vsock_ok=1
grep -q "${BOOT_MARKER}" "${workdir}/console.out" && boot_ok=0
grep -q "${VSOCK_MARKER}" "${workdir}/listener.out" && vsock_ok=0

printf 'BOOT (ttyAMA0 console reached init): %s\n' "$([[ ${boot_ok} -eq 0 ]] && echo PASS || echo FAIL)"
printf 'VSOCK (guest->host vhost-vsock under TCG): %s\n' "$([[ ${vsock_ok} -eq 0 ]] && echo PASS || echo FAIL)"

[[ ${boot_ok} -eq 0 && ${vsock_ok} -eq 0 ]]
