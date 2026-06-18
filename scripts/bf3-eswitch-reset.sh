#!/usr/bin/env bash
#
# Best-effort, re-entrant reset of the BF-3 e-switch into the "stock production"
# topology: switchdev mode, HWS steering, multiport e-switch, 2 VFs per port.
#
# This is a validation hack. It is full of fixed-sleep races that should one day
# become netlink/devlink completion waits (see rekon/) rather than `sleep`. Until
# then, if it wedges, a full host power cycle is always an option.

# NB: deliberately NOT `-e`. A reset must drive the *whole* sequence to the end
# even when an individual idempotent step is a no-op "failure" (e.g. numvfs already
# 0, e-switch already legacy). Aborting half-way leaves the card in a worse state
# for the next run -- a likely source of mystery errors. The one genuinely fatal
# step (the device reload) is checked explicitly below.
set -uxo pipefail
shopt -s nullglob

declare -ar BDF=(
   "0000:e1:00.0"
   "0000:e1:00.1"
)

declare -r PRIMARY_BDF="0000:e1:00.0"

# driver_reinit re-inits the driver WITHOUT a firmware sync reset, which avoids the
# malfunction we hit with fw_activate: fw_activate does a "PCI Sync FW Update Reset"
# ("Function is forced down") that -- with any HWS/switchdev state live -- strands the
# HW-steering command queues ("mlx5hws_bwc_queue_poll: ... TIMEOUT", "Failed to
# allocate RX STE range (-67)" every 60s; journal boot -1), requiring a host power
# cycle. Trade-off: driver_reinit does NOT scrub deep firmware-sticky state, so we
# rely on the explicit param/mode sets below to reach "stock". Switch back to
# fw_activate only if you need that deeper reset (and kill any DPDK app holding HWS
# first). Either way, keep the legacy-before-reload ordering below.
declare -r RELOAD_ACTION="driver_reinit"

# 1. Tear down any pre-existing VFs.
for dev in "${BDF[@]}"; do
    tee "/sys/bus/pci/devices/${dev}/sriov_numvfs" <<< 0
done

# 2. Move BOTH PFs to legacy BEFORE the reload.
#    LOAD-BEARING -- NOT redundant. Reloading/activating firmware while the e-switch
#    is still in switchdev/offloads mode malfunctions the driver badly enough to
#    require a full host power cycle (observed). Always reach legacy first.
for dev in "${BDF[@]}"; do
    devlink dev eswitch set "pci/${dev}" mode legacy
    sleep 1
done

# 3. Reset the device. One reload per ASIC (both PFs share it); affects e1:00.1 too.
#    This is the one fatal step: if it fails, do not proceed on a half-reset card.
if ! devlink dev reload "pci/${PRIMARY_BDF}" action "${RELOAD_ACTION}"; then
    echo "FATAL: 'devlink dev reload ... ${RELOAD_ACTION}' failed; a power cycle may be required" >&2
    exit 1
fi
sleep 10 # race: wait for both PFs to re-probe (should be a devlink completion wait)

# 4. Steering + e-switch params, set while still in legacy.
#    flow_steering_mode MUST be set before e-switch activation (the switchdev flip
#    in step 7), so it is set here. If you remove this and that flip starts failing,
#    this is why.
for dev in "${BDF[@]}"; do
    devlink dev param set "pci/${dev}" name flow_steering_mode value smfs cmode runtime
    devlink dev param set "pci/${dev}" name esw_multiport value true cmode runtime
    devlink dev param set "pci/${dev}" name esw_port_metadata value true cmode runtime
done
sleep 2

# 5. Create VFs (auto-probed at creation).
#    NB: tried sriov_drivers_autoprobe=0 here to skip the probe/unbind churn, but on this
#    card the later bind then fails "tee: .../bind: No such device" -- the VFs get
#    re-enumerated across the switchdev flip (step 7) and a never-probed VF is not
#    bindable yet. A VF that was probed-at-creation, unbound (step 6), then rebound
#    (step 9) binds cleanly, so we keep that dance despite the extra churn.
for dev in "${BDF[@]}"; do
    tee "/sys/bus/pci/devices/${dev}/sriov_numvfs" <<< 2
done
sleep 5

# 6. Detach the VFs (and collect their BDFs): the e-switch mode cannot flip while VFs
#    are bound/in-use, so unbind them before switchdev and rebind after (step 9).
declare -a virtfns=()
for dev in "${BDF[@]}"; do
    for virtfn in "/sys/bus/pci/devices/${dev}/virtfn"*; do
        bdf="$(basename "$(readlink -e "${virtfn}")")"
        virtfns+=("${bdf}")
        tee /sys/bus/pci/drivers/mlx5_core/unbind <<< "${bdf}"
        sleep 1
    done
done

# 7. Flip both PFs to switchdev (the representors appear here).
for dev in "${BDF[@]}"; do
    devlink dev eswitch set "pci/${dev}" mode switchdev
    sleep 1
done
sleep 5

# 8. Re-assert steering + e-switch params now that switchdev is active.
for dev in "${BDF[@]}"; do
    devlink dev param set "pci/${dev}" name flow_steering_mode value smfs cmode runtime
    devlink dev param set "pci/${dev}" name esw_multiport value true cmode runtime
    devlink dev param set "pci/${dev}" name esw_port_metadata value true cmode runtime
done
sleep 5

# 9. Rebind the VFs (in switchdev context). A probed-then-unbound VF rebinds cleanly.
for virtfn in "${virtfns[@]}"; do
    tee /sys/bus/pci/drivers/mlx5_core/bind <<< "${virtfn}"
    sleep 1
done
