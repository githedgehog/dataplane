#!/usr/bin/env bash
#
# Reset the BF-3 e-switch to switchdev, HWS steering, multiport, and two VFs per port.
# Fixed sleeps make this best-effort; recovery may require a host power cycle.

# Continue through idempotent failures. Abort explicitly if device reload fails.
set -uxo pipefail
shopt -s nullglob

declare -ar BDF=(
   "0000:e1:00.0"
   "0000:e1:00.1"
)

declare -r PRIMARY_BDF="0000:e1:00.0"

# driver_reinit avoids the firmware sync reset that wedged live HWS queues.
# It does not clear all firmware state; restore parameters explicitly below.
declare -r RELOAD_ACTION="driver_reinit"

# 1. Tear down any pre-existing VFs.
for dev in "${BDF[@]}"; do
    tee "/sys/bus/pci/devices/${dev}/sriov_numvfs" <<< 0
done

# 2. Move both PFs to legacy before reload; reloading in switchdev has wedged
#    the device and required a host power cycle.
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

# 4. Set steering and e-switch parameters before activating switchdev.
for dev in "${BDF[@]}"; do
    devlink dev param set "pci/${dev}" name flow_steering_mode value smfs cmode runtime
    devlink dev param set "pci/${dev}" name esw_multiport value true cmode runtime
    devlink dev param set "pci/${dev}" name esw_port_metadata value true cmode runtime
done
sleep 2

# 5. Create and auto-probe VFs. Disabling autoprobe caused later binds to fail
#    after switchdev re-enumeration on this card.
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
