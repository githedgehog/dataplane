#!/usr/bin/env bash


set -euo pipefail

get_mlx5_devices() {
  for dev in /sys/bus/pci/drivers/mlx5_core/*/net/*; do
    readlink -e "${dev}"
  done | sort | uniq
}

get_eswitches() {
  while read -r dev; do
    echo "$(< "$dev/phys_switch_id"): $(basename "$dev")"
  done < <(get_mlx5_devices)
}

get_unique_eswitches() {
  declare -A eswitches
  while read -r dev; do
    if [ -n "${eswitches["$(< "$dev/phys_switch_id")"]:-}" ]; then
      continue
    fi
    eswitches["$(< "$dev/phys_switch_id")"]="$(basename "$(readlink -e $dev/../)")"
  done < <(get_mlx5_devices)
  for eswitch in "${!eswitches[@]}"; do
    echo "${eswitches["$eswitch"]}"
  done
}

reset_all_mlx5_nics() {
  while read -r nic; do
    echo "Resetting NIC: ${nic}"
    sudo mstfwreset --yes --dev "${nic}" reset
  done < <(get_unique_eswitches)
}

reset_all_mlx5_nics_firmware_to_stock() {
  while read -r nic; do
    echo "Resetting NIC firmware to stock: ${nic}"
    sudo mstconfig --yes --dev "${nic}" reset
  done < <(get_unique_eswitches)
}

upgrade_all_mlx5_nics_firmware() {
  sudo mlxup --online --yes
}

configure_all_mlx5_nics_firmware() {
  while read -r mlx5_nic; do
    echo "Configuring NIC: ${mlx5_nic}"
    mstconfig --yes --dev 0000:85:00.0 set \
      ATS_ENABLED=True \
      CQE_COMPRESSION=BALANCED \
      KEEP_ETH_LINK_UP_P1=False \
      KEEP_ETH_LINK_UP_P2=False \
      KEEP_ETH_LINK_UP_P3=False \
      KEEP_ETH_LINK_UP_P4=False \
      KEEP_IB_LINK_UP_P1=False \
      KEEP_IB_LINK_UP_P2=False \
      KEEP_IB_LINK_UP_P3=False \
      KEEP_IB_LINK_UP_P4=False \
      KEEP_LINK_UP_ON_BOOT_P1=False \
      KEEP_LINK_UP_ON_BOOT_P2=False \
      KEEP_LINK_UP_ON_BOOT_P3=False \
      KEEP_LINK_UP_ON_BOOT_P4=False \
      KEEP_LINK_UP_ON_STANDBY_P1=False \
      KEEP_LINK_UP_ON_STANDBY_P2=False \
      KEEP_LINK_UP_ON_STANDBY_P3=False \
      KEEP_LINK_UP_ON_STANDBY_P4=False \
      NUM_OF_VFS=4 \
      SRIOV_EN=True \
      UCTX_EN=True
  done < <(get_mlx5_devices)
}

reset_all_mlx5_nics
reset_all_mlx5_nics_firmware_to_stock
reset_all_mlx5_nics
upgrade_all_mlx5_nics_firmware
reset_all_mlx5_nics
reset_all_mlx5_nics_firmware_to_stock
reset_all_mlx5_nics
configure_all_mlx5_nics_firmware
reset_all_mlx5_nics




