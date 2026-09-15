// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Map the mlx5 switchdev port topology exposed by the `representor=` devarg.
//!
//! When the PF is probed with `representor=...`, the PMD creates extra DPDK eth ports (uplink / PF /
//! VF representors). This enumerates every probed port and prints its switch_info (domain + physical
//! switch port id) and representor role -- so we can see which DPDK port_id is the uplink/wire vs the
//! host PF vs a VF representor, and thus how to address the wire egress in a transfer rule.
//!
//! Run as root:  sudo ./representor_probe 0000:e1:00.1 [representor_spec=vf[0-1]]

use dataplane_dpdk::eal;
use dpdk_sys::{
    rte_eth_dev_get_name_by_port, rte_eth_dev_info, rte_eth_dev_info_get, rte_eth_find_next,
};

type Err = Box<dyn std::error::Error>;

const RTE_MAX_ETHPORTS: u16 = 32;

fn cstr(p: *const core::ffi::c_char) -> String {
    if p.is_null() {
        return "(null)".to_string();
    }
    // SAFETY: caller passes a valid C string pointer or null (checked above).
    unsafe { core::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned()
}

fn main() -> Result<(), Err> {
    let mut args = std::env::args().skip(1);
    let bdf = args.next().unwrap_or_else(|| "0000:e1:00.1".to_string());
    let rep = args.next().unwrap_or_else(|| "vf[0-1]".to_string());

    let devarg = format!("{bdf},dv_flow_en=2,representor={rep}");
    println!("EAL devarg: {devarg}");
    let _eal = eal::init([
        "-a",
        devarg.as_str(),
        "-n",
        "4",
        "--in-memory",
        "--iova-mode=va",
        "-l",
        "0-1",
        "--no-telemetry",
    ]);

    println!("--- probed DPDK ports ---");
    let mut p = unsafe { rte_eth_find_next(0) };
    while p < RTE_MAX_ETHPORTS {
        let mut name = [0i8; 64];
        // SAFETY: name buffer is RTE_ETH_NAME_MAX_LEN-sized; p is a valid probed port.
        unsafe { rte_eth_dev_get_name_by_port(p, name.as_mut_ptr()) };
        let mut info: rte_eth_dev_info = unsafe { core::mem::zeroed() };
        // SAFETY: info is a live out-param; p is valid.
        let rc = unsafe { rte_eth_dev_info_get(p, &mut info) };
        if rc == 0 {
            let sw = &info.switch_info;
            println!(
                "port {p}: name={} driver={} switch{{name={} domain_id={} phys_port_id={} rx_domain={}}}",
                cstr(name.as_ptr()),
                cstr(info.driver_name),
                cstr(sw.name),
                sw.domain_id,
                sw.port_id,
                sw.rx_domain,
            );
        } else {
            println!("port {p}: dev_info_get failed rc={rc}");
        }
        p = unsafe { rte_eth_find_next(p + 1) };
    }
    Ok(())
}
