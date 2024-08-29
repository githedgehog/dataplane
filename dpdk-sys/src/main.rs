use crate::dpdk_sys::{rte_eal_cleanup, rte_eal_has_pci, rte_eal_init, rte_eth_dev_count_avail, rte_exit};
use std::ffi::{c_char, CString};
use std::process::exit;

mod dpdk_sys;

fn as_cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

struct DpdkEnv;

impl DpdkEnv {
    /// TODO: proper safety analysis
    fn new<T: AsRef<str>>(args: Vec<T>) -> DpdkEnv {
        {
            let mut args: Vec<_> = args.iter().map(|s| as_cstr(s.as_ref())).collect();
            let len = args.len();
            let mut args2 = args.iter().map(|s| s.as_ptr() as *mut c_char).collect::<Vec<*mut c_char>>();
            let exit_code =
                unsafe { rte_eal_init(len as _, args2.as_mut_ptr()) };
            if exit_code < 0 {
                const ERR_MSG: &str = "Invalid EAL arguments";
                let err_msg = CString::new(ERR_MSG).unwrap().as_c_str().as_ptr();
                unsafe {
                    rte_exit(exit_code, err_msg);
                }
            }
            println!("EAL initialization successful: {exit_code}");
        }
        Self
    }
}

impl Drop for DpdkEnv {
    /// TODO: proper safety analysis
    fn drop(&mut self) {
        let exit_code = unsafe { rte_eal_cleanup() };
        match exit_code {
            0 => {
                println!("EAL cleanup successful");
            }
            _ => {
                eprintln!("Error: Invalid EAL cleanup");
                exit(exit_code);
            }
        }
    }
}

fn main() {
    let args = vec![
        "--in-memory",
        "--huge-dir",
        "/mnt/huge/1G",
        "--allow",
        "0000:01:00.0",
        "--allow",
        "0000:01:00.1",
        "--allow",
        "0000:02:00.0",
        "-d",
        "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_bus_pci.so",
        "-d",
        "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_net_mlx5.so",
        "-d",
        "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_common_mlx5.so",
        "-d",
        "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_regex_mlx5.so",
        "-d",
        "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_vdpa_mlx5.so",
    ];
    println!("DPDK arguments: {:?}", args);
    let eal = DpdkEnv::new(args);
    let has_pci = unsafe { rte_eal_has_pci() };
    println!("Has PCI: {}", has_pci);
    let count = unsafe { rte_eth_dev_count_avail() };
    println!("Available Ethernet devices: {}", count);
}
