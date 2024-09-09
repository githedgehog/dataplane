use crate::dpdk_sys::{
    rte_eal_cleanup, rte_eal_has_pci, rte_eal_init, rte_eth_dev_count_avail, rte_eth_dev_info_get,
    rte_exit,
};
use std::ffi::{c_char, c_int, c_uint, CStr, CString};
use std::fmt::Debug;
use std::io;
use std::net::Ipv4Addr;
use std::rc::Rc;
use tracing::{debug, error, info, trace, warn};

mod dpdk_sys;

/// Macro to create a static, null-terminated, literal C string from a string literal.
///
/// # Safety
///
/// The rules are basically the same as any C string usage.
///
/// 1. The literal must not include interior null bytes.
/// 2. The literal must not include non-ASCII bytes.
macro_rules! cstr_literal {
    ($l:literal) => {{
        concat!($l, "\0").as_ptr().cast()
    }};
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", ret))]
// TODO: proper safety.  This should return a Result but I'm being a savage for demo purposes.
fn as_cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[derive(Debug)]
struct Eal;

impl Eal {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", ret))]
    /// Initializes the DPDK Environment Abstraction Layer (EAL).
    ///
    /// TODO: proper safety analysis (in a hurry for demo purposes)
    pub fn new<T: Debug + AsRef<str>>(args: Vec<T>) -> Eal {
        {
            let args: Vec<_> = args.iter().map(|s| as_cstr(s.as_ref())).collect();
            let mut cargs: Vec<_> = args.iter().map(|s| s.as_ptr() as *mut c_char).collect();
            let len = cargs.len() as c_int;
            let exit_code = unsafe { rte_eal_init(len, cargs.as_mut_ptr()) };
            /// TODO: this is a poor error message
            if exit_code < 0 {
                unsafe { rte_exit(exit_code, cstr_literal!("Invalid EAL arguments")) };
            }
            info!("EAL initialization successful: {exit_code}");
        }
        Self
    }
}

/// Exits the DPDK application with an error message, cleaning up the EAL as gracefully as
/// possible (by way of [`dpdk_sys::rte_exit`]).
///
/// This function never returns as it exits the application.
pub fn fatal_error(message: &str) -> ! {
    error!("{message}");
    let message_cstring = as_cstr(message);
    unsafe { rte_exit(1, message_cstring.as_ptr()) }
}

impl Drop for Eal {
    /// TODO: proper safety analysis
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
    fn drop(&mut self) {
        let exit_code = unsafe { rte_eal_cleanup() };
        if exit_code < 0 {
            fatal_error("EAL cleanup failed");
        } else {
            info!("EAL cleanup successful");
        }
    }
}

impl Eal {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", ret))]
    /// Returns `true` if the [`Eal`] is using the PCI bus.
    ///
    /// This is mostly a safe wrapper around [`dpdk_sys::rte_eal_has_pci`] which simply converts to
    /// a bool instead of a `c_int`.
    pub fn has_pci(&self) -> bool {
        unsafe { rte_eal_has_pci() != 0 }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument(level = "trace", ret))]
    /// Safe wrapper around [`dpdk_sys::rte_eth_dev_count_avail`]
    pub fn eth_dev_count_avail(&self) -> u16 {
        unsafe { rte_eth_dev_count_avail() }
    }
}

/// Sets up flow rules for demo purposes
fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();
    let args = vec![
        "-c",
        "0xffffffffff",
        "--in-memory",
        "--huge-dir",
        "/mnt/huge/2M",
        "--huge-dir",
        "/mnt/huge/1G",
        "--allow",
        "0000:01:00.0,dv_flow_en=2",
        "--trace=.*",
        "--iova-mode=va",
        "-l",
        "8,9,10,11,12,13,14,15",
        // "--allow",
        // "0000:01:00.1",
        // "--allow",
        // "0000:02:00.0",
        "--huge-worker-stack=8192",
        "--socket-mem=4096,4096,4096,4096",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/librte_mempool.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/librte_mempool_ring.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/librte_mempool_stack.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_bus_pci.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_net_mlx5.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_common_mlx5.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_regex_mlx5.so",
        // "-d",
        // "/mnt/dpdk-arch-sysroot/usr/lib/dpdk/pmds-24.2/librte_vdpa_mlx5.so",
    ];
    info!("DPDK arguments: {args:?}");
    let eal = Eal::new(args);
    let has_pci = eal.has_pci();
    info!("Has PCI: {has_pci}");

    if !has_pci {
        fatal_error("No PCI devices found")
    }
    let count = eal.eth_dev_count_avail();

    info!("Available Ethernet devices: {count}");
    if count == 0 {
        return fatal_error("No Ethernet devices found");
    }

    if count > 1 {
        return fatal_error("Multiple Ethernet devices found");
    }

    let socket_id = unsafe { dpdk_sys::rte_socket_id() } as c_int;

    info!("Socket ID: {socket_id}");

    const MBUF_POOL_NAME: &str = "mbuf_pool";
    let mbuf_pool_name = as_cstr(MBUF_POOL_NAME);

    const MBUF_POOL_SIZE: u32 = (1 << 12) - 1;
    const MBUF_CACHE_SIZE: u32 = 128;
    const MBUF_PRIV_SIZE: u16 = 0;
    const MBUF_DATA_SIZE: u32 = 2048 + 128;

    let mbuf_pool = {
        let mbuf_pool_ptr = unsafe {
            dpdk_sys::rte_pktmbuf_pool_create(
                mbuf_pool_name.as_ptr(),
                MBUF_POOL_SIZE,
                MBUF_CACHE_SIZE,
                MBUF_PRIV_SIZE,
                2048 + 128,
                3,
            )
        };

        if mbuf_pool_ptr.is_null() {
            let errno = unsafe { dpdk_sys::rte_get_errno() };
            let c_err_str = unsafe { dpdk_sys::rte_strerror(errno) };
            let err_str = unsafe { std::ffi::CStr::from_ptr(c_err_str) };
            let err_str = err_str.to_str().unwrap();
            error!("Failed to create mbuf pool: errno {errno}, {err_str}");
            unsafe {
                rte_exit(
                    errno,
                    format!("Failed to create mbuf pool: errno {errno}, {err_str}").as_ptr()
                        as *const _,
                );
            }
        }
        unsafe { &mut *mbuf_pool_ptr }
    };

    let port_id = 0;
    init_port2(port_id, mbuf_pool);

    meter_stuff(port_id);

    {
        debug!("Setting up flow rules");
        let mut err = dpdk_sys::rte_flow_error::default();
        let flow = generate_ct_flow2(
            port_id,
            4,
            &mut err,
        );
    }

    debug!("Should have torn down flow rules");

    let ret = unsafe { dpdk_sys::rte_eth_dev_stop(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to stop device: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    unsafe {
        dpdk_sys::rte_mempool_free(mbuf_pool as *mut _);
    };
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "info", skip(mbuf_pool))
)]
fn init_port(port_id: u16, mbuf_pool: &mut dpdk_sys::rte_mempool) {
    let mut port_conf = dpdk_sys::rte_eth_conf {
        txmode: dpdk_sys::rte_eth_txmode {
            offloads: (dpdk_sys::rte_eth_tx_offload::VLAN_INSERT
                | dpdk_sys::rte_eth_tx_offload::IPV4_CKSUM
                | dpdk_sys::rte_eth_tx_offload::UDP_CKSUM
                | dpdk_sys::rte_eth_tx_offload::TCP_CKSUM
                | dpdk_sys::rte_eth_tx_offload::SCTP_CKSUM
                | dpdk_sys::rte_eth_tx_offload::TCP_TSO)
                .0,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut txq_conf: dpdk_sys::rte_eth_txconf;
    let mut rxq_conf: dpdk_sys::rte_eth_rxconf = unsafe { std::mem::zeroed() };
    let mut dev_info: dpdk_sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };

    let ret = unsafe { rte_eth_dev_info_get(port_id, &mut dev_info as *mut _) };

    if ret != 0 {
        let err_msg = format!(
            "Failed to get device info: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    info!("Port ID {port_id}");
    let driver_name = unsafe { CStr::from_ptr(dev_info.driver_name).to_str().unwrap() };
    info!("Driver name: {driver_name}");

    let nr_queues = 5;

    port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    info!("Initialising port {port_id}");
    let ret = unsafe { dpdk_sys::rte_eth_dev_configure(port_id, nr_queues, nr_queues, &port_conf) };

    if ret != 0 {
        let err_msg = format!(
            "Failed to configure device: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;

    let nr_rx_descriptors = 512;

    // configure rx queues
    for queue_num in 0..nr_queues {
        info!("Configuring RX queue {queue_num}");
        let ret = unsafe {
            dpdk_sys::rte_eth_rx_queue_setup(
                port_id,
                queue_num,
                nr_rx_descriptors,
                dpdk_sys::rte_eth_dev_socket_id(port_id) as c_uint,
                &rxq_conf,
                mbuf_pool,
            )
        };

        if ret < 0 {
            let err_msg = format!(
                "Failed to configure RX queue {queue_num}: {ret}",
                queue_num = queue_num,
                ret = io::Error::from_raw_os_error(ret)
            );
            fatal_error(err_msg.as_str());
        }
        info!("RX queue {queue_num} configured");
    }

    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    for queue_num in 0..nr_queues {
        info!("Configuring TX queue {queue_num}");
        let ret = unsafe {
            dpdk_sys::rte_eth_tx_queue_setup(
                port_id,
                queue_num,
                nr_rx_descriptors,
                dpdk_sys::rte_eth_dev_socket_id(port_id) as c_uint,
                &txq_conf as *const _,
            )
        };

        if ret < 0 {
            let err_msg = format!(
                "Failed to configure TX queue {queue_num}: {ret}",
                queue_num = queue_num,
                ret = io::Error::from_raw_os_error(ret)
            );
            fatal_error(err_msg.as_str());
        }
        info!("TX queue {queue_num} configured");
    }

    info!("Port {port_id} configured");

    let ret = unsafe { dpdk_sys::rte_eth_promiscuous_enable(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to enable promiscuous mode: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    info!("Port {port_id} set to promiscuous mode");

    let ret = unsafe { dpdk_sys::rte_eth_dev_start(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to start device: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    info!("Port {port_id} started");
    assert_link_status(port_id);
    info!("Port {port_id} has been initialized");
}

const EINVAL: i32 = 11;

fn assert_link_status(port_id: u16) {
    let mut link: dpdk_sys::rte_eth_link = unsafe { std::mem::zeroed() };
    let rep_cnt = 900;
    let mut link_get_err = -EINVAL;
    for _cycle in 0..rep_cnt {
        link_get_err = unsafe { dpdk_sys::rte_eth_link_get(port_id, &mut link as *mut _) };
        if link_get_err == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    if link_get_err < 0 {
        let err_str = unsafe { dpdk_sys::rte_strerror(-link_get_err) };
        let err_msg = format!(
            "Failed to get link status ({link_get_err}): {err_str}",
            err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
        );
        fatal_error(err_msg.as_str());
    }

    // TODO: assert link status!
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// As yet unchecked arguments used to create a mbuf pool.
pub struct MbufPoolArgs<'a> {
    pub name: &'a str,
    pub size: u32,
    pub cache_size: u32,
    pub private_size: u16,
    pub data_size: u16,
    pub socket_id: i32,
}

impl<'a> MbufPoolArgs<'a> {
    pub const SOCKET_ID_ANY: i32 = -1;
    pub const DEFAULT: Self = Self {
        name: "mbuf_pool",
        size: (1 << 12) - 1,
        cache_size: 128,
        private_size: 0,
        data_size: 2048 + 128,
        socket_id: Self::SOCKET_ID_ANY,
    };
}

impl<'a> Default for MbufPoolArgs<'a> {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MbufPool {
    pool: *mut dpdk_sys::rte_mempool,
}

impl MbufPool {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
    /// TODO: thiserror should be used to get a properly structured error.
    pub fn new_pkt_pool(args: MbufPoolArgs) -> Result<MbufPool, String> {
        let name = as_cstr(args.name);
        let pool = unsafe {
            dpdk_sys::rte_pktmbuf_pool_create(
                name.as_ptr(),
                args.size,
                args.cache_size,
                args.private_size,
                args.data_size,
                args.socket_id,
            )
        };

        if pool.is_null() {
            let errno = unsafe { dpdk_sys::rte_get_errno() };
            let c_err_str = unsafe { dpdk_sys::rte_strerror(errno) };
            let err_str = unsafe { CStr::from_ptr(c_err_str) };
            let err_str = err_str.to_str().unwrap();
            let err_msg = format!("Failed to create mbuf pool: {err_str}; (errno: {errno})");
            error!("{err_msg}");
            return Err(err_msg);
        }

        Ok(Self { pool })
    }
}

impl Drop for MbufPool {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
    fn drop(&mut self) {
        unsafe {
            dpdk_sys::rte_mempool_free(self.pool);
        }
    }
}

const MAX_PATTERN_NUM: usize = 3;

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
fn generate_ipv4_flow(
    port_id: u16,
    rx_q: u16,
    src_ip: Ipv4Addr,
    src_mask: Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_mask: Ipv4Addr,
    err: &mut dpdk_sys::rte_flow_error,
) -> RteFlow {
    let mut attr: dpdk_sys::rte_flow_attr = Default::default();
    let mut pattern: [dpdk_sys::rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [dpdk_sys::rte_flow_action; MAX_PATTERN_NUM] = Default::default();
    let queue = dpdk_sys::rte_flow_action_queue { index: rx_q };

    attr.set_ingress(1);

    action[0].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue as *const _ as *const _;
    action[1].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;
    let ip_spec = dpdk_sys::rte_flow_item_ipv4 {
        hdr: dpdk_sys::rte_ipv4_hdr {
            src_addr: htonl(src_ip),
            dst_addr: htonl(dest_ip),
            ..Default::default()
        },
    };
    let ip_mask = dpdk_sys::rte_flow_item_ipv4 {
        hdr: dpdk_sys::rte_ipv4_hdr {
            src_addr: htonl(src_mask),
            dst_addr: htonl(dest_mask),
            ..Default::default()
        },
    };
    pattern[1].spec = &ip_spec as *const _ as *const _;
    pattern[1].mask = &ip_mask as *const _ as *const _;

    pattern[2].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;

    let res = unsafe {
        dpdk_sys::rte_flow_validate(
            port_id,
            &attr as *const _,
            pattern.as_ptr(),
            action.as_ptr(),
            err,
        )
    };

    if res != 0 {
        let err_str = unsafe { dpdk_sys::rte_strerror(res) };
        let err_msg = format!(
            "Failed to validate flow: {err_str}",
            err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
        );
        fatal_error(err_msg.as_str());
    }

    let flow = unsafe {
        dpdk_sys::rte_flow_create(
            port_id,
            &attr as *const _,
            pattern.as_ptr() as *const _,
            action.as_ptr() as *const _,
            err,
        )
    };

    if flow.is_null() || !err.message.is_null() {
        if err.message.is_null() {
            fatal_error("Failed to create flow: unknown error");
        }
        let err_str = unsafe { CStr::from_ptr(err.message) };
        fatal_error(err_str.to_str().unwrap());
    }

    debug!("Flow created");

    RteFlow::new(port_id, flow)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RteFlow {
    port: u16, // TODO: this should be a ref for safety
    flow: *mut dpdk_sys::rte_flow,
}

impl RteFlow {
    // TODO: this is stupid, make a real wrapper
    fn new(port: u16, flow: *mut dpdk_sys::rte_flow) -> Self {
        Self { port, flow }
    }
}

impl Drop for RteFlow {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
    fn drop(&mut self) {
        if self.flow.is_null() {
            warn!("Attempted to destroy null flow?");
            return;
        }
        let mut err = dpdk_sys::rte_flow_error::default();
        let res = unsafe { dpdk_sys::rte_flow_destroy(self.port, self.flow, &mut err) };

        if res == 0 {
            debug!("Flow destroyed");
            return;
        }

        let rte_err = unsafe { dpdk_sys::rte_get_errno() };
        let err_msg = unsafe { CStr::from_ptr(dpdk_sys::rte_strerror(res)) }
            .to_str()
            .unwrap();
        if err.message.is_null() {
            fatal_error(
                format!("Failed to destroy flow, but no flow error was given): {err_msg} (rte_errno: {rte_err})").as_str(),
            );
        } else {
            let err_str = unsafe { CStr::from_ptr(err.message) }.to_str().unwrap();
            let err_msg = format!("Failed to destroy flow: {err_str} (rte_errno: {rte_err})");
            fatal_error(err_msg.as_str());
        }
    }
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "trace"))]
fn htonl<T: Debug + Into<u32>>(x: T) -> u32 {
    u32::to_be(x.into())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
fn check_hairpin_cap(port_id: u16) {
    let mut cap: dpdk_sys::rte_eth_hairpin_cap = Default::default();
    let ret = unsafe { dpdk_sys::rte_eth_dev_hairpin_capability_get(port_id, &mut cap) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to get hairpin capability: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    let locked_device_memory = cap.rx_cap.locked_device_memory();
    let reserved = cap.rx_cap.reserved();
    let rte_memory = cap.rx_cap.rte_memory();

    info!("Hairpin cap: rx locked_device_memory: {locked_device_memory}");
    info!("Hairpin cap: rx reserved: {reserved}");
    info!("Hairpin cap: rx rte_memory: {rte_memory}");
    info!(
        "Hairpin cap: tx locked_device_memory: {}",
        cap.tx_cap.locked_device_memory()
    );
    info!("Hairpin cap: tx reserved: {}", cap.tx_cap.reserved());
    info!("Hairpin cap: tx rte_memory: {}", cap.tx_cap.rte_memory());
    info!("Hairpin cap: max tx to rx: {}", cap.max_tx_2_rx);
    info!("Hairpin cap: max rx to tx: {}", cap.max_rx_2_tx);
    info!("Hairpin cap: max nb queues: {}", cap.max_nb_queues);
    info!("Hairpin cap: max nb desc: {}", cap.max_nb_desc);
}

#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "info", skip(mbuf_pool))
)]
fn init_port2(port_id: u16, mbuf_pool: &mut dpdk_sys::rte_mempool) {
    let mut port_conf = dpdk_sys::rte_eth_conf {
        txmode: dpdk_sys::rte_eth_txmode {
            offloads: (dpdk_sys::rte_eth_tx_offload::VLAN_INSERT
                | dpdk_sys::rte_eth_tx_offload::IPV4_CKSUM
                | dpdk_sys::rte_eth_tx_offload::UDP_CKSUM
                | dpdk_sys::rte_eth_tx_offload::TCP_CKSUM
                | dpdk_sys::rte_eth_tx_offload::SCTP_CKSUM
                | dpdk_sys::rte_eth_tx_offload::TCP_TSO)
                .0,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut txq_conf: dpdk_sys::rte_eth_txconf;
    let mut rxq_conf: dpdk_sys::rte_eth_rxconf = unsafe { std::mem::zeroed() };
    let mut dev_info: dpdk_sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };

    let ret = unsafe { rte_eth_dev_info_get(port_id, &mut dev_info as *mut _) };

    if ret != 0 {
        let err_msg = format!(
            "Failed to get device info: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    info!("Port ID {port_id}");
    let driver_name = unsafe { CStr::from_ptr(dev_info.driver_name).to_str().unwrap() };
    info!("Driver name: {driver_name}");

    let nr_queues = 5;

    port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    info!("Initialising port {port_id}");
    let ret = unsafe { dpdk_sys::rte_eth_dev_configure(port_id, nr_queues, nr_queues, &port_conf) };

    if ret != 0 {
        let err_msg = format!(
            "Failed to configure device: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;

    let nr_rx_descriptors = 512;

    // configure rx queues
    for queue_num in 0..(nr_queues - 1) {
        info!("Configuring RX queue {queue_num}");
        let ret = unsafe {
            dpdk_sys::rte_eth_rx_queue_setup(
                port_id,
                queue_num,
                nr_rx_descriptors,
                dpdk_sys::rte_eth_dev_socket_id(port_id) as c_uint,
                &rxq_conf,
                mbuf_pool,
            )
        };

        if ret < 0 {
            let err_msg = format!(
                "Failed to configure RX queue {queue_num}: {ret}",
                queue_num = queue_num,
                ret = io::Error::from_raw_os_error(ret)
            );
            fatal_error(err_msg.as_str());
        }
        info!("RX queue {queue_num} configured");
    }

    check_hairpin_cap(port_id);

    let mut rx_hairpin_conf = dpdk_sys::rte_eth_hairpin_conf::default();
    rx_hairpin_conf.set_peer_count(1);
    rx_hairpin_conf.peers[0].port = port_id;
    rx_hairpin_conf.peers[0].queue = nr_queues - 1;

    let ret = unsafe {
        dpdk_sys::rte_eth_rx_hairpin_queue_setup(port_id, nr_queues - 1, 0, &rx_hairpin_conf)
    };

    if ret < 0 {
        let err_msg = format!(
            "Failed to configure RX hairpin queue: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    info!("RX hairpin queue configured");

    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    for queue_num in 0..(nr_queues - 1) {
        info!("Configuring TX queue {queue_num}");
        let ret = unsafe {
            dpdk_sys::rte_eth_tx_queue_setup(
                port_id,
                queue_num,
                nr_rx_descriptors,
                dpdk_sys::rte_eth_dev_socket_id(port_id) as c_uint,
                &txq_conf as *const _,
            )
        };

        if ret < 0 {
            let err_msg = format!(
                "Failed to configure TX queue {queue_num}: {ret}",
                queue_num = queue_num,
                ret = io::Error::from_raw_os_error(ret)
            );
            fatal_error(err_msg.as_str());
        }
        info!("TX queue {queue_num} configured");
    }

    let mut tx_hairpin_conf = dpdk_sys::rte_eth_hairpin_conf::default();
    tx_hairpin_conf.set_peer_count(1);
    tx_hairpin_conf.peers[0].port = port_id;
    tx_hairpin_conf.peers[0].queue = nr_queues - 1;

    let ret = unsafe {
        dpdk_sys::rte_eth_tx_hairpin_queue_setup(port_id, nr_queues - 1, 0, &tx_hairpin_conf)
    };

    if ret < 0 {
        let err_msg = format!(
            "Failed to configure TX hairpin queue: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    info!("TX hairpin queue configured");

    info!("Port {port_id} configured");

    let ret = unsafe { dpdk_sys::rte_eth_promiscuous_enable(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to enable promiscuous mode: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    info!("Port {port_id} set to promiscuous mode");

    let flow_port_attr = dpdk_sys::rte_flow_port_attr {
        nb_conn_tracks: 1,
        host_port_id: 5,
        // nb_meters: 1000,
        // host_port_id: 5,
        // nb_meters: 1,
        // flags: dpdk_sys::rte_flow_port_flag::STRICT_QUEUE,
        ..Default::default()
    };

    let flow_queue_attr = dpdk_sys::rte_flow_queue_attr {
        size: 16,
    };

    let mut flow_configure_error = dpdk_sys::rte_flow_error::default();

    let ret = unsafe {
        dpdk_sys::rte_flow_configure(
            port_id,
            &flow_port_attr,
            1,
            &mut (&flow_queue_attr as *const _),
            &mut flow_configure_error,
        )
    };

    if ret != 0 || !flow_configure_error.message.is_null() {
        if flow_configure_error.message.is_null() {
            let err_str = unsafe { dpdk_sys::rte_strerror(ret) };
            let err_msg = format!(
                "Failed to configure flow engine: {err_str}",
                err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
            );
            fatal_error(err_msg.as_str());
        } else {
            let err_str = unsafe { CStr::from_ptr(flow_configure_error.message) };
            let err_msg = format!(
                "Failed to configure flow engine: {err_str}",
                err_str = err_str.to_str().unwrap()
            );
            fatal_error(err_msg.as_str());
        }
    }

    info!("Flow engine configuration installed");

    let ret = unsafe { dpdk_sys::rte_eth_dev_start(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to start device: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    info!("Port {port_id} started");
    assert_link_status(port_id);
    info!("Port {port_id} has been initialized");
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
fn generate_ct_flow(
    port_id: u16,
    rx_q: u16,
    src_ip: Ipv4Addr,
    src_mask: Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_mask: Ipv4Addr,
    err: &mut dpdk_sys::rte_flow_error,
) -> RteFlow {
    const MAX_PATTERN_NUM: usize = 16;
    const MAX_ACTION_NUM: usize = 16;
    let mut attr: dpdk_sys::rte_flow_attr = Default::default();
    let mut pattern: [dpdk_sys::rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [dpdk_sys::rte_flow_action; MAX_ACTION_NUM] = Default::default();
    let queue = dpdk_sys::rte_flow_action_queue { index: rx_q };

    attr.set_ingress(1);

    pattern[0].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;

    pattern[2].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP;
    let tcp_spec = dpdk_sys::rte_flow_item_tcp {
        hdr: dpdk_sys::rte_tcp_hdr {
            dst_port: 80,
            ..Default::default()
        },
    };
    pattern[2].spec = &tcp_spec as *const _ as *const _;

    pattern[3].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_CONNTRACK;
    let conntrack_spec = dpdk_sys::rte_flow_item_conntrack {
        flags: dpdk_sys::rte_flow_conntrack_tcp_last_index::RTE_FLOW_CONNTRACK_FLAG_SYN,
    };
    pattern[3].spec = &conntrack_spec as *const _ as *const _;

    pattern[4].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;


    action[0].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue as *const _ as *const _;
    action[1].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    let res = unsafe {
        dpdk_sys::rte_flow_validate(
            port_id,
            &attr as *const _,
            pattern.as_ptr(),
            action.as_ptr(),
            err,
        )
    };

    if res != 0 {
        let err_str = unsafe { dpdk_sys::rte_strerror(res) };
        let err_msg = format!(
            "Failed to validate flow: {err_str}",
            err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
        );
        fatal_error(err_msg.as_str());
    }

    let flow = unsafe {
        dpdk_sys::rte_flow_create(
            port_id,
            &attr as *const _,
            pattern.as_ptr() as *const _,
            action.as_ptr() as *const _,
            err,
        )
    };

    if flow.is_null() || !err.message.is_null() {
        if err.message.is_null() {
            fatal_error("Failed to create flow: unknown error");
        }
        let err_str = unsafe { CStr::from_ptr(err.message) };
        fatal_error(err_str.to_str().unwrap());
    }

    debug!("Flow created");

    RteFlow::new(port_id, flow)
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug"))]
fn generate_ct_flow2(
    port_id: u16,
    rx_q: u16,
    err: &mut dpdk_sys::rte_flow_error,
) -> RteFlow {
    const MAX_PATTERN_NUM: usize = 16;
    const MAX_ACTION_NUM: usize = 16;
    let mut attr: dpdk_sys::rte_flow_attr = Default::default();
    attr.group = 1;
    attr.set_ingress(1);
    let mut pattern: [dpdk_sys::rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [dpdk_sys::rte_flow_action; MAX_ACTION_NUM] = Default::default();
    let queue = dpdk_sys::rte_flow_action_queue { index: rx_q };

    pattern[0].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;

    pattern[2].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP;
    let tcp_spec = dpdk_sys::rte_flow_item_tcp {
        hdr: dpdk_sys::rte_tcp_hdr {
            dst_port: 80,
            tcp_flags: dpdk_sys::RTE_TCP_SYN_FLAG as u8,
            ..Default::default()
        },
    };
    pattern[2].spec = &tcp_spec as *const _ as *const _;

    pattern[3].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_CONNTRACK;
    let conntrack_spec = dpdk_sys::rte_flow_item_conntrack {
        flags: dpdk_sys::rte_flow_conntrack_tcp_last_index::RTE_FLOW_CONNTRACK_FLAG_NONE,
    };
    pattern[3].spec = &conntrack_spec as *const _ as *const _;

    pattern[4].type_ = dpdk_sys::rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;

    action[0].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_CONNTRACK;
    let mut contrack_action = dpdk_sys::rte_flow_action_conntrack::default();
    contrack_action.set_enable(1);
    // contrack_action.set_is_original_dir(1);
    contrack_action.state = dpdk_sys::rte_flow_conntrack_state::RTE_FLOW_CONNTRACK_STATE_SYN_RECV;
    action[0].conf = &contrack_action as *const _ as *const _;

    action[1].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[1].conf = &queue as *const _ as *const _;
    action[2].type_ = dpdk_sys::rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    info!("Validating flow");

    let res = unsafe {
        dpdk_sys::rte_flow_validate(
            port_id,
            &attr as *const _,
            pattern.as_ptr(),
            action.as_ptr(),
            err,
        )
    };

    if res == 0 {
        info!("Connection tracking flow validated");
    }

    if res != 0 {
        let err_str = unsafe { dpdk_sys::rte_strerror(res) };
        if err.message.is_null() {
            let err_msg = format!(
                "Failed to validate flow: {err_str}",
                err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
            );
            fatal_error(err_msg.as_str());
        } else {
            let flow_err_str = unsafe { CStr::from_ptr(err.message) }.to_str().unwrap();
            let err_msg = format!(
                "Failed to validate flow: {flow_err_str}; {err_str}",
                err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
            );
            fatal_error(err_msg.as_str());
        }
    }

    info!("Creating flow");

    let flow = unsafe {
        dpdk_sys::rte_flow_create(
            port_id,
            &attr as *const _,
            pattern.as_ptr() as *const _,
            action.as_ptr() as *const _,
            err,
        )
    };

    info!("Flow create attempt result: {flow:?}, {err:?}");

    if flow.is_null() || !err.message.is_null() {
        if err.message.is_null() {
            fatal_error("Failed to create flow: unknown error");
        }
        let err_str = unsafe { CStr::from_ptr(err.message) };
        fatal_error(err_str.to_str().unwrap());
    }

    debug!("Flow created");

    RteFlow::new(port_id, flow)
}

fn meter_stuff(port_id: u16) {
    let mut caps = dpdk_sys::rte_mtr_capabilities::default();
    let mut err = dpdk_sys::rte_mtr_error::default();
    let ret = unsafe {
        dpdk_sys::rte_mtr_capabilities_get(port_id, &mut caps, &mut err)
    };

    if ret != 0 || !err.message.is_null() {
        let io_error_msg = io::Error::from_raw_os_error(ret).to_string();
        let err_msg = if err.message.is_null() {
            format!(
                "Failed to get meter capabilities: {io_error_msg}",
            )
        } else {
            let err_str = unsafe { CStr::from_ptr(err.message) };
            format!(
                "Failed to get meter capabilities: {err_str}; {io_error_msg}",
                err_str = err_str.to_str().unwrap()
            )
        };
    }

    info!("Meter capabilities: {caps:?}");

}
