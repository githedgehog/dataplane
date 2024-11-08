// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dpdk::dev::TxOffloadConfig;
use dpdk::{dev, eal, mem, queue, socket};
use dpdk_sys::*;
use std::ffi::{c_uint, CStr, CString};
use std::fmt::{Debug, Display};
use std::io;
use std::net::Ipv4Addr;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};

#[tracing::instrument(level = "trace", ret)]
// TODO: proper safety.  This should return a Result but I'm being a savage for demo purposes.
fn as_cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

// #[derive(Debug)]
// struct Eal;
//
// impl Eal {
//     #[tracing::instrument(level = "trace", ret)]
//     /// Initializes the DPDK Environment Abstraction Layer (EAL).
//     ///
//     /// TODO: proper safety analysis (in a hurry for demo purposes)
//     pub fn new<T: Debug + AsRef<str>>(args: Vec<T>) -> Eal {
//         {
//             let args: Vec<_> = args.iter().map(|s| as_cstr(s.as_ref())).collect();
//             let mut cargs: Vec<_> = args.iter().map(|s| s.as_ptr() as *mut c_char).collect();
//             let len = cargs.len() as c_int;
//             let exit_code = unsafe { rte_eal_init(len, cargs.as_mut_ptr()) };
//             /// TODO: this is a poor error message
//             if exit_code < 0 {
//                 unsafe { rte_exit(exit_code, cstr_literal!("Invalid EAL arguments")) };
//             }
//             info!("EAL initialization successful: {exit_code}");
//         }
//         Self
//     }
// }

/// Exits the DPDK application with an error message, cleaning up the EAL as gracefully as
/// possible (by way of [`rte_exit`]).
///
/// This function never returns as it exits the application.
pub fn fatal_error<T: Display + AsRef<str>>(message: T) -> ! {
    error!("{message}");
    let message_cstring = as_cstr(message.as_ref());
    unsafe { rte_exit(1, message_cstring.as_ptr()) }
}

const MAX_PATTERN_NUM: usize = 8;

#[tracing::instrument(level = "debug")]
fn generate_ipv4_flow(
    port_id: u16,
    rx_q: u16,
    src_ip: Ipv4Addr,
    src_mask: Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_mask: Ipv4Addr,
    err: &mut rte_flow_error,
) -> RteFlow {
    let mut attr: rte_flow_attr = Default::default();
    let mut pattern: [rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [rte_flow_action; MAX_PATTERN_NUM] = Default::default();
    let queue = rte_flow_action_queue { index: rx_q };

    attr.set_ingress(1);

    action[0].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue as *const _ as *const _;
    action[1].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;
    let ip_spec = rte_flow_item_ipv4 {
        hdr: rte_ipv4_hdr {
            src_addr: htonl(src_ip),
            dst_addr: htonl(dest_ip),
            ..Default::default()
        },
    };
    let ip_mask = rte_flow_item_ipv4 {
        hdr: rte_ipv4_hdr {
            src_addr: htonl(src_mask),
            dst_addr: htonl(dest_mask),
            ..Default::default()
        },
    };
    pattern[1].spec = &ip_spec as *const _ as *const _;
    pattern[1].mask = &ip_mask as *const _ as *const _;

    pattern[2].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;

    let res = unsafe {
        rte_flow_validate(
            port_id,
            &attr as *const _,
            pattern.as_ptr(),
            action.as_ptr(),
            err,
        )
    };

    if res != 0 {
        let err_str = unsafe { rte_strerror(res) };
        let err_msg = format!(
            "Failed to validate flow: {err_str}",
            err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
        );
        fatal_error(err_msg.as_str());
    }

    let flow = unsafe {
        rte_flow_create(
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
    flow: *mut rte_flow,
}

impl RteFlow {
    // TODO: this is stupid, make a real wrapper
    fn new(port: u16, flow: *mut rte_flow) -> Self {
        Self { port, flow }
    }
}

impl Drop for RteFlow {
    #[tracing::instrument(level = "debug")]
    fn drop(&mut self) {
        if self.flow.is_null() {
            warn!("Attempted to destroy null flow?");
            return;
        }
        let mut err = rte_flow_error::default();
        let res = unsafe { rte_flow_destroy(self.port, self.flow, &mut err) };

        if res == 0 {
            debug!("Flow destroyed");
            return;
        }

        let rte_err = unsafe { wrte_errno() };
        let err_msg = unsafe { CStr::from_ptr(rte_strerror(res)) }
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

#[tracing::instrument(level = "trace")]
fn htonl<T: Debug + Into<u32>>(x: T) -> u32 {
    u32::to_be(x.into())
}

#[tracing::instrument(level = "debug")]
fn check_hairpin_cap(port_id: u16) {
    let mut cap: rte_eth_hairpin_cap = Default::default();
    let ret = unsafe { rte_eth_dev_hairpin_capability_get(port_id, &mut cap) };
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

#[tracing::instrument(level = "info", skip(mbuf_pool))]
fn init_port2(port_id: u16, mbuf_pool: &mut rte_mempool) {
    let mut port_conf = rte_eth_conf {
        txmode: rte_eth_txmode {
            offloads: wrte_eth_tx_offload::VLAN_INSERT
                | wrte_eth_tx_offload::IPV4_CKSUM
                | wrte_eth_tx_offload::UDP_CKSUM
                | wrte_eth_tx_offload::TCP_CKSUM
                | wrte_eth_tx_offload::SCTP_CKSUM
                | wrte_eth_tx_offload::TCP_TSO,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut txq_conf: rte_eth_txconf;
    #[allow(unused)]
    let mut rxq_conf: rte_eth_rxconf = unsafe { std::mem::zeroed() };
    let mut dev_info: rte_eth_dev_info = unsafe { std::mem::zeroed() };

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
    let ret = unsafe { rte_eth_dev_configure(port_id, nr_queues, nr_queues, &port_conf) };

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
            rte_eth_rx_queue_setup(
                port_id,
                queue_num,
                nr_rx_descriptors,
                rte_eth_dev_socket_id(port_id) as c_uint,
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

    let mut rx_hairpin_conf = rte_eth_hairpin_conf::default();
    rx_hairpin_conf.set_peer_count(1);
    rx_hairpin_conf.peers[0].port = port_id;
    rx_hairpin_conf.peers[0].queue = nr_queues - 1;

    let ret =
        unsafe { rte_eth_rx_hairpin_queue_setup(port_id, nr_queues - 1, 0, &rx_hairpin_conf) };

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
            rte_eth_tx_queue_setup(
                port_id,
                queue_num,
                nr_rx_descriptors,
                rte_eth_dev_socket_id(port_id) as c_uint,
                &txq_conf,
            )
        };

        if ret < 0 {
            let err_msg = format!(
                "Failed to configure TX queue {queue_num}: {ret}",
                ret = io::Error::from_raw_os_error(ret)
            );
            fatal_error(err_msg.as_str());
        }
        info!("TX queue {queue_num} configured");
    }

    let mut tx_hairpin_conf = rte_eth_hairpin_conf::default();
    tx_hairpin_conf.set_peer_count(1);
    tx_hairpin_conf.peers[0].port = port_id;
    tx_hairpin_conf.peers[0].queue = nr_queues - 1;

    let ret =
        unsafe { rte_eth_tx_hairpin_queue_setup(port_id, nr_queues - 1, 0, &tx_hairpin_conf) };

    if ret < 0 {
        let err_msg = format!(
            "Failed to configure TX hairpin queue: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    info!("TX hairpin queue configured");

    info!("Port {port_id} configured");

    let ret = unsafe { rte_eth_promiscuous_enable(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to enable promiscuous mode: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }
    info!("Port {port_id} set to promiscuous mode");

    let flow_port_attr = rte_flow_port_attr {
        nb_conn_tracks: 1,
        host_port_id: 5,
        // nb_meters: 1000,
        // host_port_id: 5,
        // nb_meters: 1,
        // flags: rte_flow_port_flag::STRICT_QUEUE,
        ..Default::default()
    };

    let flow_queue_attr = rte_flow_queue_attr { size: 16 };

    let mut flow_configure_error = rte_flow_error::default();

    let ret = unsafe {
        rte_flow_configure(
            port_id,
            &flow_port_attr,
            1,
            &mut (&flow_queue_attr as *const _),
            &mut flow_configure_error,
        )
    };

    if ret != 0 || !flow_configure_error.message.is_null() {
        if flow_configure_error.message.is_null() {
            let err_str = unsafe { rte_strerror(ret) };
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

    let ret = unsafe { rte_eth_dev_start(port_id) };
    if ret != 0 {
        let err_msg = format!(
            "Failed to start device: {ret}",
            ret = io::Error::from_raw_os_error(ret)
        );
        fatal_error(err_msg.as_str());
    }

    info!("Port {port_id} started");
    // assert_link_status(port_id);
    info!("Port {port_id} has been initialized");
}

#[tracing::instrument(level = "debug")]
fn generate_ct_flow(port_id: u16, rx_q: u16, err: &mut rte_flow_error) -> RteFlow {
    const MAX_PATTERN_NUM: usize = 16;
    const MAX_ACTION_NUM: usize = 16;
    let mut attr: rte_flow_attr = Default::default();
    let mut pattern: [rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [rte_flow_action; MAX_ACTION_NUM] = Default::default();
    let queue = rte_flow_action_queue { index: rx_q };

    attr.set_ingress(1);

    pattern[0].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;

    pattern[2].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP;
    let tcp_spec = rte_flow_item_tcp {
        hdr: rte_tcp_hdr {
            dst_port: 80,
            ..Default::default()
        },
    };
    pattern[2].spec = &tcp_spec as *const _ as *const _;

    pattern[3].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_CONNTRACK;
    let conntrack_spec = rte_flow_item_conntrack {
        flags: rte_flow_conntrack_tcp_last_index::RTE_FLOW_CONNTRACK_FLAG_SYN,
    };
    pattern[3].spec = &conntrack_spec as *const _ as *const _;

    pattern[4].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;

    action[0].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue as *const _ as *const _;
    action[1].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    let res = unsafe {
        rte_flow_validate(
            port_id,
            &attr as *const _,
            pattern.as_ptr(),
            action.as_ptr(),
            err,
        )
    };

    if res != 0 {
        let err_str = unsafe { rte_strerror(res) };
        let err_msg = format!(
            "Failed to validate flow: {err_str}",
            err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
        );
        fatal_error(err_msg.as_str());
    }

    let flow = unsafe {
        rte_flow_create(
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

#[tracing::instrument(level = "debug")]
fn generate_ct_flow2(port_id: u16, rx_q: u16, err: &mut rte_flow_error) -> RteFlow {
    const MAX_PATTERN_NUM: usize = 16;
    const MAX_ACTION_NUM: usize = 16;
    let mut attr = rte_flow_attr {
        group: 1,
        ..Default::default()
    };
    attr.set_ingress(1);
    let mut pattern: [rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [rte_flow_action; MAX_ACTION_NUM] = Default::default();
    let queue = rte_flow_action_queue { index: rx_q };

    pattern[0].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;

    pattern[2].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP;
    let tcp_spec = rte_flow_item_tcp {
        hdr: rte_tcp_hdr {
            dst_port: 80,
            tcp_flags: RTE_TCP_SYN_FLAG as u8,
            ..Default::default()
        },
    };
    pattern[2].spec = &tcp_spec as *const _ as _;

    pattern[3].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_CONNTRACK;
    let conntrack_spec = rte_flow_item_conntrack {
        flags: rte_flow_conntrack_tcp_last_index::RTE_FLOW_CONNTRACK_FLAG_NONE,
    };
    pattern[3].spec = &conntrack_spec as *const _ as _;

    pattern[4].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;

    action[0].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_CONNTRACK;
    let mut contrack_action = rte_flow_action_conntrack::default();
    contrack_action.set_enable(1);
    // contrack_action.set_is_original_dir(1);
    contrack_action.state = rte_flow_conntrack_state::RTE_FLOW_CONNTRACK_STATE_SYN_RECV;
    action[0].conf = &contrack_action as *const _ as _;

    action[1].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[1].conf = &queue as *const _ as _;
    action[2].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    info!("Validating flow");

    let res = unsafe {
        rte_flow_validate(
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
        let err_str = unsafe { rte_strerror(res) };
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

    let flow = unsafe { rte_flow_create(port_id, &attr, pattern.as_ptr(), action.as_ptr(), err) };

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

fn main() {
    eal_main();
}

fn eal_main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    let eal_args = vec![
        "-src",
        "0xffffffffff",
        "--in-memory",
        "--huge-dir",
        "/mnt/huge/2M",
        "--huge-dir",
        "/mnt/huge/1G",
        "--allow",
        "0000:85:00.0,dv_flow_en=1",
        // "--trace=.*",
        // "--iova-mode=va",
        // "-l",
        // "8,9,10,11,12,13,14,15",
        // "--allow",
        // "0000:01:00.1",
        "--huge-worker-stack=8192",
        "--socket-mem=4096",
        "--no-telemetry",
    ];

    let rte = eal::init(eal_args).unwrap_or_else(|err| match err {
        eal::InitError::InvalidArguments(args, err_msg) => {
            fatal_error(format!(
                "Invalid arguments: {args:?}; {err_msg}",
                args = args,
                err_msg = err_msg
            ));
        }
        eal::InitError::AlreadyInitialized => {
            fatal_error("EAL already initialized");
        }
        eal::InitError::InitializationFailed(err) => {
            fatal_error(format!("EAL initialization failed: {err:?}"));
        }
        eal::InitError::UnknownError(code) => {
            fatal_error(format!("Unknown error code {code}"));
        }
    });

    let pool = mem::PoolHandle::new_pkt_pool(
        mem::PoolConfig::new("science", mem::PoolParams::default()).unwrap(),
    )
    .unwrap();

    rte.socket.iter().for_each(|socket| {
        info!("Socket: {socket:?}");
    });

    rte.dev.iter().for_each(|dev| {
        info!("Device if_index: {if_index:?}", if_index = dev.if_index());
        info!("Driver name: {name:?}", name = dev.driver_name());
        let tx_config: TxOffloadConfig = dev.tx_offload_caps().into();
        info!(
            "Device tx offload capabilities: {tx_offload:?}",
            tx_offload = tx_config
        );
        info!(
            "Device rx offload capabilities: {rx_offload:?}",
            rx_offload = dev.rx_offload_caps()
        );

        let config = dev::DevConfig {
            num_rx_queues: 5,
            num_tx_queues: 5,
            num_hairpin_queues: 1,
            tx_offloads: Some(TxOffloadConfig::default()),
        };

        let mut my_dev = match config.apply(dev) {
            Ok(stopped_dev) => {
                warn!("Device configured {stopped_dev:?}");
                stopped_dev
            }
            Err(err) => {
                fatal_error(format!("Failed to configure device: {err:?}"));
            }
        };

        let rx_config = queue::rx::RxQueueConfig {
            dev: my_dev.info.index(),
            queue_index: queue::rx::RxQueueIndex(0),
            num_descriptors: 512,
            socket_preference: socket::Preference::Dev(my_dev.info.index()),
            config: (),
            pool: pool.clone(),
        };

        let tx_config = queue::tx::TxQueueConfig {
            queue_index: queue::tx::TxQueueIndex(0),
            num_descriptors: 512,
            socket_preference: socket::Preference::Dev(my_dev.info.index()),
            config: (),
        };

        my_dev.configure_rx_queue(rx_config).unwrap();
        my_dev.configure_tx_queue(tx_config).unwrap();

        let rx_config = queue::rx::RxQueueConfig {
            dev: my_dev.info.index(),
            queue_index: queue::rx::RxQueueIndex(1),
            num_descriptors: 512,
            socket_preference: socket::Preference::Dev(my_dev.info.index()),
            config: (),
            pool: pool.clone(),
        };

        let tx_config = queue::tx::TxQueueConfig {
            queue_index: queue::tx::TxQueueIndex(1),
            num_descriptors: 512,
            socket_preference: socket::Preference::Dev(my_dev.info.index()),
            config: (),
        };

        my_dev
            .configure_hairpin_queue(rx_config, tx_config)
            .unwrap();
        my_dev.start().unwrap();

        let mut start = Instant::now();

        for i in 0..50_000_000 {
            if i % 100_000 == 0 {
                let stop = Instant::now();
                let elapsed = stop.duration_since(start);
                warn!(
                    "{i} rules installed, rate: {rate:.1}k / second",
                    rate = 100.0 / elapsed.as_secs_f64()
                );
                start = Instant::now();
            }
            let src = Ipv4Addr::from(i);
            let dst = Ipv4Addr::from(rand::random::<u32>());
            let mut err = rte_flow_error::default();
            generate_modify_field_flow(
                i,
                my_dev.info.index().0,
                0,
                src,
                Ipv4Addr::new(255, 255, 255, 255),
                dst,
                Ipv4Addr::new(255, 255, 255, 255),
                &mut err,
            );
        }

        warn!("Flows created");

        // for i in 0..2000 {
        //     let flow0 = generate_modify_field_flow(
        //         my_dev.info.index().0,
        //         0,
        //         Ipv4Addr::new(192, 168, 1, 1),
        //         Ipv4Addr::new(255, 255, 255, 255),
        //         Ipv4Addr::new(192, 168, 1, 2),
        //         Ipv4Addr::new(255, 255, 255, 255),
        //         &mut err,
        //     );
        //     let flow1 = generate_modify_field_flow(
        //         my_dev.info.index().0,
        //         0,
        //         Ipv4Addr::new(192, 168, 1, 1),
        //         Ipv4Addr::new(255, 255, 255, 255),
        //         Ipv4Addr::new(192, 168, 1, 2),
        //         Ipv4Addr::new(255, 255, 255, 255),
        //         &mut err,
        //     );
        //     let flow2 = generate_modify_field_flow(
        //         my_dev.info.index().0,
        //         0,
        //         Ipv4Addr::new(192, 168, 1, 1),
        //         Ipv4Addr::new(255, 255, 255, 255),
        //         Ipv4Addr::new(192, 168, 1, 2),
        //         Ipv4Addr::new(255, 255, 255, 255),
        //         &mut err,
        //     );
        // }
    });
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug")]
fn generate_modify_field_flow(
    i: u32,
    port_id: u16,
    rx_q: u16,
    src_ip: Ipv4Addr,
    src_mask: Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_mask: Ipv4Addr,
    err: &mut rte_flow_error,
) -> RteFlow {
    let mut attr: rte_flow_attr = rte_flow_attr {
        group: 99u32,
        priority: 9,
        ..Default::default()
    };
    attr.set_ingress(1);
    let mut pattern: [rte_flow_item; MAX_PATTERN_NUM] = Default::default();
    let mut action: [rte_flow_action; MAX_PATTERN_NUM] = Default::default();
    let queue = rte_flow_action_queue { index: rx_q };

    pattern[0].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_ETH;

    let mut eth_spec = rte_flow_item_eth::default();
    #[allow(unused_unsafe)]
    unsafe {
        eth_spec.annon1.hdr.dst_addr = rte_ether_addr {
            addr_bytes: [
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
            ],
        };
    }
    #[allow(unused_unsafe)]
    unsafe {
        eth_spec.annon1.hdr.src_addr = rte_ether_addr {
            addr_bytes: [
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
                rand::random::<u8>(),
            ],
        }
    }

    let mut eth_mask = rte_flow_item_eth::default();

    #[allow(unused_unsafe)]
    unsafe {
        eth_mask.annon1.hdr.dst_addr = rte_ether_addr {
            addr_bytes: [0xff; 6],
        };
        eth_mask.annon1.hdr.src_addr = rte_ether_addr {
            addr_bytes: [0xff; 6],
        };
    }

    pattern[0].spec = &eth_spec as *const _ as *const _;
    pattern[0].mask = &eth_mask as *const _ as *const _;

    pattern[1].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_IPV4;
    let ip_spec = rte_flow_item_ipv4 {
        hdr: rte_ipv4_hdr {
            src_addr: htonl(src_ip),
            dst_addr: htonl(dest_ip),
            ..Default::default()
        },
    };
    let ip_mask = rte_flow_item_ipv4 {
        hdr: rte_ipv4_hdr {
            src_addr: htonl(src_mask),
            dst_addr: htonl(dest_mask),
            ..Default::default()
        },
    };
    pattern[1].spec = &ip_spec as *const _ as *const _;
    pattern[1].mask = &ip_mask as *const _ as *const _;

    pattern[2].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_TCP;
    let tcp_spec = rte_flow_item_tcp {
        hdr: rte_tcp_hdr {
            dst_port: rand::random::<u16>(),
            ..Default::default()
        },
    };
    let tcp_mask = rte_flow_item_tcp {
        hdr: rte_tcp_hdr {
            dst_port: u16::MAX,
            ..Default::default()
        },
    };

    pattern[2].spec = &tcp_spec as *const _ as *const _;
    pattern[2].mask = &tcp_mask as *const _ as *const _;

    pattern[3].type_ = rte_flow_item_type::RTE_FLOW_ITEM_TYPE_END;

    let new_src_ip = Ipv4Addr::from(rand::random::<u32>());
    let mut ip_src_value = [0u8; 16];
    ip_src_value[0..4].copy_from_slice(&new_src_ip.to_bits().to_be_bytes());

    let new_dst_ip = Ipv4Addr::from(rand::random::<u32>());
    let mut ip_dst_value = [0u8; 16];
    ip_dst_value[0..4].copy_from_slice(&new_dst_ip.to_bits().to_be_bytes());

    let new_eth_dst = [
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    let modify_eth_src_action_conf = rte_flow_action_modify_field {
        operation: rte_flow_modify_op::RTE_FLOW_MODIFY_SET,
        src: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_VALUE,
            annon1: rte_flow_field_data__bindgen_ty_1 { value: new_eth_dst },
        },
        dst: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_MAC_SRC,
            annon1: rte_flow_field_data__bindgen_ty_1::default(),
        },
        width: size_of::<rte_ether_addr>() as u32,
    };

    let modify_eth_dst_action_conf = rte_flow_action_modify_field {
        operation: rte_flow_modify_op::RTE_FLOW_MODIFY_SET,
        src: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_VALUE,
            annon1: rte_flow_field_data__bindgen_ty_1 { value: new_eth_dst },
        },
        dst: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_MAC_DST,
            annon1: rte_flow_field_data__bindgen_ty_1::default(),
        },
        width: size_of::<rte_ether_addr>() as u32,
    };

    let modify_ipv4_src_action_conf = rte_flow_action_modify_field {
        operation: rte_flow_modify_op::RTE_FLOW_MODIFY_SET,
        src: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_VALUE,
            annon1: rte_flow_field_data__bindgen_ty_1 {
                value: ip_src_value,
            },
        },
        dst: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_IPV4_SRC,
            annon1: rte_flow_field_data__bindgen_ty_1::default(),
        },
        width: size_of::<Ipv4Addr>() as u32,
    };

    let modify_ipv4_dst_action_conf = rte_flow_action_modify_field {
        operation: rte_flow_modify_op::RTE_FLOW_MODIFY_SET,
        src: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_VALUE,
            annon1: rte_flow_field_data__bindgen_ty_1 {
                value: ip_dst_value,
            },
        },
        dst: rte_flow_field_data {
            field: rte_flow_field_id::RTE_FLOW_FIELD_IPV4_DST,
            annon1: rte_flow_field_data__bindgen_ty_1::default(),
        },
        width: size_of::<Ipv4Addr>() as u32,
    };

    action[0].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_COUNT;
    action[0].conf = &rte_flow_action_count { id: i } as *const _ as *const _;

    action[1].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD;
    action[1].conf = &modify_eth_src_action_conf as *const _ as *const _;

    action[2].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD;
    action[2].conf = &modify_eth_dst_action_conf as *const _ as *const _;

    action[3].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD;
    action[3].conf = &modify_ipv4_src_action_conf as *const _ as *const _;

    action[4].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_MODIFY_FIELD;
    action[4].conf = &modify_ipv4_dst_action_conf as *const _ as *const _;

    action[5].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_QUEUE;
    action[5].conf = &queue as *const _ as *const _;

    action[6].type_ = rte_flow_action_type::RTE_FLOW_ACTION_TYPE_END;

    // let res = unsafe {
    //     rte_flow_validate(
    //         port_id,
    //         &attr as *const _,
    //         pattern.as_ptr(),
    //         action.as_ptr(),
    //         err,
    //     )
    // };
    //
    // if res != 0 {
    //     let err_str = unsafe { rte_strerror(res) };
    //     let err_msg = format!(
    //         "Failed to validate flow: {err_str}",
    //         err_str = unsafe { CStr::from_ptr(err_str) }.to_str().unwrap()
    //     );
    //     fatal_error(err_msg.as_str());
    // } else {
    //     trace!("Flow validated");
    // }

    let flow = unsafe {
        rte_flow_create(
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
    } else {
        trace!("Flow created");
    }

    info!("Flow created");

    RteFlow::new(port_id, flow)
}
