// Trace point and and trace point register need to be included before other headers
#include <rte_trace_point_register.h>
#include <rte_trace_point.h>

#include <rte_alarm.h>
#include <rte_arp.h>
#include <rte_atomic.h>
#include <rte_bitmap.h>
#include <rte_bitops.h>
#include <rte_branch_prediction.h>
#include <rte_build_config.h>
#include <rte_bus.h>
#include <rte_bus_pci.h>
#include <rte_bus_vdev.h>
#include <rte_byteorder.h>
#include <rte_class.h>
#include <rte_cman.h>
#include <rte_common.h>
#include <rte_compat.h>
#include <rte_config.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_dev_info.h>
#include <rte_devargs.h>
#include <rte_dtls.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_eal_trace.h>
#include <rte_ecpri.h>
#include <rte_epoll.h>
#include <rte_errno.h>
#include <rte_esp.h>
#include <rte_eth_ctrl.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_ethdev_core.h>
#include <rte_ethdev_trace_fp.h>
#include <rte_ether.h>
#include <rte_fbarray.h>
#include <rte_fbk_hash.h>
#include <rte_flow.h>
#include <rte_geneve.h>
#include <rte_gre.h>
#include <rte_gtp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_hexdump.h>
#include <rte_higig.h>
#include <rte_hypervisor.h>
#include <rte_ib.h>
#include <rte_icmp.h>
#include <rte_interrupts.h>
#include <rte_io.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_keepalive.h>
#include <rte_kvargs.h>
#include <rte_l2tpv2.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_lock_annotations.h>
#include <rte_log.h>
#include <rte_macsec.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_mbuf_ptype.h>
#include <rte_mcslock.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mempool_trace_fp.h>
#include <rte_memzone.h>
#include <rte_meter.h>
#include <rte_mpls.h>
#include <rte_mtr.h>
#include <rte_net.h>
#include <rte_net_crc.h>
#include <rte_os.h>
#include <rte_pause.h>
#include <rte_pci.h>
#include <rte_pci_dev_feature_defs.h>
#include <rte_pci_dev_features.h>
#include <rte_pdcp_hdr.h>
#include <rte_per_lcore.h>
#include <rte_pflock.h>
#include <rte_pmd_mlx5.h>
#include <rte_power_intrinsics.h>
#include <rte_ppp.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_rcu_qsbr.h>
#include <rte_reciprocal.h>
#include <rte_ring.h>
#include <rte_ring_core.h>
#include <rte_ring_elem.h>
#include <rte_ring_elem_pvt.h>
#include <rte_ring_hts.h>
#include <rte_ring_peek.h>
#include <rte_ring_peek_zc.h>
#include <rte_ring_rts.h>
#include <rte_rtm.h>
#include <rte_rwlock.h>
#include <rte_sctp.h>
#include <rte_seqcount.h>
#include <rte_seqlock.h>
#include <rte_service.h>
#include <rte_service_component.h>
#include <rte_spinlock.h>
#include <rte_stack.h>
#include <rte_stdatomic.h>
#include <rte_string_fns.h>
#include <rte_tailq.h>
#include <rte_tcp.h>
#include <rte_telemetry.h>
#include <rte_thash.h>
#include <rte_thash_gfni.h>
#include <rte_thash_x86_gfni.h>
#include <rte_thread.h>
#include <rte_ticketlock.h>
#include <rte_time.h>
#include <rte_tls.h>
#include <rte_tm.h>
#include <rte_trace.h>
#include <rte_udp.h>
#include <rte_uuid.h>
#include <rte_vect.h>
#include <rte_version.h>
#include <rte_vfio.h>
#include <rte_vxlan.h>

//int const rte_get_errno();

//enum rte_eth_tx_offload: uint64_t {
//  VLAN_INSERT      = RTE_ETH_TX_OFFLOAD_VLAN_INSERT,
//  IPV4_CKSUM       = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
//  UDP_CKSUM        = RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
//  TCP_CKSUM        = RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
//  SCTP_CKSUM       = RTE_ETH_TX_OFFLOAD_SCTP_CKSUM,
//  TCP_TSO          = RTE_ETH_TX_OFFLOAD_TCP_TSO,
//  UDP_TSO          = RTE_ETH_TX_OFFLOAD_UDP_TSO,
//  OUTER_IPV4_CKSUM = RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM,
//  QINQ_INSERT      = RTE_ETH_TX_OFFLOAD_QINQ_INSERT,
//  VXLAN_TNL_TSO    = RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO,
//  GRE_TNL_TSO      = RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO,
//  IPIP_TNL_TSO     = RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO,
//  GENEVE_TNL_TSO   = RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO,
//  MACSEC_INSERT    = RTE_ETH_TX_OFFLOAD_MACSEC_INSERT,
//};

//enum rte_flow_port_flag: uint32_t {
//  /**
//   * Indicate all operations for a given flow rule will _strictly_
//   * happen on the same queue (create/destroy/query/update).
//   */
//  STRICT_QUEUE = RTE_FLOW_PORT_FLAG_STRICT_QUEUE,
//
//  /**
//   * Indicate all steering objects should be created on contexts
//   * of the host port, providing indirect object sharing between
//   * ports.
//   */
//  SHARE_INDIRECT = RTE_FLOW_PORT_FLAG_SHARE_INDIRECT
//};




// Things which are either duplicated, totally inapplicable or not needed
//#include <cmdline.h>
//#include <cmdline_cirbuf.h>
//#include <cmdline_parse.h>
//#include <cmdline_parse_etheraddr.h>
//#include <cmdline_parse_ipaddr.h>
//#include <cmdline_parse_num.h>
//#include <cmdline_parse_portlist.h>
//#include <cmdline_parse_string.h>
//#include <cmdline_rdline.h>
//#include <cmdline_socket.h>
//#include <cmdline_vt100.h>
//#include <generic/rte_atomic.h>
//#include <generic/rte_byteorder.h>
//#include <generic/rte_cpuflags.h>
//#include <generic/rte_cycles.h>
//#include <generic/rte_io.h>
//#include <generic/rte_memcpy.h>
//#include <generic/rte_pause.h>
//#include <generic/rte_power_intrinsics.h>
//#include <generic/rte_prefetch.h>
//#include <generic/rte_rwlock.h>
//#include <generic/rte_spinlock.h>
//#include <generic/rte_vect.h>
//#include <rte_atomic_32.h>
//#include <rte_atomic_64.h>
//#include <rte_byteorder_32.h>
//#include <rte_byteorder_64.h>
//#include <rte_crc_arm64.h>
//#include <rte_crc_generic.h>
//#include <rte_crc_sw.h>
//#include <rte_crc_x86.h>
//#include <rte_flow_driver.h> // this is an internal header
//#include <rte_mtr_driver.h>
//#include <rte_ring_c11_pvt.h>
//#include <rte_ring_generic_pvt.h>
//#include <rte_ring_hts_elem_pvt.h>
//#include <rte_ring_peek_elem_pvt.h>
//#include <rte_ring_rts_elem_pvt.h>
//#include <rte_stack_lf.h>
//#include <rte_stack_lf_c11.h>
//#include <rte_stack_lf_generic.h>
//#include <rte_stack_lf_stubs.h>
//#include <rte_stack_std.h>
//#include <rte_tm_driver.h>
