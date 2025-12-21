// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#include <rte_config.h>

#include <rte_alarm.h>
#include <rte_atomic.h>
#include <rte_bitmap.h>
#include <rte_bitops.h>
#include <rte_bitset.h>
#include <rte_branch_prediction.h>
#include <rte_build_config.h>
#include <rte_bus.h>
#include <rte_bus_pci.h>
#include <rte_bus_vdev.h>
#include <rte_byteorder.h>
#include <rte_cksum.h>
#include <rte_class.h>
#include <rte_cman.h>
#include <rte_common.h>
#include <rte_compat.h>
#include <rte_cpuflags.h>
#include <rte_crypto.h>
#include <rte_crypto_asym.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_core.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_dev_info.h>
#include <rte_devargs.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_ecpri.h>
#include <rte_epoll.h>
#include <rte_errno.h>
#include <rte_esp.h>
#include <rte_eth_ctrl.h>
#include <rte_eth_ring.h>
#include <rte_eth_vhost.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_event_crypto_adapter.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_event_ring.h>
#include <rte_event_timer_adapter.h>
#include <rte_event_vector_adapter.h>
#include <rte_eventdev.h>
#include <rte_eventdev_core.h>
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
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_jhash.h>
#include <rte_keepalive.h>
#include <rte_kvargs.h>
#include <rte_l2tpv2.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_lcore_var.h>
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
#include <rte_pmd_i40e.h>
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
#include <rte_ring_hts.h>
#include <rte_ring_peek.h>
#include <rte_ring_peek_zc.h>
#include <rte_ring_rts.h>
// #include <rte_rtm.h>
#include <rte_rwlock.h>
#include <rte_security.h>
#include <rte_seqcount.h>
#include <rte_seqlock.h>
#include <rte_service.h>
#include <rte_service_component.h>
#include <rte_soring.h>
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
#include <rte_timer.h>
#include <rte_tls.h>
#include <rte_tm.h>
#include <rte_udp.h>
#include <rte_vdpa.h>
#include <rte_vect.h>
#include <rte_version.h>
#include <rte_vfio.h>
#include <rte_vhost.h>
#include <rte_vhost_async.h>
#include <rte_vhost_crypto.h>
#include <rte_vxlan.h>

// Things which are either duplicated, totally inapplicable or not needed
// #include <cmdline.h>
// #include <cmdline_cirbuf.h>
// #include <cmdline_parse.h>
// #include <cmdline_parse_etheraddr.h>
// #include <cmdline_parse_ipaddr.h>
// #include <cmdline_parse_num.h>
// #include <cmdline_parse_portlist.h>
// #include <cmdline_parse_string.h>
// #include <cmdline_rdline.h>
// #include <cmdline_socket.h>
// #include <cmdline_vt100.h>
// #include <generic/rte_atomic.h>
// #include <generic/rte_byteorder.h>
// #include <generic/rte_cpuflags.h>
// #include <generic/rte_cycles.h>
// #include <generic/rte_io.h>
// #include <generic/rte_memcpy.h>
// #include <generic/rte_pause.h>
// #include <generic/rte_power_intrinsics.h>
// #include <generic/rte_prefetch.h>
// #include <generic/rte_rwlock.h>
// #include <generic/rte_spinlock.h>
// #include <generic/rte_vect.h>
// #include <rte_arp.h>
// #include <rte_atomic_32.h>
// #include <rte_atomic_64.h>
// #include <rte_byteorder_32.h>
// #include <rte_byteorder_64.h>
// #include <rte_crc_arm64.h>
// #include <rte_crc_generic.h>
// #include <rte_crc_sw.h>
// #include <rte_crc_x86.h>
// #include <rte_dtls.h>
// #include <rte_ecpri.h>
// #include <rte_esp.h>
// #include <rte_ether.h>
// #include <rte_flow_driver.h> // this is an internal header
// #include <rte_geneve.h>
// #include <rte_gre.h>
// #include <rte_gtp.h>
// #include <rte_higig.h>
// #include <rte_ib.h>
// #include <rte_ip.h>
// #include <rte_l2tpv2.h>
// #include <rte_log.h>
// #include <rte_macsec.h>
// #include <rte_mpls.h>
// #include <rte_mtr_driver.h>
// #include <rte_net.h>
// #include <rte_pdcp_hdr.h>
// #include <rte_ppp.h>
// #include <rte_ring_c11_pvt.h>
// #include <rte_ring_generic_pvt.h>
// #include <rte_ring_hts_elem_pvt.h>
// #include <rte_ring_peek_elem_pvt.h>
// #include <rte_ring_rts_elem_pvt.h>
// #include <rte_sctp.h>
// #include <rte_stack_lf.h>
// #include <rte_stack_lf_c11.h>
// #include <rte_stack_lf_generic.h>
// #include <rte_stack_lf_stubs.h>
// #include <rte_stack_std.h>
// #include <rte_tcp.h>
// #include <rte_telemetry.h>
// #include <rte_tls.h>
// #include <rte_tm_driver.h>
// #include <rte_udp.h>
// #include <rte_uuid.h>
// #include <rte_vxlan.h>

// #include <rte_mempool_trace_fp.h>
// #include <rte_eal_trace.h>
// #include <rte_trace.h>
// #include <rte_ethdev_trace_fp.h>

/**
 * Thin wrapper to expose `rte_errno`.
 *
 * @return
 *   The last rte_errno value (thread local value).
 */
int rte_errno_get();

/**
 * TX offloads to be set in [`rte_eth_tx_mode.offloads`].
 *
 * This is a bitfield.  Union these to enable multiple offloads.
 *
 * I wrapped these because the enum must be explicitly typed as 64 bit, but
 * DPDK is not yet using the C23 standard (which would allow the inheritance
 * notation with `uint64_t` seen here.).
 */
enum rte_eth_tx_offload : uint64_t {
  TX_OFFLOAD_VLAN_INSERT = RTE_ETH_TX_OFFLOAD_VLAN_INSERT,
  TX_OFFLOAD_IPV4_CKSUM = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
  TX_OFFLOAD_UDP_CKSUM = RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
  TX_OFFLOAD_TCP_CKSUM = RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
  TX_OFFLOAD_SCTP_CKSUM = RTE_ETH_TX_OFFLOAD_SCTP_CKSUM,
  TX_OFFLOAD_TCP_TSO = RTE_ETH_TX_OFFLOAD_TCP_TSO,
  TX_OFFLOAD_UDP_TSO = RTE_ETH_TX_OFFLOAD_UDP_TSO,
  TX_OFFLOAD_OUTER_IPV4_CKSUM = RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM,
  TX_OFFLOAD_QINQ_INSERT = RTE_ETH_TX_OFFLOAD_QINQ_INSERT,
  TX_OFFLOAD_VXLAN_TNL_TSO = RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO,
  TX_OFFLOAD_GRE_TNL_TSO = RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO,
  TX_OFFLOAD_IPIP_TNL_TSO = RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO,
  TX_OFFLOAD_GENEVE_TNL_TSO = RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO,
  TX_OFFLOAD_MACSEC_INSERT = RTE_ETH_TX_OFFLOAD_MACSEC_INSERT,
  TX_OFFLOAD_MT_LOCKFREE = RTE_ETH_TX_OFFLOAD_MT_LOCKFREE,
  TX_OFFLOAD_MULTI_SEGS = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
  TX_OFFLOAD_MBUF_FAST_FREE = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
  TX_OFFLOAD_SECURITY = RTE_ETH_TX_OFFLOAD_SECURITY,
  TX_OFFLOAD_UDP_TNL_TSO = RTE_ETH_TX_OFFLOAD_UDP_TNL_TSO,
  TX_OFFLOAD_IP_TNL_TSO = RTE_ETH_TX_OFFLOAD_IP_TNL_TSO,
  TX_OFFLOAD_OUTER_UDP_CKSUM = RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM,
  TX_OFFLOAD_SEND_ON_TIMESTAMP = RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP
};

/**
 * RX offloads to be set in [`rte_eth_rx_mode.offloads`].
 *
 * This is a bitfield.  Union these to enable multiple offloads.
 *
 * I wrapped these because the enum must be explicitly typed as 64 bit, but
 * DPDK is not yet using the C23 standard (which would allow the inheritance
 * notation with `uint64_t` seen here.).
 */
enum wrte_eth_rx_offload : uint64_t {
  RX_OFFLOAD_VLAN_STRIP = RTE_ETH_RX_OFFLOAD_VLAN_STRIP,
  RX_OFFLOAD_IPV4_CKSUM = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM,
  RX_OFFLOAD_UDP_CKSUM = RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
  RX_OFFLOAD_TCP_CKSUM = RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
  RX_OFFLOAD_TCP_LRO = RTE_ETH_RX_OFFLOAD_TCP_LRO,
  RX_OFFLOAD_QINQ_STRIP = RTE_ETH_RX_OFFLOAD_QINQ_STRIP,
  RX_OFFLOAD_OUTER_IPV4_CKSUM = RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM,
  RX_OFFLOAD_MACSEC_STRIP = RTE_ETH_RX_OFFLOAD_MACSEC_STRIP,
  RX_OFFLOAD_VLAN_FILTER = RTE_ETH_RX_OFFLOAD_VLAN_FILTER,
  RX_OFFLOAD_VLAN_EXTEND = RTE_ETH_RX_OFFLOAD_VLAN_EXTEND,
  RX_OFFLOAD_SCATTER = RTE_ETH_RX_OFFLOAD_SCATTER,
  RX_OFFLOAD_TIMESTAMP = RTE_ETH_RX_OFFLOAD_TIMESTAMP,
  RX_OFFLOAD_SECURITY = RTE_ETH_RX_OFFLOAD_SECURITY,
  RX_OFFLOAD_KEEP_CRC = RTE_ETH_RX_OFFLOAD_KEEP_CRC,
  RX_OFFLOAD_SCTP_CKSUM = RTE_ETH_RX_OFFLOAD_SCTP_CKSUM,
  RX_OFFLOAD_OUTER_UDP_CKSUM = RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM,
  RX_OFFLOAD_RSS_HASH = RTE_ETH_RX_OFFLOAD_RSS_HASH,
  RX_OFFLOAD_BUFFER_SPLIT = RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT,
};
