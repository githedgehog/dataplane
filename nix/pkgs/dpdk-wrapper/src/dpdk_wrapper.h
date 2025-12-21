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
enum rte_eth_rx_offload : uint64_t {
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


int rte_errno_get() { return rte_errno; }

// Static wrappers

int rte_is_aligned_w(const void *const ptr, const unsigned int align) {
  return rte_is_aligned(ptr, align);
}
void rte_atomic_thread_fence_w(rte_memory_order memorder) {
  rte_atomic_thread_fence(memorder);
}
int rte_atomic16_cmpset_w(uint16_t *dst, uint16_t exp, uint16_t src) {
  return rte_atomic16_cmpset(dst, exp, src);
}
uint16_t rte_atomic16_exchange_w(uint16_t *dst, uint16_t val) {
  return rte_atomic16_exchange(dst, val);
}
void rte_atomic16_init_w(rte_atomic16_t *v) { rte_atomic16_init(v); }
int16_t rte_atomic16_read_w(const rte_atomic16_t *v) {
  return rte_atomic16_read(v);
}
void rte_atomic16_set_w(rte_atomic16_t *v, int16_t new_value) {
  rte_atomic16_set(v, new_value);
}
void rte_atomic16_add_w(rte_atomic16_t *v, int16_t inc) {
  rte_atomic16_add(v, inc);
}
void rte_atomic16_sub_w(rte_atomic16_t *v, int16_t dec) {
  rte_atomic16_sub(v, dec);
}
void rte_atomic16_inc_w(rte_atomic16_t *v) { rte_atomic16_inc(v); }
void rte_atomic16_dec_w(rte_atomic16_t *v) { rte_atomic16_dec(v); }
int16_t rte_atomic16_add_return_w(rte_atomic16_t *v, int16_t inc) {
  return rte_atomic16_add_return(v, inc);
}
int16_t rte_atomic16_sub_return_w(rte_atomic16_t *v, int16_t dec) {
  return rte_atomic16_sub_return(v, dec);
}
int rte_atomic16_inc_and_test_w(rte_atomic16_t *v) {
  return rte_atomic16_inc_and_test(v);
}
int rte_atomic16_dec_and_test_w(rte_atomic16_t *v) {
  return rte_atomic16_dec_and_test(v);
}
int rte_atomic16_test_and_set_w(rte_atomic16_t *v) {
  return rte_atomic16_test_and_set(v);
}
void rte_atomic16_clear_w(rte_atomic16_t *v) { rte_atomic16_clear(v); }
int rte_atomic32_cmpset_w(uint32_t *dst, uint32_t exp, uint32_t src) {
  return rte_atomic32_cmpset(dst, exp, src);
}
uint32_t rte_atomic32_exchange_w(uint32_t *dst, uint32_t val) {
  return rte_atomic32_exchange(dst, val);
}
void rte_atomic32_init_w(rte_atomic32_t *v) { rte_atomic32_init(v); }
int32_t rte_atomic32_read_w(const rte_atomic32_t *v) {
  return rte_atomic32_read(v);
}
void rte_atomic32_set_w(rte_atomic32_t *v, int32_t new_value) {
  rte_atomic32_set(v, new_value);
}
void rte_atomic32_add_w(rte_atomic32_t *v, int32_t inc) {
  rte_atomic32_add(v, inc);
}
void rte_atomic32_sub_w(rte_atomic32_t *v, int32_t dec) {
  rte_atomic32_sub(v, dec);
}
void rte_atomic32_inc_w(rte_atomic32_t *v) { rte_atomic32_inc(v); }
void rte_atomic32_dec_w(rte_atomic32_t *v) { rte_atomic32_dec(v); }
int32_t rte_atomic32_add_return_w(rte_atomic32_t *v, int32_t inc) {
  return rte_atomic32_add_return(v, inc);
}
int32_t rte_atomic32_sub_return_w(rte_atomic32_t *v, int32_t dec) {
  return rte_atomic32_sub_return(v, dec);
}
int rte_atomic32_inc_and_test_w(rte_atomic32_t *v) {
  return rte_atomic32_inc_and_test(v);
}
int rte_atomic32_dec_and_test_w(rte_atomic32_t *v) {
  return rte_atomic32_dec_and_test(v);
}
int rte_atomic32_test_and_set_w(rte_atomic32_t *v) {
  return rte_atomic32_test_and_set(v);
}
void rte_atomic32_clear_w(rte_atomic32_t *v) { rte_atomic32_clear(v); }
int rte_atomic64_cmpset_w(uint64_t *dst, uint64_t exp, uint64_t src) {
  return rte_atomic64_cmpset(dst, exp, src);
}
uint64_t rte_atomic64_exchange_w(uint64_t *dst, uint64_t val) {
  return rte_atomic64_exchange(dst, val);
}
void rte_atomic64_init_w(rte_atomic64_t *v) { rte_atomic64_init(v); }
int64_t rte_atomic64_read_w(rte_atomic64_t *v) { return rte_atomic64_read(v); }
void rte_atomic64_set_w(rte_atomic64_t *v, int64_t new_value) {
  rte_atomic64_set(v, new_value);
}
void rte_atomic64_add_w(rte_atomic64_t *v, int64_t inc) {
  rte_atomic64_add(v, inc);
}
void rte_atomic64_sub_w(rte_atomic64_t *v, int64_t dec) {
  rte_atomic64_sub(v, dec);
}
void rte_atomic64_inc_w(rte_atomic64_t *v) { rte_atomic64_inc(v); }
void rte_atomic64_dec_w(rte_atomic64_t *v) { rte_atomic64_dec(v); }
int64_t rte_atomic64_add_return_w(rte_atomic64_t *v, int64_t inc) {
  return rte_atomic64_add_return(v, inc);
}
int64_t rte_atomic64_sub_return_w(rte_atomic64_t *v, int64_t dec) {
  return rte_atomic64_sub_return(v, dec);
}
int rte_atomic64_inc_and_test_w(rte_atomic64_t *v) {
  return rte_atomic64_inc_and_test(v);
}
int rte_atomic64_dec_and_test_w(rte_atomic64_t *v) {
  return rte_atomic64_dec_and_test(v);
}
int rte_atomic64_test_and_set_w(rte_atomic64_t *v) {
  return rte_atomic64_test_and_set(v);
}
void rte_atomic64_clear_w(rte_atomic64_t *v) { rte_atomic64_clear(v); }
void rte_smp_mb_w(void) { rte_smp_mb(); }
uint64_t rte_get_tsc_cycles_w(void) { return rte_get_tsc_cycles(); }
uint64_t rte_get_timer_cycles_w(void) { return rte_get_timer_cycles(); }
uint64_t rte_get_timer_hz_w(void) { return rte_get_timer_hz(); }
void rte_delay_ms_w(unsigned int ms) { rte_delay_ms(ms); }
uint64_t rte_rdtsc_w(void) { return rte_rdtsc(); }
uint64_t rte_rdtsc_precise_w(void) { return rte_rdtsc_precise(); }
size_t rte_strlcpy_w(char *dst, const char *src, size_t size) {
  return rte_strlcpy(dst, src, size);
}
size_t rte_strlcat_w(char *dst, const char *src, size_t size) {
  return rte_strlcat(dst, src, size);
}
const char *rte_str_skip_leading_spaces_w(const char *src) {
  return rte_str_skip_leading_spaces(src);
}
void rte_uuid_copy_w(rte_uuid_t dst, const rte_uuid_t src) {
  rte_uuid_copy(dst, src);
}
int rte_gettid_w(void) { return rte_gettid(); }
unsigned int rte_lcore_id_w(void) { return rte_lcore_id(); }
void rte_pause_w(void) { rte_pause(); }
void rte_wait_until_equal_16_w(uint16_t *addr, uint16_t expected,
                               rte_memory_order memorder) {
  rte_wait_until_equal_16(addr, expected, memorder);
}
void rte_wait_until_equal_32_w(uint32_t *addr, uint32_t expected,
                               rte_memory_order memorder) {
  rte_wait_until_equal_32(addr, expected, memorder);
}
void rte_wait_until_equal_64_w(uint64_t *addr, uint64_t expected,
                               rte_memory_order memorder) {
  rte_wait_until_equal_64(addr, expected, memorder);
}
void rte_spinlock_init_w(rte_spinlock_t *sl) { rte_spinlock_init(sl); }
void rte_spinlock_lock_w(rte_spinlock_t *sl) { rte_spinlock_lock(sl); }
void rte_spinlock_unlock_w(rte_spinlock_t *sl) { rte_spinlock_unlock(sl); }
int rte_spinlock_trylock_w(rte_spinlock_t *sl) {
  return rte_spinlock_trylock(sl);
}
int rte_spinlock_is_locked_w(rte_spinlock_t *sl) {
  return rte_spinlock_is_locked(sl);
}
int rte_tm_supported_w(void) { return rte_tm_supported(); }
void rte_spinlock_lock_tm_w(rte_spinlock_t *sl) { rte_spinlock_lock_tm(sl); }
void rte_spinlock_unlock_tm_w(rte_spinlock_t *sl) {
  rte_spinlock_unlock_tm(sl);
}
int rte_spinlock_trylock_tm_w(rte_spinlock_t *sl) {
  return rte_spinlock_trylock_tm(sl);
}
void rte_spinlock_recursive_init_w(rte_spinlock_recursive_t *slr) {
  rte_spinlock_recursive_init(slr);
}
void rte_spinlock_recursive_lock_w(rte_spinlock_recursive_t *slr) {
  rte_spinlock_recursive_lock(slr);
}
void rte_spinlock_recursive_unlock_w(rte_spinlock_recursive_t *slr) {
  rte_spinlock_recursive_unlock(slr);
}
int rte_spinlock_recursive_trylock_w(rte_spinlock_recursive_t *slr) {
  return rte_spinlock_recursive_trylock(slr);
}
void rte_spinlock_recursive_lock_tm_w(rte_spinlock_recursive_t *slr) {
  rte_spinlock_recursive_lock_tm(slr);
}
void rte_spinlock_recursive_unlock_tm_w(rte_spinlock_recursive_t *slr) {
  rte_spinlock_recursive_unlock_tm(slr);
}
int rte_spinlock_recursive_trylock_tm_w(rte_spinlock_recursive_t *slr) {
  return rte_spinlock_recursive_trylock_tm(slr);
}
// unsigned int rte_xbegin_w(void) { return rte_xbegin(); }
// void rte_xend_w(void) { rte_xend(); }
// int rte_xtest_w(void) { return rte_xtest(); }
// int rte_try_tm_w(int *lock) { return rte_try_tm(lock); }
uint32_t rte_bit_relaxed_get32_w(unsigned int nr, uint32_t *addr) {
  return rte_bit_relaxed_get32(nr, addr);
}
void rte_bit_relaxed_set32_w(unsigned int nr, uint32_t *addr) {
  rte_bit_relaxed_set32(nr, addr);
}
void rte_bit_relaxed_clear32_w(unsigned int nr, uint32_t *addr) {
  rte_bit_relaxed_clear32(nr, addr);
}
uint32_t rte_bit_relaxed_test_and_set32_w(unsigned int nr, uint32_t *addr) {
  return rte_bit_relaxed_test_and_set32(nr, addr);
}
uint32_t rte_bit_relaxed_test_and_clear32_w(unsigned int nr, uint32_t *addr) {
  return rte_bit_relaxed_test_and_clear32(nr, addr);
}
uint64_t rte_bit_relaxed_get64_w(unsigned int nr, uint64_t *addr) {
  return rte_bit_relaxed_get64(nr, addr);
}
void rte_bit_relaxed_set64_w(unsigned int nr, uint64_t *addr) {
  rte_bit_relaxed_set64(nr, addr);
}
void rte_bit_relaxed_clear64_w(unsigned int nr, uint64_t *addr) {
  rte_bit_relaxed_clear64(nr, addr);
}
uint64_t rte_bit_relaxed_test_and_set64_w(unsigned int nr, uint64_t *addr) {
  return rte_bit_relaxed_test_and_set64(nr, addr);
}
uint64_t rte_bit_relaxed_test_and_clear64_w(unsigned int nr, uint64_t *addr) {
  return rte_bit_relaxed_test_and_clear64(nr, addr);
}
unsigned int rte_clz32_w(uint32_t v) { return rte_clz32(v); }
unsigned int rte_clz64_w(uint64_t v) { return rte_clz64(v); }
unsigned int rte_ctz32_w(uint32_t v) { return rte_ctz32(v); }
unsigned int rte_ctz64_w(uint64_t v) { return rte_ctz64(v); }
unsigned int rte_popcount32_w(uint32_t v) { return rte_popcount32(v); }
unsigned int rte_popcount64_w(uint64_t v) { return rte_popcount64(v); }
uint32_t rte_combine32ms1b_w(uint32_t x) { return rte_combine32ms1b(x); }
uint64_t rte_combine64ms1b_w(uint64_t v) { return rte_combine64ms1b(v); }
uint32_t rte_bsf32_w(uint32_t v) { return rte_bsf32(v); }
int rte_bsf32_safe_w(uint32_t v, uint32_t *pos) {
  return rte_bsf32_safe(v, pos);
}
uint32_t rte_bsf64_w(uint64_t v) { return rte_bsf64(v); }
int rte_bsf64_safe_w(uint64_t v, uint32_t *pos) {
  return rte_bsf64_safe(v, pos);
}
uint32_t rte_fls_u32_w(uint32_t x) { return rte_fls_u32(x); }
uint32_t rte_fls_u64_w(uint64_t x) { return rte_fls_u64(x); }
int rte_is_power_of_2_w(uint32_t n) { return rte_is_power_of_2(n); }
uint32_t rte_align32pow2_w(uint32_t x) { return rte_align32pow2(x); }
uint32_t rte_align32prevpow2_w(uint32_t x) { return rte_align32prevpow2(x); }
uint64_t rte_align64pow2_w(uint64_t v) { return rte_align64pow2(v); }
uint64_t rte_align64prevpow2_w(uint64_t v) { return rte_align64prevpow2(v); }
uint32_t rte_log2_u32_w(uint32_t v) { return rte_log2_u32(v); }
uint32_t rte_log2_u64_w(uint64_t v) { return rte_log2_u64(v); }
void rte_rwlock_init_w(rte_rwlock_t *rwl) { rte_rwlock_init(rwl); }
void rte_rwlock_read_lock_w(rte_rwlock_t *rwl) { rte_rwlock_read_lock(rwl); }
int rte_rwlock_read_trylock_w(rte_rwlock_t *rwl) {
  return rte_rwlock_read_trylock(rwl);
}
void rte_rwlock_read_unlock_w(rte_rwlock_t *rwl) {
  rte_rwlock_read_unlock(rwl);
}
int rte_rwlock_write_trylock_w(rte_rwlock_t *rwl) {
  return rte_rwlock_write_trylock(rwl);
}
void rte_rwlock_write_lock_w(rte_rwlock_t *rwl) { rte_rwlock_write_lock(rwl); }
void rte_rwlock_write_unlock_w(rte_rwlock_t *rwl) {
  rte_rwlock_write_unlock(rwl);
}
int rte_rwlock_write_is_locked_w(rte_rwlock_t *rwl) {
  return rte_rwlock_write_is_locked(rwl);
}
void rte_rwlock_read_lock_tm_w(rte_rwlock_t *rwl) {
  rte_rwlock_read_lock_tm(rwl);
}
void rte_rwlock_read_unlock_tm_w(rte_rwlock_t *rwl) {
  rte_rwlock_read_unlock_tm(rwl);
}
void rte_rwlock_write_lock_tm_w(rte_rwlock_t *rwl) {
  rte_rwlock_write_lock_tm(rwl);
}
void rte_rwlock_write_unlock_tm_w(rte_rwlock_t *rwl) {
  rte_rwlock_write_unlock_tm(rwl);
}
unsigned int rte_ring_mp_enqueue_bulk_elem_w(struct rte_ring *r,
                                             const void *obj_table,
                                             unsigned int esize, unsigned int n,
                                             unsigned int *free_space) {
  return rte_ring_mp_enqueue_bulk_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_sp_enqueue_bulk_elem_w(struct rte_ring *r,
                                             const void *obj_table,
                                             unsigned int esize, unsigned int n,
                                             unsigned int *free_space) {
  return rte_ring_sp_enqueue_bulk_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_mp_hts_enqueue_bulk_elem_w(struct rte_ring *r,
                                                 const void *obj_table,
                                                 unsigned int esize,
                                                 unsigned int n,
                                                 unsigned int *free_space) {
  return rte_ring_mp_hts_enqueue_bulk_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_mc_hts_dequeue_bulk_elem_w(struct rte_ring *r,
                                                 void *obj_table,
                                                 unsigned int esize,
                                                 unsigned int n,
                                                 unsigned int *available) {
  return rte_ring_mc_hts_dequeue_bulk_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_mp_hts_enqueue_burst_elem_w(struct rte_ring *r,
                                                  const void *obj_table,
                                                  unsigned int esize,
                                                  unsigned int n,
                                                  unsigned int *free_space) {
  return rte_ring_mp_hts_enqueue_burst_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_mc_hts_dequeue_burst_elem_w(struct rte_ring *r,
                                                  void *obj_table,
                                                  unsigned int esize,
                                                  unsigned int n,
                                                  unsigned int *available) {
  return rte_ring_mc_hts_dequeue_burst_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_mp_hts_enqueue_bulk_w(struct rte_ring *r,
                                            void *const *obj_table,
                                            unsigned int n,
                                            unsigned int *free_space) {
  return rte_ring_mp_hts_enqueue_bulk(r, obj_table, n, free_space);
}
unsigned int rte_ring_mc_hts_dequeue_bulk_w(struct rte_ring *r,
                                            void **obj_table, unsigned int n,
                                            unsigned int *available) {
  return rte_ring_mc_hts_dequeue_bulk(r, obj_table, n, available);
}
unsigned int rte_ring_mp_hts_enqueue_burst_w(struct rte_ring *r,
                                             void *const *obj_table,
                                             unsigned int n,
                                             unsigned int *free_space) {
  return rte_ring_mp_hts_enqueue_burst(r, obj_table, n, free_space);
}
unsigned int rte_ring_mc_hts_dequeue_burst_w(struct rte_ring *r,
                                             void **obj_table, unsigned int n,
                                             unsigned int *available) {
  return rte_ring_mc_hts_dequeue_burst(r, obj_table, n, available);
}
unsigned int rte_ring_mp_rts_enqueue_bulk_elem_w(struct rte_ring *r,
                                                 const void *obj_table,
                                                 unsigned int esize,
                                                 unsigned int n,
                                                 unsigned int *free_space) {
  return rte_ring_mp_rts_enqueue_bulk_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_mc_rts_dequeue_bulk_elem_w(struct rte_ring *r,
                                                 void *obj_table,
                                                 unsigned int esize,
                                                 unsigned int n,
                                                 unsigned int *available) {
  return rte_ring_mc_rts_dequeue_bulk_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_mp_rts_enqueue_burst_elem_w(struct rte_ring *r,
                                                  const void *obj_table,
                                                  unsigned int esize,
                                                  unsigned int n,
                                                  unsigned int *free_space) {
  return rte_ring_mp_rts_enqueue_burst_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_mc_rts_dequeue_burst_elem_w(struct rte_ring *r,
                                                  void *obj_table,
                                                  unsigned int esize,
                                                  unsigned int n,
                                                  unsigned int *available) {
  return rte_ring_mc_rts_dequeue_burst_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_mp_rts_enqueue_bulk_w(struct rte_ring *r,
                                            void *const *obj_table,
                                            unsigned int n,
                                            unsigned int *free_space) {
  return rte_ring_mp_rts_enqueue_bulk(r, obj_table, n, free_space);
}
unsigned int rte_ring_mc_rts_dequeue_bulk_w(struct rte_ring *r,
                                            void **obj_table, unsigned int n,
                                            unsigned int *available) {
  return rte_ring_mc_rts_dequeue_bulk(r, obj_table, n, available);
}
unsigned int rte_ring_mp_rts_enqueue_burst_w(struct rte_ring *r,
                                             void *const *obj_table,
                                             unsigned int n,
                                             unsigned int *free_space) {
  return rte_ring_mp_rts_enqueue_burst(r, obj_table, n, free_space);
}
unsigned int rte_ring_mc_rts_dequeue_burst_w(struct rte_ring *r,
                                             void **obj_table, unsigned int n,
                                             unsigned int *available) {
  return rte_ring_mc_rts_dequeue_burst(r, obj_table, n, available);
}
uint32_t rte_ring_get_prod_htd_max_w(const struct rte_ring *r) {
  return rte_ring_get_prod_htd_max(r);
}
int rte_ring_set_prod_htd_max_w(struct rte_ring *r, uint32_t v) {
  return rte_ring_set_prod_htd_max(r, v);
}
uint32_t rte_ring_get_cons_htd_max_w(const struct rte_ring *r) {
  return rte_ring_get_cons_htd_max(r);
}
int rte_ring_set_cons_htd_max_w(struct rte_ring *r, uint32_t v) {
  return rte_ring_set_cons_htd_max(r, v);
}
unsigned int rte_ring_enqueue_bulk_elem_w(struct rte_ring *r,
                                          const void *obj_table,
                                          unsigned int esize, unsigned int n,
                                          unsigned int *free_space) {
  return rte_ring_enqueue_bulk_elem(r, obj_table, esize, n, free_space);
}
int rte_ring_mp_enqueue_elem_w(struct rte_ring *r, void *obj,
                               unsigned int esize) {
  return rte_ring_mp_enqueue_elem(r, obj, esize);
}
int rte_ring_sp_enqueue_elem_w(struct rte_ring *r, void *obj,
                               unsigned int esize) {
  return rte_ring_sp_enqueue_elem(r, obj, esize);
}
int rte_ring_enqueue_elem_w(struct rte_ring *r, void *obj, unsigned int esize) {
  return rte_ring_enqueue_elem(r, obj, esize);
}
unsigned int rte_ring_mc_dequeue_bulk_elem_w(struct rte_ring *r,
                                             void *obj_table,
                                             unsigned int esize, unsigned int n,
                                             unsigned int *available) {
  return rte_ring_mc_dequeue_bulk_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_sc_dequeue_bulk_elem_w(struct rte_ring *r,
                                             void *obj_table,
                                             unsigned int esize, unsigned int n,
                                             unsigned int *available) {
  return rte_ring_sc_dequeue_bulk_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_dequeue_bulk_elem_w(struct rte_ring *r, void *obj_table,
                                          unsigned int esize, unsigned int n,
                                          unsigned int *available) {
  return rte_ring_dequeue_bulk_elem(r, obj_table, esize, n, available);
}
int rte_ring_mc_dequeue_elem_w(struct rte_ring *r, void *obj_p,
                               unsigned int esize) {
  return rte_ring_mc_dequeue_elem(r, obj_p, esize);
}
int rte_ring_sc_dequeue_elem_w(struct rte_ring *r, void *obj_p,
                               unsigned int esize) {
  return rte_ring_sc_dequeue_elem(r, obj_p, esize);
}
int rte_ring_dequeue_elem_w(struct rte_ring *r, void *obj_p,
                            unsigned int esize) {
  return rte_ring_dequeue_elem(r, obj_p, esize);
}
unsigned int rte_ring_mp_enqueue_burst_elem_w(struct rte_ring *r,
                                              const void *obj_table,
                                              unsigned int esize,
                                              unsigned int n,
                                              unsigned int *free_space) {
  return rte_ring_mp_enqueue_burst_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_sp_enqueue_burst_elem_w(struct rte_ring *r,
                                              const void *obj_table,
                                              unsigned int esize,
                                              unsigned int n,
                                              unsigned int *free_space) {
  return rte_ring_sp_enqueue_burst_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_enqueue_burst_elem_w(struct rte_ring *r,
                                           const void *obj_table,
                                           unsigned int esize, unsigned int n,
                                           unsigned int *free_space) {
  return rte_ring_enqueue_burst_elem(r, obj_table, esize, n, free_space);
}
unsigned int rte_ring_mc_dequeue_burst_elem_w(struct rte_ring *r,
                                              void *obj_table,
                                              unsigned int esize,
                                              unsigned int n,
                                              unsigned int *available) {
  return rte_ring_mc_dequeue_burst_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_sc_dequeue_burst_elem_w(struct rte_ring *r,
                                              void *obj_table,
                                              unsigned int esize,
                                              unsigned int n,
                                              unsigned int *available) {
  return rte_ring_sc_dequeue_burst_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_dequeue_burst_elem_w(struct rte_ring *r, void *obj_table,
                                           unsigned int esize, unsigned int n,
                                           unsigned int *available) {
  return rte_ring_dequeue_burst_elem(r, obj_table, esize, n, available);
}
unsigned int rte_ring_enqueue_bulk_elem_start_w(struct rte_ring *r,
                                                unsigned int n,
                                                unsigned int *free_space) {
  return rte_ring_enqueue_bulk_elem_start(r, n, free_space);
}
unsigned int rte_ring_enqueue_bulk_start_w(struct rte_ring *r, unsigned int n,
                                           unsigned int *free_space) {
  return rte_ring_enqueue_bulk_start(r, n, free_space);
}
unsigned int rte_ring_enqueue_burst_elem_start_w(struct rte_ring *r,
                                                 unsigned int n,
                                                 unsigned int *free_space) {
  return rte_ring_enqueue_burst_elem_start(r, n, free_space);
}
unsigned int rte_ring_enqueue_burst_start_w(struct rte_ring *r, unsigned int n,
                                            unsigned int *free_space) {
  return rte_ring_enqueue_burst_start(r, n, free_space);
}
void rte_ring_enqueue_elem_finish_w(struct rte_ring *r, const void *obj_table,
                                    unsigned int esize, unsigned int n) {
  rte_ring_enqueue_elem_finish(r, obj_table, esize, n);
}
void rte_ring_enqueue_finish_w(struct rte_ring *r, void *const *obj_table,
                               unsigned int n) {
  rte_ring_enqueue_finish(r, obj_table, n);
}
unsigned int rte_ring_dequeue_bulk_elem_start_w(struct rte_ring *r,
                                                void *obj_table,
                                                unsigned int esize,
                                                unsigned int n,
                                                unsigned int *available) {
  return rte_ring_dequeue_bulk_elem_start(r, obj_table, esize, n, available);
}
unsigned int rte_ring_dequeue_bulk_start_w(struct rte_ring *r, void **obj_table,
                                           unsigned int n,
                                           unsigned int *available) {
  return rte_ring_dequeue_bulk_start(r, obj_table, n, available);
}
unsigned int rte_ring_dequeue_burst_elem_start_w(struct rte_ring *r,
                                                 void *obj_table,
                                                 unsigned int esize,
                                                 unsigned int n,
                                                 unsigned int *available) {
  return rte_ring_dequeue_burst_elem_start(r, obj_table, esize, n, available);
}
unsigned int rte_ring_dequeue_burst_start_w(struct rte_ring *r,
                                            void **obj_table, unsigned int n,
                                            unsigned int *available) {
  return rte_ring_dequeue_burst_start(r, obj_table, n, available);
}
void rte_ring_dequeue_elem_finish_w(struct rte_ring *r, unsigned int n) {
  rte_ring_dequeue_elem_finish(r, n);
}
void rte_ring_dequeue_finish_w(struct rte_ring *r, unsigned int n) {
  rte_ring_dequeue_finish(r, n);
}
unsigned int rte_ring_enqueue_zc_bulk_elem_start_w(struct rte_ring *r,
                                                   unsigned int esize,
                                                   unsigned int n,
                                                   struct rte_ring_zc_data *zcd,
                                                   unsigned int *free_space) {
  return rte_ring_enqueue_zc_bulk_elem_start(r, esize, n, zcd, free_space);
}
unsigned int rte_ring_enqueue_zc_bulk_start_w(struct rte_ring *r,
                                              unsigned int n,
                                              struct rte_ring_zc_data *zcd,
                                              unsigned int *free_space) {
  return rte_ring_enqueue_zc_bulk_start(r, n, zcd, free_space);
}
unsigned int rte_ring_enqueue_zc_burst_elem_start_w(
    struct rte_ring *r, unsigned int esize, unsigned int n,
    struct rte_ring_zc_data *zcd, unsigned int *free_space) {
  return rte_ring_enqueue_zc_burst_elem_start(r, esize, n, zcd, free_space);
}
unsigned int rte_ring_enqueue_zc_burst_start_w(struct rte_ring *r,
                                               unsigned int n,
                                               struct rte_ring_zc_data *zcd,
                                               unsigned int *free_space) {
  return rte_ring_enqueue_zc_burst_start(r, n, zcd, free_space);
}
void rte_ring_enqueue_zc_elem_finish_w(struct rte_ring *r, unsigned int n) {
  rte_ring_enqueue_zc_elem_finish(r, n);
}
void rte_ring_enqueue_zc_finish_w(struct rte_ring *r, unsigned int n) {
  rte_ring_enqueue_zc_finish(r, n);
}
unsigned int rte_ring_dequeue_zc_bulk_elem_start_w(struct rte_ring *r,
                                                   unsigned int esize,
                                                   unsigned int n,
                                                   struct rte_ring_zc_data *zcd,
                                                   unsigned int *available) {
  return rte_ring_dequeue_zc_bulk_elem_start(r, esize, n, zcd, available);
}
unsigned int rte_ring_dequeue_zc_bulk_start_w(struct rte_ring *r,
                                              unsigned int n,
                                              struct rte_ring_zc_data *zcd,
                                              unsigned int *available) {
  return rte_ring_dequeue_zc_bulk_start(r, n, zcd, available);
}
unsigned int rte_ring_dequeue_zc_burst_elem_start_w(
    struct rte_ring *r, unsigned int esize, unsigned int n,
    struct rte_ring_zc_data *zcd, unsigned int *available) {
  return rte_ring_dequeue_zc_burst_elem_start(r, esize, n, zcd, available);
}
unsigned int rte_ring_dequeue_zc_burst_start_w(struct rte_ring *r,
                                               unsigned int n,
                                               struct rte_ring_zc_data *zcd,
                                               unsigned int *available) {
  return rte_ring_dequeue_zc_burst_start(r, n, zcd, available);
}
void rte_ring_dequeue_zc_elem_finish_w(struct rte_ring *r, unsigned int n) {
  rte_ring_dequeue_zc_elem_finish(r, n);
}
void rte_ring_dequeue_zc_finish_w(struct rte_ring *r, unsigned int n) {
  rte_ring_dequeue_zc_finish(r, n);
}
unsigned int rte_ring_mp_enqueue_bulk_w(struct rte_ring *r,
                                        void *const *obj_table, unsigned int n,
                                        unsigned int *free_space) {
  return rte_ring_mp_enqueue_bulk(r, obj_table, n, free_space);
}
unsigned int rte_ring_sp_enqueue_bulk_w(struct rte_ring *r,
                                        void *const *obj_table, unsigned int n,
                                        unsigned int *free_space) {
  return rte_ring_sp_enqueue_bulk(r, obj_table, n, free_space);
}
unsigned int rte_ring_enqueue_bulk_w(struct rte_ring *r, void *const *obj_table,
                                     unsigned int n, unsigned int *free_space) {
  return rte_ring_enqueue_bulk(r, obj_table, n, free_space);
}
int rte_ring_mp_enqueue_w(struct rte_ring *r, void *obj) {
  return rte_ring_mp_enqueue(r, obj);
}
int rte_ring_sp_enqueue_w(struct rte_ring *r, void *obj) {
  return rte_ring_sp_enqueue(r, obj);
}
int rte_ring_enqueue_w(struct rte_ring *r, void *obj) {
  return rte_ring_enqueue(r, obj);
}
unsigned int rte_ring_mc_dequeue_bulk_w(struct rte_ring *r, void **obj_table,
                                        unsigned int n,
                                        unsigned int *available) {
  return rte_ring_mc_dequeue_bulk(r, obj_table, n, available);
}
unsigned int rte_ring_sc_dequeue_bulk_w(struct rte_ring *r, void **obj_table,
                                        unsigned int n,
                                        unsigned int *available) {
  return rte_ring_sc_dequeue_bulk(r, obj_table, n, available);
}
unsigned int rte_ring_dequeue_bulk_w(struct rte_ring *r, void **obj_table,
                                     unsigned int n, unsigned int *available) {
  return rte_ring_dequeue_bulk(r, obj_table, n, available);
}
int rte_ring_mc_dequeue_w(struct rte_ring *r, void **obj_p) {
  return rte_ring_mc_dequeue(r, obj_p);
}
int rte_ring_sc_dequeue_w(struct rte_ring *r, void **obj_p) {
  return rte_ring_sc_dequeue(r, obj_p);
}
int rte_ring_dequeue_w(struct rte_ring *r, void **obj_p) {
  return rte_ring_dequeue(r, obj_p);
}
unsigned int rte_ring_count_w(const struct rte_ring *r) {
  return rte_ring_count(r);
}
unsigned int rte_ring_free_count_w(const struct rte_ring *r) {
  return rte_ring_free_count(r);
}
int rte_ring_full_w(const struct rte_ring *r) { return rte_ring_full(r); }
int rte_ring_empty_w(const struct rte_ring *r) { return rte_ring_empty(r); }
unsigned int rte_ring_get_size_w(const struct rte_ring *r) {
  return rte_ring_get_size(r);
}
unsigned int rte_ring_get_capacity_w(const struct rte_ring *r) {
  return rte_ring_get_capacity(r);
}
enum rte_ring_sync_type
rte_ring_get_prod_sync_type_w(const struct rte_ring *r) {
  return rte_ring_get_prod_sync_type(r);
}
int rte_ring_is_prod_single_w(const struct rte_ring *r) {
  return rte_ring_is_prod_single(r);
}
enum rte_ring_sync_type
rte_ring_get_cons_sync_type_w(const struct rte_ring *r) {
  return rte_ring_get_cons_sync_type(r);
}
int rte_ring_is_cons_single_w(const struct rte_ring *r) {
  return rte_ring_is_cons_single(r);
}
unsigned int rte_ring_mp_enqueue_burst_w(struct rte_ring *r,
                                         void *const *obj_table, unsigned int n,
                                         unsigned int *free_space) {
  return rte_ring_mp_enqueue_burst(r, obj_table, n, free_space);
}
unsigned int rte_ring_sp_enqueue_burst_w(struct rte_ring *r,
                                         void *const *obj_table, unsigned int n,
                                         unsigned int *free_space) {
  return rte_ring_sp_enqueue_burst(r, obj_table, n, free_space);
}
unsigned int rte_ring_enqueue_burst_w(struct rte_ring *r,
                                      void *const *obj_table, unsigned int n,
                                      unsigned int *free_space) {
  return rte_ring_enqueue_burst(r, obj_table, n, free_space);
}
unsigned int rte_ring_mc_dequeue_burst_w(struct rte_ring *r, void **obj_table,
                                         unsigned int n,
                                         unsigned int *available) {
  return rte_ring_mc_dequeue_burst(r, obj_table, n, available);
}
unsigned int rte_ring_sc_dequeue_burst_w(struct rte_ring *r, void **obj_table,
                                         unsigned int n,
                                         unsigned int *available) {
  return rte_ring_sc_dequeue_burst(r, obj_table, n, available);
}
unsigned int rte_ring_dequeue_burst_w(struct rte_ring *r, void **obj_table,
                                      unsigned int n, unsigned int *available) {
  return rte_ring_dequeue_burst(r, obj_table, n, available);
}
void *rte_memcpy_w(void *dst, const void *src, size_t n) {
  return rte_memcpy(dst, src, n);
}
// void *rte_mov15_or_less_w(void *dst, const void *src, size_t n) {
//   return rte_mov15_or_less(dst, src, n);
// }
void rte_mov16_w(uint8_t *dst, const uint8_t *src) { rte_mov16(dst, src); }
void rte_mov32_w(uint8_t *dst, const uint8_t *src) { rte_mov32(dst, src); }
void rte_mov64_w(uint8_t *dst, const uint8_t *src) { rte_mov64(dst, src); }
void rte_mov256_w(uint8_t *dst, const uint8_t *src) { rte_mov256(dst, src); }
// void *rte_memcpy_generic_w(void *dst, const void *src, size_t n) {
//   return rte_memcpy_generic(dst, src, n);
// }
// void *rte_memcpy_aligned_w(void *dst, const void *src, size_t n) {
//   return rte_memcpy_aligned(dst, src, n);
// }
struct rte_mempool_objhdr *rte_mempool_get_header_w(void *obj) {
  return rte_mempool_get_header(obj);
}
struct rte_mempool *rte_mempool_from_obj_w(void *obj) {
  return rte_mempool_from_obj(obj);
}
struct rte_mempool_objtlr *rte_mempool_get_trailer_w(void *obj) {
  return rte_mempool_get_trailer(obj);
}
struct rte_mempool_ops *rte_mempool_get_ops_w(int ops_index) {
  return rte_mempool_get_ops(ops_index);
}
int rte_mempool_ops_dequeue_bulk_w(struct rte_mempool *mp, void **obj_table,
                                   unsigned int n) {
  return rte_mempool_ops_dequeue_bulk(mp, obj_table, n);
}
int rte_mempool_ops_dequeue_contig_blocks_w(struct rte_mempool *mp,
                                            void **first_obj_table,
                                            unsigned int n) {
  return rte_mempool_ops_dequeue_contig_blocks(mp, first_obj_table, n);
}
int rte_mempool_ops_enqueue_bulk_w(struct rte_mempool *mp,
                                   void *const *obj_table, unsigned int n) {
  return rte_mempool_ops_enqueue_bulk(mp, obj_table, n);
}
struct rte_mempool_cache *rte_mempool_default_cache_w(struct rte_mempool *mp,
                                                      unsigned int lcore_id) {
  return rte_mempool_default_cache(mp, lcore_id);
}
void rte_mempool_cache_flush_w(struct rte_mempool_cache *cache,
                               struct rte_mempool *mp) {
  rte_mempool_cache_flush(cache, mp);
}
void rte_mempool_do_generic_put_w(struct rte_mempool *mp,
                                  void *const *obj_table, unsigned int n,
                                  struct rte_mempool_cache *cache) {
  rte_mempool_do_generic_put(mp, obj_table, n, cache);
}
void rte_mempool_generic_put_w(struct rte_mempool *mp, void *const *obj_table,
                               unsigned int n,
                               struct rte_mempool_cache *cache) {
  rte_mempool_generic_put(mp, obj_table, n, cache);
}
void rte_mempool_put_bulk_w(struct rte_mempool *mp, void *const *obj_table,
                            unsigned int n) {
  rte_mempool_put_bulk(mp, obj_table, n);
}
void rte_mempool_put_w(struct rte_mempool *mp, void *obj) {
  rte_mempool_put(mp, obj);
}
int rte_mempool_do_generic_get_w(struct rte_mempool *mp, void **obj_table,
                                 unsigned int n,
                                 struct rte_mempool_cache *cache) {
  return rte_mempool_do_generic_get(mp, obj_table, n, cache);
}
int rte_mempool_generic_get_w(struct rte_mempool *mp, void **obj_table,
                              unsigned int n, struct rte_mempool_cache *cache) {
  return rte_mempool_generic_get(mp, obj_table, n, cache);
}
int rte_mempool_get_bulk_w(struct rte_mempool *mp, void **obj_table,
                           unsigned int n) {
  return rte_mempool_get_bulk(mp, obj_table, n);
}
int rte_mempool_get_w(struct rte_mempool *mp, void **obj_p) {
  return rte_mempool_get(mp, obj_p);
}
int rte_mempool_get_contig_blocks_w(struct rte_mempool *mp,
                                    void **first_obj_table, unsigned int n) {
  return rte_mempool_get_contig_blocks(mp, first_obj_table, n);
}
int rte_mempool_full_w(const struct rte_mempool *mp) {
  return rte_mempool_full(mp);
}
int rte_mempool_empty_w(const struct rte_mempool *mp) {
  return rte_mempool_empty(mp);
}
rte_iova_t rte_mempool_virt2iova_w(const void *elt) {
  return rte_mempool_virt2iova(elt);
}
void *rte_mempool_get_priv_w(struct rte_mempool *mp) {
  return rte_mempool_get_priv(mp);
}
void rte_prefetch0_w(const void *p) { rte_prefetch0(p); }
void rte_prefetch1_w(const void *p) { rte_prefetch1(p); }
void rte_prefetch2_w(const void *p) { rte_prefetch2(p); }
void rte_prefetch_non_temporal_w(const void *p) {
  rte_prefetch_non_temporal(p);
}
void rte_prefetch0_write_w(const void *p) { rte_prefetch0_write(p); }
void rte_prefetch1_write_w(const void *p) { rte_prefetch1_write(p); }
void rte_prefetch2_write_w(const void *p) { rte_prefetch2_write(p); }
void rte_cldemote_w(const void *p) { rte_cldemote(p); }
uint16_t rte_constant_bswap16_w(uint16_t x) { return rte_constant_bswap16(x); }
uint32_t rte_constant_bswap32_w(uint32_t x) { return rte_constant_bswap32(x); }
uint64_t rte_constant_bswap64_w(uint64_t x) { return rte_constant_bswap64(x); }
// uint16_t rte_arch_bswap16_w(uint16_t _x) { return rte_arch_bswap16(_x); }
// uint32_t rte_arch_bswap32_w(uint32_t _x) { return rte_arch_bswap32(_x); }
// uint64_t rte_arch_bswap64_w(uint64_t _x) { return rte_arch_bswap64(_x); }
void rte_mbuf_prefetch_part1_w(struct rte_mbuf *m) {
  rte_mbuf_prefetch_part1(m);
}
void rte_mbuf_prefetch_part2_w(struct rte_mbuf *m) {
  rte_mbuf_prefetch_part2(m);
}
uint16_t rte_pktmbuf_priv_size_w(struct rte_mempool *mp) {
  return rte_pktmbuf_priv_size(mp);
}
rte_iova_t rte_mbuf_iova_get_w(const struct rte_mbuf *m) {
  return rte_mbuf_iova_get(m);
}
void rte_mbuf_iova_set_w(struct rte_mbuf *m, rte_iova_t iova) {
  rte_mbuf_iova_set(m, iova);
}
rte_iova_t rte_mbuf_data_iova_w(const struct rte_mbuf *mb) {
  return rte_mbuf_data_iova(mb);
}
rte_iova_t rte_mbuf_data_iova_default_w(const struct rte_mbuf *mb) {
  return rte_mbuf_data_iova_default(mb);
}
struct rte_mbuf *rte_mbuf_from_indirect_w(struct rte_mbuf *mi) {
  return rte_mbuf_from_indirect(mi);
}
char *rte_mbuf_buf_addr_w(struct rte_mbuf *mb, struct rte_mempool *mp) {
  return rte_mbuf_buf_addr(mb, mp);
}
char *rte_mbuf_data_addr_default_w(struct rte_mbuf *mb) {
  return rte_mbuf_data_addr_default(mb);
}
char *rte_mbuf_to_baddr_w(struct rte_mbuf *md) { return rte_mbuf_to_baddr(md); }
void *rte_mbuf_to_priv_w(struct rte_mbuf *m) { return rte_mbuf_to_priv(m); }
uint32_t rte_pktmbuf_priv_flags_w(struct rte_mempool *mp) {
  return rte_pktmbuf_priv_flags(mp);
}
uint16_t rte_mbuf_refcnt_read_w(const struct rte_mbuf *m) {
  return rte_mbuf_refcnt_read(m);
}
void rte_mbuf_refcnt_set_w(struct rte_mbuf *m, uint16_t new_value) {
  rte_mbuf_refcnt_set(m, new_value);
}
uint16_t rte_mbuf_refcnt_update_w(struct rte_mbuf *m, int16_t value) {
  return rte_mbuf_refcnt_update(m, value);
}
uint16_t
rte_mbuf_ext_refcnt_read_w(const struct rte_mbuf_ext_shared_info *shinfo) {
  return rte_mbuf_ext_refcnt_read(shinfo);
}
void rte_mbuf_ext_refcnt_set_w(struct rte_mbuf_ext_shared_info *shinfo,
                               uint16_t new_value) {
  rte_mbuf_ext_refcnt_set(shinfo, new_value);
}
uint16_t rte_mbuf_ext_refcnt_update_w(struct rte_mbuf_ext_shared_info *shinfo,
                                      int16_t value) {
  return rte_mbuf_ext_refcnt_update(shinfo, value);
}
struct rte_mbuf *rte_mbuf_raw_alloc_w(struct rte_mempool *mp) {
  return rte_mbuf_raw_alloc(mp);
}
void rte_mbuf_raw_free_w(struct rte_mbuf *m) { rte_mbuf_raw_free(m); }
uint16_t rte_pktmbuf_data_room_size_w(struct rte_mempool *mp) {
  return rte_pktmbuf_data_room_size(mp);
}
void rte_pktmbuf_reset_headroom_w(struct rte_mbuf *m) {
  rte_pktmbuf_reset_headroom(m);
}
void rte_pktmbuf_reset_w(struct rte_mbuf *m) { rte_pktmbuf_reset(m); }
struct rte_mbuf *rte_pktmbuf_alloc_w(struct rte_mempool *mp) {
  return rte_pktmbuf_alloc(mp);
}
int rte_pktmbuf_alloc_bulk_w(struct rte_mempool *pool, struct rte_mbuf **mbufs,
                             unsigned int count) {
  return rte_pktmbuf_alloc_bulk(pool, mbufs, count);
}
struct rte_mbuf_ext_shared_info *
rte_pktmbuf_ext_shinfo_init_helper_w(void *buf_addr, uint16_t *buf_len,
                                     rte_mbuf_extbuf_free_callback_t free_cb,
                                     void *fcb_opaque) {
  return rte_pktmbuf_ext_shinfo_init_helper(buf_addr, buf_len, free_cb,
                                            fcb_opaque);
}
void rte_pktmbuf_attach_extbuf_w(struct rte_mbuf *m, void *buf_addr,
                                 rte_iova_t buf_iova, uint16_t buf_len,
                                 struct rte_mbuf_ext_shared_info *shinfo) {
  rte_pktmbuf_attach_extbuf(m, buf_addr, buf_iova, buf_len, shinfo);
}
void rte_mbuf_dynfield_copy_w(struct rte_mbuf *mdst,
                              const struct rte_mbuf *msrc) {
  rte_mbuf_dynfield_copy(mdst, msrc);
}
void rte_pktmbuf_attach_w(struct rte_mbuf *mi, struct rte_mbuf *m) {
  rte_pktmbuf_attach(mi, m);
}
void rte_pktmbuf_detach_w(struct rte_mbuf *m) { rte_pktmbuf_detach(m); }
struct rte_mbuf *rte_pktmbuf_prefree_seg_w(struct rte_mbuf *m) {
  return rte_pktmbuf_prefree_seg(m);
}
void rte_pktmbuf_free_seg_w(struct rte_mbuf *m) { rte_pktmbuf_free_seg(m); }
void rte_pktmbuf_free_w(struct rte_mbuf *m) { rte_pktmbuf_free(m); }
void rte_pktmbuf_refcnt_update_w(struct rte_mbuf *m, int16_t v) {
  rte_pktmbuf_refcnt_update(m, v);
}
uint16_t rte_pktmbuf_headroom_w(const struct rte_mbuf *m) {
  return rte_pktmbuf_headroom(m);
}
uint16_t rte_pktmbuf_tailroom_w(const struct rte_mbuf *m) {
  return rte_pktmbuf_tailroom(m);
}
struct rte_mbuf *rte_pktmbuf_lastseg_w(struct rte_mbuf *m) {
  return rte_pktmbuf_lastseg(m);
}
char *rte_pktmbuf_prepend_w(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_prepend(m, len);
}
char *rte_pktmbuf_append_w(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_append(m, len);
}
char *rte_pktmbuf_adj_w(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_adj(m, len);
}
int rte_pktmbuf_trim_w(struct rte_mbuf *m, uint16_t len) {
  return rte_pktmbuf_trim(m, len);
}
int rte_pktmbuf_is_contiguous_w(const struct rte_mbuf *m) {
  return rte_pktmbuf_is_contiguous(m);
}
const void *rte_pktmbuf_read_w(const struct rte_mbuf *m, uint32_t off,
                               uint32_t len, void *buf) {
  return rte_pktmbuf_read(m, off, len, buf);
}
int rte_pktmbuf_chain_w(struct rte_mbuf *head, struct rte_mbuf *tail) {
  return rte_pktmbuf_chain(head, tail);
}
uint64_t rte_mbuf_tx_offload_w(uint64_t il2, uint64_t il3, uint64_t il4,
                               uint64_t tso, uint64_t ol3, uint64_t ol2,
                               uint64_t unused) {
  return rte_mbuf_tx_offload(il2, il3, il4, tso, ol3, ol2, unused);
}
int rte_validate_tx_offload_w(const struct rte_mbuf *m) {
  return rte_validate_tx_offload(m);
}
int rte_pktmbuf_linearize_w(struct rte_mbuf *mbuf) {
  return rte_pktmbuf_linearize(mbuf);
}
uint32_t rte_mbuf_sched_queue_get_w(const struct rte_mbuf *m) {
  return rte_mbuf_sched_queue_get(m);
}
uint8_t rte_mbuf_sched_traffic_class_get_w(const struct rte_mbuf *m) {
  return rte_mbuf_sched_traffic_class_get(m);
}
uint8_t rte_mbuf_sched_color_get_w(const struct rte_mbuf *m) {
  return rte_mbuf_sched_color_get(m);
}
void rte_mbuf_sched_get_w(const struct rte_mbuf *m, uint32_t *queue_id,
                          uint8_t *traffic_class, uint8_t *color) {
  rte_mbuf_sched_get(m, queue_id, traffic_class, color);
}
void rte_mbuf_sched_queue_set_w(struct rte_mbuf *m, uint32_t queue_id) {
  rte_mbuf_sched_queue_set(m, queue_id);
}
void rte_mbuf_sched_traffic_class_set_w(struct rte_mbuf *m,
                                        uint8_t traffic_class) {
  rte_mbuf_sched_traffic_class_set(m, traffic_class);
}
void rte_mbuf_sched_color_set_w(struct rte_mbuf *m, uint8_t color) {
  rte_mbuf_sched_color_set(m, color);
}
void rte_mbuf_sched_set_w(struct rte_mbuf *m, uint32_t queue_id,
                          uint8_t traffic_class, uint8_t color) {
  rte_mbuf_sched_set(m, queue_id, traffic_class, color);
}
int rte_is_same_ether_addr_w(const struct rte_ether_addr *ea1,
                             const struct rte_ether_addr *ea2) {
  return rte_is_same_ether_addr(ea1, ea2);
}
int rte_is_zero_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_zero_ether_addr(ea);
}
int rte_is_unicast_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_unicast_ether_addr(ea);
}
int rte_is_multicast_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_multicast_ether_addr(ea);
}
int rte_is_broadcast_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_broadcast_ether_addr(ea);
}
int rte_is_universal_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_universal_ether_addr(ea);
}
int rte_is_local_admin_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_local_admin_ether_addr(ea);
}
int rte_is_valid_assigned_ether_addr_w(const struct rte_ether_addr *ea) {
  return rte_is_valid_assigned_ether_addr(ea);
}
void rte_ether_addr_copy_w(const struct rte_ether_addr *ea_from,
                           struct rte_ether_addr *ea_to) {
  rte_ether_addr_copy(ea_from, ea_to);
}
int rte_vlan_strip_w(struct rte_mbuf *m) { return rte_vlan_strip(m); }
int rte_vlan_insert_w(struct rte_mbuf **m) { return rte_vlan_insert(m); }
uint32_t rte_bitmap_get_memory_footprint_w(uint32_t n_bits) {
  return rte_bitmap_get_memory_footprint(n_bits);
}
struct rte_bitmap *rte_bitmap_init_w(uint32_t n_bits, uint8_t *mem,
                                     uint32_t mem_size) {
  return rte_bitmap_init(n_bits, mem, mem_size);
}
struct rte_bitmap *rte_bitmap_init_with_all_set_w(uint32_t n_bits, uint8_t *mem,
                                                  uint32_t mem_size) {
  return rte_bitmap_init_with_all_set(n_bits, mem, mem_size);
}
void rte_bitmap_free_w(struct rte_bitmap *bmp) { return rte_bitmap_free(bmp); }
void rte_bitmap_reset_w(struct rte_bitmap *bmp) { rte_bitmap_reset(bmp); }
void rte_bitmap_prefetch0_w(struct rte_bitmap *bmp, uint32_t pos) {
  rte_bitmap_prefetch0(bmp, pos);
}
uint64_t rte_bitmap_get_w(struct rte_bitmap *bmp, uint32_t pos) {
  return rte_bitmap_get(bmp, pos);
}
void rte_bitmap_set_w(struct rte_bitmap *bmp, uint32_t pos) {
  rte_bitmap_set(bmp, pos);
}
void rte_bitmap_set_slab_w(struct rte_bitmap *bmp, uint32_t pos,
                           uint64_t slab) {
  rte_bitmap_set_slab(bmp, pos, slab);
}
void rte_bitmap_clear_w(struct rte_bitmap *bmp, uint32_t pos) {
  rte_bitmap_clear(bmp, pos);
}
int rte_bitmap_scan_w(struct rte_bitmap *bmp, uint32_t *pos, uint64_t *slab) {
  return rte_bitmap_scan(bmp, pos, slab);
}
uint16_t rte_raw_cksum_w(const void *buf, size_t len) {
  return rte_raw_cksum(buf, len);
}
int rte_raw_cksum_mbuf_w(const struct rte_mbuf *m, uint32_t off, uint32_t len,
                         uint16_t *cksum) {
  return rte_raw_cksum_mbuf(m, off, len, cksum);
}
uint8_t rte_ipv4_hdr_len_w(const struct rte_ipv4_hdr *ipv4_hdr) {
  return rte_ipv4_hdr_len(ipv4_hdr);
}
uint16_t rte_ipv4_cksum_w(const struct rte_ipv4_hdr *ipv4_hdr) {
  return rte_ipv4_cksum(ipv4_hdr);
}
uint16_t rte_ipv4_cksum_simple_w(const struct rte_ipv4_hdr *ipv4_hdr) {
  return rte_ipv4_cksum_simple(ipv4_hdr);
}
uint16_t rte_ipv4_phdr_cksum_w(const struct rte_ipv4_hdr *ipv4_hdr,
                               uint64_t ol_flags) {
  return rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
}
uint16_t rte_ipv4_udptcp_cksum_w(const struct rte_ipv4_hdr *ipv4_hdr,
                                 const void *l4_hdr) {
  return rte_ipv4_udptcp_cksum(ipv4_hdr, l4_hdr);
}
uint16_t rte_ipv4_udptcp_cksum_mbuf_w(const struct rte_mbuf *m,
                                      const struct rte_ipv4_hdr *ipv4_hdr,
                                      uint16_t l4_off) {
  return rte_ipv4_udptcp_cksum_mbuf(m, ipv4_hdr, l4_off);
}
int rte_ipv4_udptcp_cksum_verify_w(const struct rte_ipv4_hdr *ipv4_hdr,
                                   const void *l4_hdr) {
  return rte_ipv4_udptcp_cksum_verify(ipv4_hdr, l4_hdr);
}
int rte_ipv4_udptcp_cksum_mbuf_verify_w(const struct rte_mbuf *m,
                                        const struct rte_ipv4_hdr *ipv4_hdr,
                                        uint16_t l4_off) {
  return rte_ipv4_udptcp_cksum_mbuf_verify(m, ipv4_hdr, l4_off);
}
bool rte_ipv6_addr_eq_w(const struct rte_ipv6_addr *a,
                        const struct rte_ipv6_addr *b) {
  return rte_ipv6_addr_eq(a, b);
}
void rte_ipv6_addr_mask_w(struct rte_ipv6_addr *ip, uint8_t depth) {
  rte_ipv6_addr_mask(ip, depth);
}
bool rte_ipv6_addr_eq_prefix_w(const struct rte_ipv6_addr *a,
                               const struct rte_ipv6_addr *b, uint8_t depth) {
  return rte_ipv6_addr_eq_prefix(a, b, depth);
}
uint8_t rte_ipv6_mask_depth_w(const struct rte_ipv6_addr *mask) {
  return rte_ipv6_mask_depth(mask);
}
bool rte_ipv6_addr_is_unspec_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_unspec(ip);
}
bool rte_ipv6_addr_is_loopback_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_loopback(ip);
}
bool rte_ipv6_addr_is_linklocal_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_linklocal(ip);
}
bool rte_ipv6_addr_is_sitelocal_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_sitelocal(ip);
}
bool rte_ipv6_addr_is_v4compat_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_v4compat(ip);
}
bool rte_ipv6_addr_is_v4mapped_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_v4mapped(ip);
}
bool rte_ipv6_addr_is_mcast_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_addr_is_mcast(ip);
}
enum rte_ipv6_mc_scope rte_ipv6_mc_scope_w(const struct rte_ipv6_addr *ip) {
  return rte_ipv6_mc_scope(ip);
}
void rte_ipv6_llocal_from_ethernet_w(struct rte_ipv6_addr *ip,
                                     const struct rte_ether_addr *mac) {
  rte_ipv6_llocal_from_ethernet(ip, mac);
}
void rte_ipv6_solnode_from_addr_w(struct rte_ipv6_addr *sol,
                                  const struct rte_ipv6_addr *ip) {
  rte_ipv6_solnode_from_addr(sol, ip);
}
void rte_ether_mcast_from_ipv6_w(struct rte_ether_addr *mac,
                                 const struct rte_ipv6_addr *ip) {
  rte_ether_mcast_from_ipv6(mac, ip);
}
int rte_ipv6_check_version_w(const struct rte_ipv6_hdr *ip) {
  return rte_ipv6_check_version(ip);
}
uint16_t rte_ipv6_phdr_cksum_w(const struct rte_ipv6_hdr *ipv6_hdr,
                               uint64_t ol_flags) {
  return rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
}
uint16_t rte_ipv6_udptcp_cksum_w(const struct rte_ipv6_hdr *ipv6_hdr,
                                 const void *l4_hdr) {
  return rte_ipv6_udptcp_cksum(ipv6_hdr, l4_hdr);
}
uint16_t rte_ipv6_udptcp_cksum_mbuf_w(const struct rte_mbuf *m,
                                      const struct rte_ipv6_hdr *ipv6_hdr,
                                      uint16_t l4_off) {
  return rte_ipv6_udptcp_cksum_mbuf(m, ipv6_hdr, l4_off);
}
int rte_ipv6_udptcp_cksum_verify_w(const struct rte_ipv6_hdr *ipv6_hdr,
                                   const void *l4_hdr) {
  return rte_ipv6_udptcp_cksum_verify(ipv6_hdr, l4_hdr);
}
int rte_ipv6_udptcp_cksum_mbuf_verify_w(const struct rte_mbuf *m,
                                        const struct rte_ipv6_hdr *ipv6_hdr,
                                        uint16_t l4_off) {
  return rte_ipv6_udptcp_cksum_mbuf_verify(m, ipv6_hdr, l4_off);
}
int rte_ipv6_get_next_ext_w(const uint8_t *p, int proto, size_t *ext_len) {
  return rte_ipv6_get_next_ext(p, proto, ext_len);
}
enum rte_color
rte_meter_srtcm_color_blind_check_w(struct rte_meter_srtcm *m,
                                    struct rte_meter_srtcm_profile *p,
                                    uint64_t time, uint32_t pkt_len) {
  return rte_meter_srtcm_color_blind_check(m, p, time, pkt_len);
}
enum rte_color rte_meter_srtcm_color_aware_check_w(
    struct rte_meter_srtcm *m, struct rte_meter_srtcm_profile *p, uint64_t time,
    uint32_t pkt_len, enum rte_color pkt_color) {
  return rte_meter_srtcm_color_aware_check(m, p, time, pkt_len, pkt_color);
}
enum rte_color
rte_meter_trtcm_color_blind_check_w(struct rte_meter_trtcm *m,
                                    struct rte_meter_trtcm_profile *p,
                                    uint64_t time, uint32_t pkt_len) {
  return rte_meter_trtcm_color_blind_check(m, p, time, pkt_len);
}
enum rte_color rte_meter_trtcm_color_aware_check_w(
    struct rte_meter_trtcm *m, struct rte_meter_trtcm_profile *p, uint64_t time,
    uint32_t pkt_len, enum rte_color pkt_color) {
  return rte_meter_trtcm_color_aware_check(m, p, time, pkt_len, pkt_color);
}
enum rte_color rte_meter_trtcm_rfc4115_color_blind_check_w(
    struct rte_meter_trtcm_rfc4115 *m,
    struct rte_meter_trtcm_rfc4115_profile *p, uint64_t time,
    uint32_t pkt_len) {
  return rte_meter_trtcm_rfc4115_color_blind_check(m, p, time, pkt_len);
}
enum rte_color rte_meter_trtcm_rfc4115_color_aware_check_w(
    struct rte_meter_trtcm_rfc4115 *m,
    struct rte_meter_trtcm_rfc4115_profile *p, uint64_t time, uint32_t pkt_len,
    enum rte_color pkt_color) {
  return rte_meter_trtcm_rfc4115_color_aware_check(m, p, time, pkt_len,
                                                   pkt_color);
}
uint64_t rte_eth_rss_hf_refine_w(uint64_t rss_hf) {
  return rte_eth_rss_hf_refine(rss_hf);
}

uint16_t rte_eth_rx_burst_w(uint16_t port_id, uint16_t queue_id,
                            struct rte_mbuf **rx_pkts, const uint16_t nb_pkts) {
  return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}
int rte_eth_rx_queue_count_w(uint16_t port_id, uint16_t queue_id) {
  return rte_eth_rx_queue_count(port_id, queue_id);
}
int rte_eth_rx_descriptor_status_w(uint16_t port_id, uint16_t queue_id,
                                   uint16_t offset) {
  return rte_eth_rx_descriptor_status(port_id, queue_id, offset);
}
int rte_eth_tx_descriptor_status_w(uint16_t port_id, uint16_t queue_id,
                                   uint16_t offset) {
  return rte_eth_tx_descriptor_status(port_id, queue_id, offset);
}
uint16_t rte_eth_tx_burst_w(uint16_t port_id, uint16_t queue_id,
                            struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
  return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}
uint16_t rte_eth_tx_prepare_w(uint16_t port_id, uint16_t queue_id,
                              struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
  return rte_eth_tx_prepare(port_id, queue_id, tx_pkts, nb_pkts);
}
uint16_t rte_eth_tx_buffer_flush_w(uint16_t port_id, uint16_t queue_id,
                                   struct rte_eth_dev_tx_buffer *buffer) {
  return rte_eth_tx_buffer_flush(port_id, queue_id, buffer);
}
uint16_t rte_eth_tx_buffer_w(uint16_t port_id, uint16_t queue_id,
                             struct rte_eth_dev_tx_buffer *buffer,
                             struct rte_mbuf *tx_pkt) {
  return rte_eth_tx_buffer(port_id, queue_id, buffer, tx_pkt);
}
uint16_t
rte_eth_recycle_mbufs_w(uint16_t rx_port_id, uint16_t rx_queue_id,
                        uint16_t tx_port_id, uint16_t tx_queue_id,
                        struct rte_eth_recycle_rxq_info *recycle_rxq_info) {
  return rte_eth_recycle_mbufs(rx_port_id, rx_queue_id, tx_port_id, tx_queue_id,
                               recycle_rxq_info);
}
int rte_eth_tx_queue_count_w(uint16_t port_id, uint16_t queue_id) {
  return rte_eth_tx_queue_count(port_id, queue_id);
}
uint32_t rte_flow_dynf_metadata_get_w(struct rte_mbuf *m) {
  return rte_flow_dynf_metadata_get(m);
}
void rte_flow_dynf_metadata_set_w(struct rte_mbuf *m, uint32_t v) {
  rte_flow_dynf_metadata_set(m, v);
}
int rte_flow_dynf_metadata_avail_w(void) {
  return rte_flow_dynf_metadata_avail();
}
uint32_t rte_hash_crc_1byte_w(uint8_t data, uint32_t init_val) {
  return rte_hash_crc_1byte(data, init_val);
}
uint32_t rte_hash_crc_2byte_w(uint16_t data, uint32_t init_val) {
  return rte_hash_crc_2byte(data, init_val);
}
uint32_t rte_hash_crc_4byte_w(uint32_t data, uint32_t init_val) {
  return rte_hash_crc_4byte(data, init_val);
}
uint32_t rte_hash_crc_8byte_w(uint64_t data, uint32_t init_val) {
  return rte_hash_crc_8byte(data, init_val);
}
uint32_t rte_hash_crc_w(const void *data, uint32_t data_len,
                        uint32_t init_val) {
  return rte_hash_crc(data, data_len, init_val);
}
void rte_jhash_2hashes_w(const void *key, uint32_t length, uint32_t *pc,
                         uint32_t *pb) {
  rte_jhash_2hashes(key, length, pc, pb);
}
void rte_jhash_32b_2hashes_w(const uint32_t *k, uint32_t length, uint32_t *pc,
                             uint32_t *pb) {
  rte_jhash_32b_2hashes(k, length, pc, pb);
}
uint32_t rte_jhash_w(const void *key, uint32_t length, uint32_t initval) {
  return rte_jhash(key, length, initval);
}
uint32_t rte_jhash_32b_w(const uint32_t *k, uint32_t length, uint32_t initval) {
  return rte_jhash_32b(k, length, initval);
}
uint32_t rte_jhash_3words_w(uint32_t a, uint32_t b, uint32_t c,
                            uint32_t initval) {
  return rte_jhash_3words(a, b, c, initval);
}
uint32_t rte_jhash_2words_w(uint32_t a, uint32_t b, uint32_t initval) {
  return rte_jhash_2words(a, b, initval);
}
uint32_t rte_jhash_1word_w(uint32_t a, uint32_t initval) {
  return rte_jhash_1word(a, initval);
}
uint32_t rte_fbk_hash_get_bucket_w(const struct rte_fbk_hash_table *ht,
                                   uint32_t key) {
  return rte_fbk_hash_get_bucket(ht, key);
}
int rte_fbk_hash_add_key_with_bucket_w(struct rte_fbk_hash_table *ht,
                                       uint32_t key, uint16_t value,
                                       uint32_t bucket) {
  return rte_fbk_hash_add_key_with_bucket(ht, key, value, bucket);
}
int rte_fbk_hash_add_key_w(struct rte_fbk_hash_table *ht, uint32_t key,
                           uint16_t value) {
  return rte_fbk_hash_add_key(ht, key, value);
}
int rte_fbk_hash_delete_key_with_bucket_w(struct rte_fbk_hash_table *ht,
                                          uint32_t key, uint32_t bucket) {
  return rte_fbk_hash_delete_key_with_bucket(ht, key, bucket);
}
int rte_fbk_hash_delete_key_w(struct rte_fbk_hash_table *ht, uint32_t key) {
  return rte_fbk_hash_delete_key(ht, key);
}
int rte_fbk_hash_lookup_with_bucket_w(const struct rte_fbk_hash_table *ht,
                                      uint32_t key, uint32_t bucket) {
  return rte_fbk_hash_lookup_with_bucket(ht, key, bucket);
}
int rte_fbk_hash_lookup_w(const struct rte_fbk_hash_table *ht, uint32_t key) {
  return rte_fbk_hash_lookup(ht, key);
}
void rte_fbk_hash_clear_all_w(struct rte_fbk_hash_table *ht) {
  rte_fbk_hash_clear_all(ht);
}
double rte_fbk_hash_get_load_factor_w(struct rte_fbk_hash_table *ht) {
  return rte_fbk_hash_get_load_factor(ht);
}
void rte_rcu_qsbr_thread_online_w(struct rte_rcu_qsbr *v,
                                  unsigned int thread_id) {
  rte_rcu_qsbr_thread_online(v, thread_id);
}
void rte_rcu_qsbr_thread_offline_w(struct rte_rcu_qsbr *v,
                                   unsigned int thread_id) {
  rte_rcu_qsbr_thread_offline(v, thread_id);
}
void rte_rcu_qsbr_lock_w(struct rte_rcu_qsbr *v, unsigned int thread_id) {
  rte_rcu_qsbr_lock(v, thread_id);
}
void rte_rcu_qsbr_unlock_w(struct rte_rcu_qsbr *v, unsigned int thread_id) {
  rte_rcu_qsbr_unlock(v, thread_id);
}
uint64_t rte_rcu_qsbr_start_w(struct rte_rcu_qsbr *v) {
  return rte_rcu_qsbr_start(v);
}
void rte_rcu_qsbr_quiescent_w(struct rte_rcu_qsbr *v, unsigned int thread_id) {
  rte_rcu_qsbr_quiescent(v, thread_id);
}
int rte_rcu_qsbr_check_w(struct rte_rcu_qsbr *v, uint64_t t, bool wait) {
  return rte_rcu_qsbr_check(v, t, wait);
}
uint8_t rte_read8_relaxed_w(const void *addr) {
  return rte_read8_relaxed(addr);
}
uint16_t rte_read16_relaxed_w(const void *addr) {
  return rte_read16_relaxed(addr);
}
uint32_t rte_read32_relaxed_w(const void *addr) {
  return rte_read32_relaxed(addr);
}
uint64_t rte_read64_relaxed_w(const void *addr) {
  return rte_read64_relaxed(addr);
}
void rte_write8_relaxed_w(uint8_t value, void *addr) {
  rte_write8_relaxed(value, addr);
}
void rte_write16_relaxed_w(uint16_t value, void *addr) {
  rte_write16_relaxed(value, addr);
}
void rte_write32_relaxed_w(uint32_t value, void *addr) {
  rte_write32_relaxed(value, addr);
}
void rte_write64_relaxed_w(uint64_t value, void *addr) {
  rte_write64_relaxed(value, addr);
}
uint8_t rte_read8_w(const void *addr) { return rte_read8(addr); }
uint16_t rte_read16_w(const void *addr) { return rte_read16(addr); }
uint32_t rte_read32_w(const void *addr) { return rte_read32(addr); }
uint64_t rte_read64_w(const void *addr) { return rte_read64(addr); }
void rte_write8_w(uint8_t value, void *addr) { rte_write8(value, addr); }
void rte_write16_w(uint16_t value, void *addr) { rte_write16(value, addr); }
void rte_write32_w(uint32_t value, void *addr) { rte_write32(value, addr); }
void rte_write64_w(uint64_t value, void *addr) { rte_write64(value, addr); }
void rte_write32_wc_relaxed_w(uint32_t value, void *addr) {
  rte_write32_wc_relaxed(value, addr);
}
void rte_write32_wc_w(uint32_t value, void *addr) {
  rte_write32_wc(value, addr);
}
void rte_mcslock_lock_w(rte_mcslock_t **msl, rte_mcslock_t *me) {
  rte_mcslock_lock(msl, me);
}
void rte_mcslock_unlock_w(rte_mcslock_t **msl, rte_mcslock_t *me) {
  rte_mcslock_unlock(msl, me);
}
int rte_mcslock_trylock_w(rte_mcslock_t **msl, rte_mcslock_t *me) {
  return rte_mcslock_trylock(msl, me);
}
int rte_mcslock_is_locked_w(rte_mcslock_t *msl) {
  return rte_mcslock_is_locked(msl);
}
void rte_pflock_init_w(struct rte_pflock *pf) { rte_pflock_init(pf); }
void rte_pflock_read_lock_w(rte_pflock_t *pf) { rte_pflock_read_lock(pf); }
void rte_pflock_read_unlock_w(rte_pflock_t *pf) { rte_pflock_read_unlock(pf); }
void rte_pflock_write_lock_w(rte_pflock_t *pf) { rte_pflock_write_lock(pf); }
void rte_pflock_write_unlock_w(rte_pflock_t *pf) {
  rte_pflock_write_unlock(pf);
}
uint32_t rte_reciprocal_divide_w(uint32_t a, struct rte_reciprocal R) {
  return rte_reciprocal_divide(a, R);
}
uint64_t rte_reciprocal_divide_u64_w(uint64_t a,
                                     const struct rte_reciprocal_u64 *R) {
  return rte_reciprocal_divide_u64(a, R);
}
void rte_seqcount_init_w(rte_seqcount_t *seqcount) {
  rte_seqcount_init(seqcount);
}
uint32_t rte_seqcount_read_begin_w(const rte_seqcount_t *seqcount) {
  return rte_seqcount_read_begin(seqcount);
}
bool rte_seqcount_read_retry_w(const rte_seqcount_t *seqcount,
                               uint32_t begin_sn) {
  return rte_seqcount_read_retry(seqcount, begin_sn);
}
void rte_seqcount_write_begin_w(rte_seqcount_t *seqcount) {
  rte_seqcount_write_begin(seqcount);
}
void rte_seqcount_write_end_w(rte_seqcount_t *seqcount) {
  rte_seqcount_write_end(seqcount);
}
void rte_seqlock_init_w(rte_seqlock_t *seqlock) { rte_seqlock_init(seqlock); }
uint32_t rte_seqlock_read_begin_w(const rte_seqlock_t *seqlock) {
  return rte_seqlock_read_begin(seqlock);
}
bool rte_seqlock_read_retry_w(const rte_seqlock_t *seqlock, uint32_t begin_sn) {
  return rte_seqlock_read_retry(seqlock, begin_sn);
}
void rte_seqlock_write_lock_w(rte_seqlock_t *seqlock) {
  rte_seqlock_write_lock(seqlock);
}
void rte_seqlock_write_unlock_w(rte_seqlock_t *seqlock) {
  rte_seqlock_write_unlock(seqlock);
}
unsigned int rte_stack_push_w(struct rte_stack *s, void *const *obj_table,
                              unsigned int n) {
  return rte_stack_push(s, obj_table, n);
}
unsigned int rte_stack_pop_w(struct rte_stack *s, void **obj_table,
                             unsigned int n) {
  return rte_stack_pop(s, obj_table, n);
}
unsigned int rte_stack_count_w(struct rte_stack *s) {
  return rte_stack_count(s);
}
unsigned int rte_stack_free_count_w(struct rte_stack *s) {
  return rte_stack_free_count(s);
}
uint32_t rte_softrss_w(uint32_t *input_tuple, uint32_t input_len,
                       const uint8_t *rss_key) {
  return rte_softrss(input_tuple, input_len, rss_key);
}
uint32_t rte_softrss_be_w(uint32_t *input_tuple, uint32_t input_len,
                          const uint8_t *rss_key) {
  return rte_softrss_be(input_tuple, input_len, rss_key);
}
void rte_ticketlock_init_w(rte_ticketlock_t *tl) { rte_ticketlock_init(tl); }
void rte_ticketlock_lock_w(rte_ticketlock_t *tl) { rte_ticketlock_lock(tl); }
void rte_ticketlock_unlock_w(rte_ticketlock_t *tl) {
  rte_ticketlock_unlock(tl);
}
int rte_ticketlock_trylock_w(rte_ticketlock_t *tl) {
  return rte_ticketlock_trylock(tl);
}
int rte_ticketlock_is_locked_w(rte_ticketlock_t *tl) {
  return rte_ticketlock_is_locked(tl);
}
void rte_ticketlock_recursive_init_w(rte_ticketlock_recursive_t *tlr) {
  rte_ticketlock_recursive_init(tlr);
}
void rte_ticketlock_recursive_lock_w(rte_ticketlock_recursive_t *tlr) {
  rte_ticketlock_recursive_lock(tlr);
}
void rte_ticketlock_recursive_unlock_w(rte_ticketlock_recursive_t *tlr) {
  rte_ticketlock_recursive_unlock(tlr);
}
int rte_ticketlock_recursive_trylock_w(rte_ticketlock_recursive_t *tlr) {
  return rte_ticketlock_recursive_trylock(tlr);
}
uint64_t rte_cyclecounter_cycles_to_ns_w(struct rte_timecounter *tc,
                                         uint64_t cycles) {
  return rte_cyclecounter_cycles_to_ns(tc, cycles);
}
uint64_t rte_timecounter_update_w(struct rte_timecounter *tc,
                                  uint64_t cycle_now) {
  return rte_timecounter_update(tc, cycle_now);
}
uint64_t rte_timespec_to_ns_w(const struct timespec *ts) {
  return rte_timespec_to_ns(ts);
}
struct timespec rte_ns_to_timespec_w(uint64_t nsec) {
  return rte_ns_to_timespec(nsec);
}
bool rte_trace_feature_is_enabled_w(void) {
  return rte_trace_feature_is_enabled();
}
