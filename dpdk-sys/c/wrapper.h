#include "dpdk.h"

/**
 * Thin wrapper to expose `rte_errno`.
 *
 * @return
 *   The last rte_errno value (thread local value).
 */
__rte_hot
__rte_warn_unused_result
int wrte_errno();

///**
// * DPDK specific error codes.
// *
// * I wrapped these because the original enum is anonymous (this irritates me).
// */
//enum wrte_errno : uint32_t {
//	RTE_MIN_ERRNO = __ELASTERROR, /**< Start numbering above std errno vals */
//
//	E_RTE_SECONDARY, /**< Operation not allowed in secondary processes */
//	E_RTE_NO_CONFIG, /**< Missing rte_config */
//
//	RTE_MAX_ERRNO    /**< Max RTE error number */
//};

/**
 * TX offloads to be set in [`rte_eth_tx_mode.offloads`].
 *
 * This is a bitfield.  Union these to enable multiple offloads.
 *
 * I wrapped these because the enum must be explicitly typed as 64 bit, but
 * DPDK is not yet using the C23 standard (which would allow the inheritance
 * notation with `uint64_t` seen here.).
 */
enum wrte_eth_tx_offload: uint64_t {
  VLAN_INSERT      = RTE_ETH_TX_OFFLOAD_VLAN_INSERT,
  IPV4_CKSUM       = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
  UDP_CKSUM        = RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
  TCP_CKSUM        = RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
  SCTP_CKSUM       = RTE_ETH_TX_OFFLOAD_SCTP_CKSUM,
  TCP_TSO          = RTE_ETH_TX_OFFLOAD_TCP_TSO,
  UDP_TSO          = RTE_ETH_TX_OFFLOAD_UDP_TSO,
  OUTER_IPV4_CKSUM = RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM,
  QINQ_INSERT      = RTE_ETH_TX_OFFLOAD_QINQ_INSERT,
  VXLAN_TNL_TSO    = RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO,
  GRE_TNL_TSO      = RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO,
  IPIP_TNL_TSO     = RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO,
  GENEVE_TNL_TSO   = RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO,
  MACSEC_INSERT    = RTE_ETH_TX_OFFLOAD_MACSEC_INSERT,
};


/**
 * Thin wrapper around `rte_eth_rx_burst`.
 *
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The index of the receive queue on the Ethernet device.
 * @param rx_pkts
 *   The address of an array of pointers to [`rte_mbuf`] structures that must be
 *   large enough to store `nb_pkts` pointers in it.
 * @param nb_pkts
 *   The maximum number of packets to receive.
 * @return
 *   The number of packets received, which is the number of [`rte_mbuf`] structures
 */
__rte_hot
__rte_warn_unused_result
uint16_t wrte_eth_rx_burst(uint16_t const port_id, uint16_t const queue_id, struct rte_mbuf **rx_pkts, uint16_t const nb_pkts);

/**
 * Thin wrapper around [`rte_eth_tx_burst`].
 *
 * @param port_id
 *   The port identifier of the Ethernet device.
 * @param queue_id
 *   The index of the transmit queue on the Ethernet device.
 * @param tx_pkts
 *   The address of an array of pointers to [`rte_mbuf`] structures that contain
 * @param nb_pkts
 *   The number of packets to transmit.
 * @return
 *   The number of packets actually sent.
 */
__rte_hot
__rte_warn_unused_result
uint16_t wrte_eth_tx_burst(uint16_t const port_id, uint16_t const queue_id, struct rte_mbuf **tx_pkts, uint16_t const nb_pkts);
