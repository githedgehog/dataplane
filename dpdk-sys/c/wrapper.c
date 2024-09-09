#include "wrapper.h"

int wrte_errno() {
    return rte_errno;
}

uint16_t wrte_eth_rx_burst(uint16_t const port_id, uint16_t const queue_id, struct rte_mbuf **rx_pkts, uint16_t const nb_pkts) {
	return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t wrte_eth_tx_burst(uint16_t const port_id, uint16_t const queue_id, struct rte_mbuf **tx_pkts, uint16_t const nb_pkts) {
	return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}
