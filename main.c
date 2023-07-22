#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"
#include "tcp_util.h"
#include "dpdk_util.h"

// Application parameters
uint64_t rate;
uint32_t seed;
uint64_t duration;
uint64_t nr_flows;
uint64_t nr_queues;
uint32_t min_lcores;
uint32_t frame_size;
uint32_t tcp_payload_size;

// General variables
uint64_t TICKS_PER_US;
uint16_t **flow_indexes_array;
uint32_t **interarrival_array;
application_node_t **application_array;

// Heap and DPDK allocated
uint32_t incoming_idx;
node_t *incoming_array;
struct rte_mempool *pktmbuf_pool_rx;
struct rte_mempool *pktmbuf_pool_tx;
tcp_control_block_t *tcp_control_blocks;

// Internal threads variables
uint8_t quit_rx = 0;
uint8_t quit_tx = 0;
uint8_t quit_rx_ring = 0;
uint32_t *nr_never_sent = 0;
lcore_param lcore_params[RTE_MAX_LCORE];
struct rte_ring *rx_ring;

// Connection variables
uint16_t dst_tcp_port;
uint32_t dst_ipv4_addr;
uint32_t src_ipv4_addr;
struct rte_ether_addr dst_eth_addr;
struct rte_ether_addr src_eth_addr;

// Process the incoming TCP packet
int process_rx_pkt(struct rte_mbuf *pkt, node_t *incoming, uint32_t *incoming_idx) {
	// process only TCP packets
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	if(unlikely(ipv4_hdr->next_proto_id != IPPROTO_TCP)) {
		return 0;
	}

	// get TCP header
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + (ipv4_hdr->version_ihl & 0x0f)*4);

	// get TCP payload size
	uint32_t packet_data_size = rte_be_to_cpu_16(ipv4_hdr->total_length) - ((ipv4_hdr->version_ihl & 0x0f)*4) - ((tcp_hdr->data_off >> 4)*4);

	// do not process empty packets
	if(unlikely(packet_data_size == 0)) {
		return 0;
	}

	// obtain both timestamp from the packet
	uint64_t *payload = (uint64_t *)(((uint8_t*) tcp_hdr) + ((tcp_hdr->data_off >> 4)*4));
	uint64_t t0 = payload[0];
	uint64_t t1 = payload[1];

	// fill the node previously allocated
	node_t *node = &incoming[(*incoming_idx)++];
	node->timestamp_tx = t0;
	node->timestamp_rx = t1;

	return 1;
}

// RX processing
static int lcore_rx_ring(void *arg) {
	uint16_t nb_rx;
	struct rte_mbuf *pkts[BURST_SIZE];

	incoming_idx = 0;

	while(!quit_rx_ring) {
		// retrieve packets from the RX core
		nb_rx = rte_ring_sc_dequeue_burst(rx_ring, (void**) pkts, BURST_SIZE, NULL); 
		for(int i = 0; i < nb_rx; i++) {
			// process the incoming packet
			process_rx_pkt(pkts[i], incoming_array, &incoming_idx);
			// free the packet
			rte_pktmbuf_free(pkts[i]);
		}
	}

	// process all remaining packets that are in the RX ring (not from the NIC)
	do{
		nb_rx = rte_ring_sc_dequeue_burst(rx_ring, (void**) pkts, BURST_SIZE, NULL);
		for(int i = 0; i < nb_rx; i++) {
			// process the incoming packet
			process_rx_pkt(pkts[i], incoming_array, &incoming_idx);
			// free the packet
			rte_pktmbuf_free(pkts[i]);
		}
	} while (nb_rx != 0);

	return 0;
}

// Main RX processing
static int lcore_rx(void *arg) {
	uint16_t portid = 0;
	uint8_t qid = 0;

	uint64_t now;
	uint16_t nb_rx;
	uint16_t nb_pkts;
	struct rte_mbuf *pkts[BURST_SIZE];
	
	while(!quit_rx) {
		// retrieve the packets from the NIC
		nb_rx = rte_eth_rx_burst(portid, qid, pkts, BURST_SIZE);

		// retrive the current timestamp
		now = rte_rdtsc();
		for(int i = 0; i < nb_rx; i++) {
			// fill the timestamp into packet payload
			fill_payload_pkt(pkts[i], 1, now);
		}

		// enqueue the packets to the ring
		nb_pkts = rte_ring_sp_enqueue_burst(rx_ring, (void* const*) pkts, nb_rx, NULL);
		if(unlikely(nb_pkts != nb_rx)) {
			rte_exit(EXIT_FAILURE, "Cannot enqueue the packet to the RX thread: %s.\n", rte_strerror(errno));
		}
	}

	return 0;
}

// Main TX processing
static int lcore_tx(void *arg) {
	lcore_param *tx_conf = (lcore_param *) arg;
	uint16_t portid = tx_conf->portid;
	uint8_t qid = tx_conf->qid;
	uint64_t nr_elements = tx_conf->nr_elements;

	struct rte_mbuf *pkt;
	uint16_t *flow_indexes = flow_indexes_array[qid];
	uint32_t *interarrival_gap = interarrival_array[qid];
	application_node_t *app_array = application_array[qid];

	uint64_t next_tsc = rte_rdtsc() + interarrival_gap[0];

	for(uint64_t i = 0; i < nr_elements; i++) {
		// unable to keep up with the requested rate
		if(unlikely(rte_rdtsc() > (next_tsc + 5*TICKS_PER_US))) {
			// count this batch as dropped
			nr_never_sent[qid]++;
			next_tsc += (interarrival_gap[i] + TICKS_PER_US);
			continue;
		}

		// choose the flow to send
		uint16_t flow_id = flow_indexes[i];
		tcp_control_block_t *block = &tcp_control_blocks[flow_id];

		// get the packet
		pkt = rte_pktmbuf_alloc(pktmbuf_pool_tx);
		fill_tcp_packet(block, pkt);

		// fill the timestamp, flow id, server iterations, and server randomness into the packet payload
		fill_payload_pkt(pkt, 0, next_tsc);

		// sleep for while
		while (rte_rdtsc() < next_tsc) { }

		// send the packet
		rte_eth_tx_burst(portid, qid, &pkt, 1);

		// update the counter
		next_tsc += interarrival_gap[i];
	}

	return 0;
}

// main function
int main(int argc, char **argv) {
	// init EAL
	int ret = rte_eal_init(argc, argv);
	if(ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	}

	argc -= ret;
	argv += ret;

	// parse application arguments (after the EAL ones)
	ret = app_parse_args(argc, argv);
	if(ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");
	}

	// initialize DPDK
	uint16_t portid = 0;
	init_DPDK(portid, nr_queues, seed);

	// create nodes for incoming packets
	create_incoming_array();

	// create flow indexes array
	create_flow_indexes_array();

	// create interarrival array
	create_interarrival_array();

	// create application array
	create_application_array();

	// initialize TCP control blocks
	init_tcp_blocks();

	// create the DPDK ring for RX thread
	create_dpdk_ring();

	// start RX thread to process incoming packets
	uint32_t id_lcore = rte_lcore_id();
	id_lcore = rte_get_next_lcore(id_lcore, 1, 1);
	rte_eal_remote_launch(lcore_rx_ring, NULL, id_lcore);

	// start RX thread to receive incoming packets
	id_lcore = rte_get_next_lcore(id_lcore, 1, 1);
	rte_eal_remote_launch(lcore_rx, NULL, id_lcore);

	// start TX threads
	for(int i = 0; i < nr_queues; i++) {
		lcore_params[i].portid = portid;
		lcore_params[i].qid = i;
		lcore_params[i].nr_elements = (rate/nr_queues) * 2 * duration;

		id_lcore = rte_get_next_lcore(id_lcore, 1, 1);
		rte_eal_remote_launch(lcore_tx, (void*) &lcore_params[i], id_lcore);
	}

	// wait for duration parameter
	wait_timeout();

	// wait for RX/TX threads
	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if(rte_eal_wait_lcore(lcore_id) < 0) {
			return -1;
		}
	}

	// print stats
	print_stats_output();

	// print DPDK stats
	print_dpdk_stats(portid);

	// clean up
	clean_heap();
	clean_hugepages();

	return 0;
}
