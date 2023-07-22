#include "tcp_util.h"

// Create and initialize the TCP Control Blocks for all flows
void init_tcp_blocks() {
	// allocate the all control block structure previosly
	tcp_control_blocks = (tcp_control_block_t *) rte_zmalloc("tcp_control_blocks", nr_flows * sizeof(tcp_control_block_t), RTE_CACHE_LINE_SIZE);

	// choose TCP source port for all flows
	uint16_t src_tcp_port;
	uint16_t ports[nr_flows];
	for(uint32_t i = 0; i < nr_flows; i++) {
		ports[i] = rte_cpu_to_be_16((i % nr_flows) + 1);
	}

	for(uint32_t i = 0; i < nr_flows; i++) {
		rte_atomic16_init(&tcp_control_blocks[i].tcb_state);
		rte_atomic16_set(&tcp_control_blocks[i].tcb_state, TCP_INIT);
		rte_atomic16_set(&tcp_control_blocks[i].tcb_rwin, 0xFFFF);

		src_tcp_port = ports[i];

		tcp_control_blocks[i].src_addr = src_ipv4_addr;
		tcp_control_blocks[i].dst_addr = dst_ipv4_addr;

		tcp_control_blocks[i].src_port = src_tcp_port;
		tcp_control_blocks[i].dst_port = rte_cpu_to_be_16(dst_tcp_port);

		uint32_t seq = rte_rand();
		tcp_control_blocks[i].tcb_seq_ini = seq;
		tcp_control_blocks[i].tcb_next_seq = seq;

		tcp_control_blocks[i].flow_mark_action.id = i;
		tcp_control_blocks[i].flow_queue_action.index = 0;
		tcp_control_blocks[i].flow_eth.type = ETH_IPV4_TYPE_NETWORK;
		tcp_control_blocks[i].flow_eth_mask.type = 0xFFFF;
		tcp_control_blocks[i].flow_ipv4.hdr.src_addr = tcp_control_blocks[i].dst_addr;
		tcp_control_blocks[i].flow_ipv4.hdr.dst_addr = tcp_control_blocks[i].src_addr;
		tcp_control_blocks[i].flow_ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
		tcp_control_blocks[i].flow_ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
		tcp_control_blocks[i].flow_tcp.hdr.src_port = tcp_control_blocks[i].dst_port;
		tcp_control_blocks[i].flow_tcp.hdr.dst_port = tcp_control_blocks[i].src_port;
		tcp_control_blocks[i].flow_tcp_mask.hdr.src_port = 0xFFFF;
		tcp_control_blocks[i].flow_tcp_mask.hdr.dst_port = 0xFFFF;
	}
}

// Fill the TCP packets from TCP Control Block data
void fill_tcp_packet(tcp_control_block_t *block, struct rte_mbuf *pkt) {
	// ensure that IP/TCP checksum offloadings
	pkt->ol_flags |= (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM);

	// fill Ethernet information
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->dst_addr = dst_eth_addr;
	eth_hdr->src_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

	// fill IPv4 information
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->total_length = rte_cpu_to_be_16(frame_size - sizeof(struct rte_ether_hdr));
	ipv4_hdr->time_to_live = 255;
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->next_proto_id = IPPROTO_TCP;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->src_addr = block->src_addr;
	ipv4_hdr->dst_addr = block->dst_addr;
	ipv4_hdr->hdr_checksum = 0;

	// set the TCP SEQ number
	uint32_t sent_seq = block->tcb_next_seq;

	// fill TCP information
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp_hdr->dst_port = block->dst_port;
	tcp_hdr->src_port = block->src_port;
	tcp_hdr->data_off = 0x50;
	tcp_hdr->sent_seq = sent_seq;
	tcp_hdr->recv_ack = rte_atomic32_read(&block->tcb_next_ack);
	tcp_hdr->rx_win = 0xFFFF;
	tcp_hdr->tcp_flags = RTE_TCP_PSH_FLAG|RTE_TCP_ACK_FLAG;
	tcp_hdr->tcp_urp = 0;
	tcp_hdr->cksum = 0;

	// updates the TCP SEQ number
	sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(sent_seq) + tcp_payload_size);
	block->tcb_next_seq = sent_seq;

	// fill the packet size
	pkt->data_len = frame_size;
	pkt->pkt_len = pkt->data_len;
}
