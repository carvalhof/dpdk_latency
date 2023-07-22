#include "util.h"

int distribution;
char output_file[MAXSTRLEN];

// Sample the value using Exponential Distribution
double sample(double lambda) {
	double u = rte_drand();
	return -log(1 - u) / lambda;
}

// Convert string type into int type
static uint32_t process_int_arg(const char *arg) {
	char *end = NULL;

	return strtoul(arg, &end, 10);
}

// Allocate nodes for all incoming packets
void create_incoming_array() {
	incoming_array = (node_t*) rte_malloc(NULL, nr_packets * 1.4 * sizeof(node_t), 0);
	if(incoming_array == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot alloc the incoming array.\n");
	}
} 

// Allocate and create an array for all flow indentier to send to the server
void create_flow_indexes_array() {
	flow_indexes_array = (uint16_t*) rte_malloc(NULL, nr_packets * sizeof(uint16_t), 0);
	if(flow_indexes_array == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot alloc the flow_indexes array.\n");
	}

	for(uint64_t i = 0; i < nr_packets; i++) {
		flow_indexes_array[i] = i % nr_flows;
	}
}

// Clean up all allocate structures
void clean_heap() {
	rte_free(incoming_array);
	rte_free(flow_indexes_array);
	rte_free(interarrival_array);
	rte_free(application_array);
}

// Usage message
static void usage(const char *prgname) {
	printf("%s [EAL options] -- \n"
		"  -f FLOWS: number of flows\n"
		"  -s SIZE: frame size in bytes\n"
		"  -t TIME: time in seconds to send packets\n"
		"  -e SEED: seed\n"
		"  -c FILENAME: name of the configuration file\n"
		"  -o FILENAME: name of the output file\n"
		prgname
	);
}

// Parse the argument given in the command line of the application
int app_parse_args(int argc, char **argv) {
	int opt, ret;
	char **argvopt;
	char *prgname = argv[0];

	argvopt = argv;
	while ((opt = getopt(argc, argvopt, "a:f:s:t:c:C:o:e:i:")) != EOF) {
		switch (opt) {
		// flows
		case 'f':
			nr_flows = process_int_arg(optarg);
			break;

		// frame size (bytes)
		case 's':
			frame_size = process_int_arg(optarg);
			if (frame_size < MIN_PKTSIZE) {
				rte_exit(EXIT_FAILURE, "The minimum packet size is %d.\n", MIN_PKTSIZE);
			}
			tcp_payload_size = (frame_size - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr));
			break;

		// duration (s)
		case 't':
			duration = process_int_arg(optarg);
			break;
		
		// seed
		case 'e':
			seed = process_int_arg(optarg);
			break;

		// config file name
		case 'c':
			process_config_file(optarg);
			break;
		
		// output mode
		case 'o':
			strcpy(output_file, optarg);
			break;

		default:
			usage(prgname);
			rte_exit(EXIT_FAILURE, "Invalid arguments.\n");
		}
	}

	if(optind >= 0) {
		argv[optind - 1] = prgname;
	}

	ret = optind-1;
	optind = 1;

	return ret;
}

// Wait for the duration parameter
void wait_timeout() {
	uint32_t remaining_in_s = 5;
	rte_delay_us_sleep((2 * duration + remaining_in_s) * 1000000);

	// set quit flag for all internal cores
	quit_rx = 1;
	quit_tx = 1;
	quit_rx_ring = 1;
}

// Compare two double values (for qsort function)
int cmp_func(const void * a, const void * b) {
	double da = (*(double*)a);
	double db = (*(double*)b);

	return (da - db) > ( (fabs(da) < fabs(db) ? fabs(db) : fabs(da)) * EPSILON);
}

// Print stats into output file
void print_stats_output() {
	// open the file
	FILE *fp = fopen(output_file, "w");
	if(fp == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot open the output file.\n");
	}

	uint64_t total_never_sent = nr_never_sent;
	if((incoming_idx + total_never_sent) != nr_packets) {
		printf("ERROR: received %d and %ld never sent\n", incoming_idx, total_never_sent);
		fclose(fp);
		return;
	}

	printf("\nStart/End -- %s -- %s\n", csv_start_time, csv_end_time);
	printf("incoming_idx = %d -- never_sent = %ld\n", incoming_idx, total_never_sent);
	uint64_t j = nr_packets/2;

	// print the RTT latency in (ns)
	node_t *cur;
	for(; j < incoming_idx; j++) {
		cur = &incoming_array[j];

		fprintf(fp, "%lu\n", 
			((uint64_t)((cur->timestamp_rx - cur->timestamp_tx)/((double)TICKS_PER_US/1000)))
		);
	}

	// close the file
	fclose(fp);
}

// Process the config file
void process_config_file(char *cfg_file) {
	// open the file
	struct rte_cfgfile *file = rte_cfgfile_load(cfg_file, 0);
	if(file == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n", cfg_file);
	}

	// load ethernet addresses
	char *entry = (char*) rte_cfgfile_get_entry(file, "ethernet", "src");
	if(entry) {
		rte_ether_unformat_addr((const char*) entry, &src_eth_addr);
	}
	entry = (char*) rte_cfgfile_get_entry(file, "ethernet", "dst");
	if(entry) {
		rte_ether_unformat_addr((const char*) entry, &dst_eth_addr);
	}

	// load ipv4 addresses
	entry = (char*) rte_cfgfile_get_entry(file, "ipv4", "src");
	if(entry) {
		uint8_t b3, b2, b1, b0;
		sscanf(entry, "%hhd.%hhd.%hhd.%hhd", &b3, &b2, &b1, &b0);
		src_ipv4_addr = IPV4_ADDR(b3, b2, b1, b0);
	}
	entry = (char*) rte_cfgfile_get_entry(file, "ipv4", "dst");
	if(entry) {
		uint8_t b3, b2, b1, b0;
		sscanf(entry, "%hhd.%hhd.%hhd.%hhd", &b3, &b2, &b1, &b0);
		dst_ipv4_addr = IPV4_ADDR(b3, b2, b1, b0);
	}

	// load TCP destination port
	entry = (char*) rte_cfgfile_get_entry(file, "tcp", "dst");
	if(entry) {
		uint16_t port;
		sscanf(entry, "%hu", &port);
		dst_tcp_port = port;
	}

	// close the file
	rte_cfgfile_close(file);
}

// Fill the data into packet payload properly
inline void fill_payload_pkt(struct rte_mbuf *pkt, uint32_t i, uint64_t value) {
	uint8_t *payload = (uint8_t*) rte_pktmbuf_mtod_offset(pkt, uint8_t*, PAYLOAD_OFFSET);

	((uint64_t*) payload)[i] = value;
}
