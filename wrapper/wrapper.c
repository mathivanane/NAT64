#include "wrapper.h"
#include "storage.h"

struct s_mac_addr *mac;			/* MAC address of the device */
char		  *dev;			/* capture device name */
int		   dev_index;		/* capture device index */
struct in_addr	  *dev_ip;		/* IP address associated with the device */
struct in6_addr    ip6addr_wrapsix;	/* IPv6 prefix of WrapSix addresses */
struct in_addr	   ip4addr_wrapsix;	/* IPv4 address for WrapSix */

/* storage trees */
jsw_rbtree_t *stg_conn_tcp;
jsw_rbtree_t *stg_conn_udp;
jsw_rbtree_t *stg_conn_icmp;

/*
 * 1: IPv4 address
 * 2: IPv6 prefix
 * 3: ethernet device
 */
int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "";			/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	int num_packets = 0;			/* number of packets to capture; 0 = infinite */

	/* initialize the storage for connections */
	stg_conn_tcp  = jsw_rbnew(&stg_conn_tup_cmp, &stg_conn_tup_dup, &stg_conn_tup_rel);
	stg_conn_udp  = jsw_rbnew(&stg_conn_tup_cmp, &stg_conn_tup_dup, &stg_conn_tup_rel);
	stg_conn_icmp = jsw_rbnew(&stg_conn_icmp_cmp, &stg_conn_icmp_dup, &stg_conn_icmp_rel);

	/* find a capture device */
	dev = NULL;
	printf("Args: %d\n", argc);
	if (argc == 4) {
		if ((dev = malloc(strlen(argv[3]))) == NULL) {
			fprintf(stderr, "Fatal Error! Lack of free memory!\n");
			exit(EXIT_FAILURE);
		}
		memcpy(dev, argv[3], sizeof(dev));
	}
	else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* obtain MAC address of the device */
	mac = (struct s_mac_addr *) malloc(sizeof(struct s_mac_addr));
	if (get_mac_addr(dev, mac) != 0) {
		fprintf(stderr, "Couldn't get device MAC address\n");
		exit(EXIT_FAILURE);
	}

	/* obtain IP address of the device */
	dev_ip = (struct in_addr *) malloc(sizeof(struct in_addr));
	if (get_ip_addr(dev, dev_ip) != 0) {
		fprintf(stderr, "Couldn't get device IP address\n");
		exit(EXIT_FAILURE);
	}

	/* get index of the device */
	dev_index = get_dev_index(dev);

	/* set the WrapSix addresses */
	//inet_aton("10.0.0.111", &ip4addr_wrapsix);
	//inet_pton(AF_INET6, "fc00:1::", &ip6addr_wrapsix);
	inet_aton(argv[1], &ip4addr_wrapsix);
	inet_pton(AF_INET6, argv[2], &ip6addr_wrapsix);

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, process_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	jsw_rbdelete(stg_conn_tcp);
	jsw_rbdelete(stg_conn_udp);
	jsw_rbdelete(stg_conn_icmp);

	free(mac);
	free(dev_ip);

	printf("\nCapture complete.\n");

	return 0;
}
