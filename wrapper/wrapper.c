#include "wrapper.h"

struct s_mac_addr *mac;			/* MAC address of the device */
char *dev;				/* capture device name */
int  dev_index;				/* capture device index */

int main(int argc, char **argv)
{

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	//char filter_exp[] = "ip6";		/* filter expression */
	char filter_exp[] = "icmp6";		/* filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	int num_packets = 0;			/* number of packets to capture; 0 = infinite */

	/* find a capture device */
	dev = NULL;
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
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

	/* get index of the device */
	dev_index = get_dev_index(dev);

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
	pcap_loop(handle, num_packets, process_packet6, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}
