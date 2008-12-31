#include "wrapper.h"
#include "translate_ip.h"

void process_packet6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;			/* packet counter */

	/* declare pointers to packet headers */
	const struct s_ethernet *ethernet;	/* The ethernet header [1] */
	const struct s_ip6 *ip;			/* The IP header */
	const unsigned char *payload;			/* Packet payload */

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct s_ethernet*) (packet);

	/* define/compute ip header offset */
	ip = (struct s_ip6*) (packet + SIZE_ETHERNET);

	payload = packet + SIZE_ETHERNET + SIZE_IP6;

	/* print source and destination IP addresses */
	char ip6addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip->ip_src, ip6addr, sizeof(ip6addr));
	printf("       From: %s\n", ip6addr);
	/* keep the following line as the last one inet_ntop! */
	inet_ntop(AF_INET6, &ip->ip_dest, ip6addr, sizeof(ip6addr));
	printf("         To: %s\n", ip6addr);

	/* check if this packet is ours - hardcoded for now */
	char wsaddr[INET6_ADDRSTRLEN] = "fc00:1::4d4b:4c03";
	if (strcmp(wsaddr, ip6addr) != 0) {
		printf("==> This packet is not ours! <==\n");
		return;
	}

	/* determine protocol */
	switch (ip->next_header) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			//process_tcp();
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			break;
		case IPPROTO_ICMPV6:
			printf("   Protocol: ICMPv6\n");
			process_icmp6((struct s_ip6 *) ip, payload);
			break;
		default:
			printf("   Protocol: unknown\n");
			break;
	}
	return;
}

void process_icmp6(struct s_ip6 *ip, const unsigned char *payload)
{
	struct s_icmp *icmp;
	struct in_addr ip4_addr;

	unsigned char *icmp_data;
	unsigned char *icmp_packet;

	int packet_size;

	/* extract the ICMP header */
	icmp = (struct s_icmp *) (payload);
	icmp_data = (unsigned char *) (payload + sizeof(icmp));

	/* decide what type of ICMP we have */
	switch (icmp->type) {
		/* NDP */
		case ICMP6_NDP_NS:
			printf("       ICMP: [NDP] Neighbor Solicitation\n");
			break;
		case ICMP6_NDP_NA:
			printf("       ICMP: [NDP] Neighbor Advertisement\n");
			break;
		case ICMP6_NDP_RS:
			printf("       ICMP: [NDP] Router Solicitation\n");
			break;
		case ICMP6_NDP_RA:
			printf("       ICMP: [NDP] Router Advertisement\n");
			break;
		case ICMP6_NDP_RM:
			printf("       ICMP: [NDP] Redirect Message\n");
			break;
		/* ping */
		case ICMP6_ECHO_REQUEST:
			printf("       ICMP: Echo Request\n");

			packet_size = htons(ip->len);
			icmp_packet = (unsigned char *) malloc(packet_size);

			if (icmp_packet == NULL) {
				fprintf(stderr, "Fatal error! Lack of free memory!\n");
				exit(EXIT_FAILURE);
			}

			struct s_icmp_ping *icmp_ping = (struct s_icmp_ping *) icmp_data;

			icmp->type = ICMP4_ECHO_REQUEST;
			icmp->code = 0;
			icmp->checksum = 0;

			printf("[id;seq]:[0x%x;0x%x]\n", htons(icmp_ping->id), htons(icmp_ping->seq));

			memcpy(icmp_packet, icmp, sizeof(struct s_icmp));
			memcpy(icmp_packet + sizeof(struct s_icmp), icmp_data, packet_size - sizeof(struct s_icmp));

			// compute the checksum :c)
			icmp->checksum = checksum(icmp_packet, packet_size);

			// copy this structure again - because of the checksum
			memcpy(icmp_packet, icmp, sizeof(struct s_icmp));

			break;
		case ICMP6_ECHO_REPLY:
			printf("       ICMP: Echo Reply\n");
			break;
		default:
			printf("       ICMP: unknown: %d/0x%x\n", icmp->type, icmp->type);
			break;
	}

	/* where to send this ICMP */
	ip4_addr = ipaddr_6to4((struct in6_addr) ip->ip_dest);
	printf("    Send to: %s\n", inet_ntoa(ip4_addr));

	/* send */
	send_there(ip4_addr, ip->hop_limit, IPPROTO_ICMP, icmp_packet, packet_size);

	free(icmp_packet);
	icmp_packet = NULL;

	return;
}
