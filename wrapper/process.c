#include "wrapper.h"
#include "translate_ip.h"

struct in6_addr ip6addr_wrapsix;

void process_packet6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct s_ethernet *ethernet;	/* the ethernet header */
	const struct s_ip6 *ip;			/* the IP header */
	const unsigned char *payload;		/* packet payload */

	struct in6_addr ip6addr_ndp_multicast;

	/* define ethernet header */
	ethernet = (struct s_ethernet*) (packet);

	/* define/compute IP header offset */
	ip = (struct s_ip6*) (packet + SIZE_ETHERNET);

	/* define/compute IP payload offset */
	payload = packet + SIZE_ETHERNET + SIZE_IP6;

	/* DEBUG: print source and destination IP addresses */
	char ip6addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip->ip_src, ip6addr, sizeof(ip6addr));
	printf("\n       From: %s\n", ip6addr);
	inet_ntop(AF_INET6, &ip->ip_dest, ip6addr, sizeof(ip6addr));
	printf("         To: %s\n", ip6addr);

	/* check if this packet is ours - partially hardcoded for now */
	inet_pton(AF_INET6, "fc00:1::", &ip6addr_wrapsix);
	inet_pton(AF_INET6, "ff02::1:ff00:0", &ip6addr_ndp_multicast);
	/* check for our prefix || NDP */
	if (memcmp(&ip6addr_wrapsix, &ip->ip_dest, 12) != 0
	 && memcmp(&ip6addr_ndp_multicast, &ip->ip_dest, 13) != 0) {
		printf("==> This packet is not ours! And it's not NDP! <==\n");
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
			process_icmp6((const struct s_ethernet *) ethernet, (struct s_ip6 *) ip, payload);
			break;
		default:
			printf("   Protocol: unknown\n");
			break;
	}
	return;
}

void process_icmp6(const struct s_ethernet *eth, struct s_ip6 *ip, const unsigned char *payload)
{
	struct s_icmp *icmp;
	struct in_addr ip4_addr;

	unsigned char *icmp_data;
	unsigned char *icmp_packet;

	int packet_size = htons(ip->len);

	/* define ICMP header */
	icmp = (struct s_icmp *) (payload);
	/* define/compute ICMP data offset */
	icmp_data = (unsigned char *) (payload + sizeof(struct s_icmp));

	/* decide what type of ICMP we have */
	switch (icmp->type) {
		/* NDP */
		case ICMP6_NDP_NS:
			printf("       ICMP: [NDP] Neighbor Solicitation\n");

			process_ndp(eth, ip, icmp_data);

			return;
		/* ping */
		case ICMP6_ECHO_REQUEST:
			printf("       ICMP: Echo Request\n");

			/* DEBUG */
			struct s_icmp_ping *icmp_ping = (struct s_icmp_ping *) icmp_data;
			printf("[id;seq]:[0x%x;0x%x]\n", htons(icmp_ping->id), htons(icmp_ping->seq));

			/* fill into the header known statements */
			icmp->type = ICMP4_ECHO_REQUEST;
			icmp->code = 0;

			break;
		case ICMP6_ECHO_REPLY:
			printf("       ICMP: Echo Reply\n");
			return;
			break;
		/* nothing interesting */
		default:
			printf("       ICMP: unknown: %d/0x%x\n", icmp->type, icmp->type);
			return;
			break;
	}

	/* create one big ICMP packet */
	icmp_packet = (unsigned char *) malloc(packet_size);

	if (icmp_packet == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* the checksum has to be zeros before we have data for its computation */
	icmp->checksum = 0;

	/* copy data into the packet */
	memcpy(icmp_packet, icmp, sizeof(struct s_icmp));
	memcpy(icmp_packet + sizeof(struct s_icmp), icmp_data, packet_size - sizeof(struct s_icmp));

	/* compute the checksum */
	icmp->checksum = checksum(icmp_packet, packet_size);

	/* copy this structure again - because of the checksum */
	memcpy(icmp_packet, icmp, sizeof(struct s_icmp));

	/* decide where to send this ICMP */
	ip4_addr = ipaddr_6to4((struct in6_addr) ip->ip_dest);
	printf("    Send to: %s\n", inet_ntoa(ip4_addr));

	/* send */
	send_there(ip4_addr, ip->hop_limit, IPPROTO_ICMP, icmp_packet, packet_size);

	/* free allocated memory */
	free(icmp_packet);
	icmp_packet = NULL;
}

void process_ndp(const struct s_ethernet *eth_hdr, struct s_ip6 *ip_hdr, unsigned char *icmp_data)
{
	unsigned char		*packet;
	struct s_ethernet	*eth;
	struct ip6_hdr		*ip;
	struct s_icmp		*icmp;
	struct s_icmp_ndp_ns	*ndp_ns;
	struct s_icmp_ndp_na	*ndp_na;

	unsigned char		*buf_ip6_pseudo;
	struct s_ip6_pseudo	*ip6_pseudo;

	int packet_size;

	/* get the NDP data */
	ndp_ns = (struct s_icmp_ndp_ns *) icmp_data;

	/* check if the requested address is ours */
	if (memcmp(&ip6addr_wrapsix, &ndp_ns->target, 12) != 0) {
		printf("==> This NDP is not ours! <==\n");
		return;
	}

	/* allocate memory for the packet */
	packet_size = SIZE_ETHERNET + SIZE_IP6 + sizeof(struct s_icmp) + sizeof(struct s_icmp_ndp_na);
	packet = (unsigned char *) malloc(packet_size);

	if (packet == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* parse the packet into structures */
	eth	= (struct s_ethernet *)	   packet;
	ip	= (struct ip6_hdr *)	   (packet + SIZE_ETHERNET);
	icmp	= (struct s_icmp *)	   (packet + SIZE_ETHERNET + SIZE_IP6);
	ndp_na	= (struct s_icmp_ndp_na *) (packet + SIZE_ETHERNET + SIZE_IP6 + sizeof(struct s_icmp));

	/* assemble the ethernet header */
	memcpy(&eth->src, mac, sizeof(struct s_mac_addr));
	eth->dest = eth_hdr->src;
	eth->type = eth_hdr->type;

	/* assemble the IPv6 header */
	ip->ip6_src	= ndp_ns->target;
	ip->ip6_dst	= ip_hdr->ip_src;
	ip->ip6_flow	= 0;
	ip->ip6_vfc	= 0x60;
	ip->ip6_plen	= htons(sizeof(struct s_icmp) + sizeof(struct s_icmp_ndp_na));
	ip->ip6_nxt	= IPPROTO_ICMPV6;
	ip->ip6_hlim	= 255;

	/* assemble the ICMP header */
	icmp->type	= ICMP6_NDP_NA;
	icmp->code	= 0;
	icmp->checksum	= 0;

	/* assemble the NDP */
	//ndp_na->flags	|= INNAF_S;
	//ndp_na->flags	|= INNAF_O;
	ndp_na->zeros	= 0;
	ndp_na->flags	= 0x60;
	ndp_na->target	= ndp_ns->target;
	ndp_na->o_type	= 2;
	ndp_na->o_len	= 1;
	memcpy(&ndp_na->o_tlla, mac, sizeof(struct s_mac_addr));

	/* compute the ICMP checksum */
	buf_ip6_pseudo = (unsigned char *) malloc(sizeof(struct s_ip6_pseudo) + htons(ip->ip6_plen));

	if (buf_ip6_pseudo == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	ip6_pseudo = (struct s_ip6_pseudo *) buf_ip6_pseudo;

	ip6_pseudo->ip_src	= ip->ip6_src;
	ip6_pseudo->ip_dest	= ip->ip6_dst;
	ip6_pseudo->len		= ip->ip6_plen;
	ip6_pseudo->zeros	= 0x0;
	ip6_pseudo->next_header	= ip->ip6_nxt;

	memcpy(buf_ip6_pseudo + sizeof(struct s_ip6_pseudo), icmp, htons(ip->ip6_plen));

	icmp->checksum = checksum(buf_ip6_pseudo, sizeof(struct s_ip6_pseudo) + htons(ip->ip6_plen));

	/* send the packet */
	send_ndp(ip, packet, packet_size);

	/* free allocated memory */
	free(packet);
	free(buf_ip6_pseudo);
	packet = NULL;
	buf_ip6_pseudo = NULL;
}
