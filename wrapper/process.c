#include <net/ethernet.h>

#include "wrapper.h"
#include "translate_ip.h"
#include "storage.h"

struct in6_addr ip6addr_wrapsix;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct s_ethernet *eth;		/* the ethernet header */
	const unsigned char *payload;		/* the IP header + packet payload */

	/* define ethernet header */
	eth	= (struct s_ethernet*) (packet);
	payload	= packet + SIZE_ETHERNET;

	switch (htons(eth->type)) {
		case ETHERTYPE_IP:
			printf("\n         IP: 4\n");
			process_packet4(eth, payload);
			break;
		case ETHERTYPE_IPV6:
			printf("\n         IP: 6\n");
			process_packet6(eth, payload);
			break;
		default:
			printf("\n         IP: unknown (%d/0x%x)\n", htons(eth->type), htons(eth->type));
			break;
	}
}

/*** IPv4 ***/
void process_packet4(const struct s_ethernet *eth, const unsigned char *packet)
{
	struct s_ip4		*ip;		/* the IP header */
	const unsigned char	*payload;	/* packet payload */

	unsigned short header_length;

	/* define/compute IP header offset */
	ip = (struct s_ip4 *) packet;
	header_length = (ip->ver_ihl & 0x0f) * 4;

	/* define/compute IP payload offset */
	payload = packet + header_length;

	/* DEBUG: print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dest));

	/* check if this packet is ours */
	if (memcmp(dev_ip, &ip->ip_dest, 4)) {
		printf("==> This packet is not ours! <==\n");
		return;
	}

	/* determine protocol */
	switch (ip->proto) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			process_icmp4(eth, ip, payload, htons(ip->pckt_len) - header_length);
			break;
		default:
			printf("   Protocol: unknown (%d/0x%x)\n", ip->proto, ip->proto);
			break;
	}
}

void process_icmp4(const struct s_ethernet *eth_hdr, struct s_ip4 *ip_hdr, const unsigned char *payload, unsigned short data_size)
{
	struct s_icmp		*icmp;
	struct ip6_hdr		*ip;
	struct s_ethernet	*eth;

	unsigned char	*icmp_data;
	unsigned char	*packet;
	unsigned int	 packet_size;

	struct stg_conn_icmp *ent = NULL;
	struct stg_conn_icmp *ent_tmp;

	/* define ICMP header */
	icmp = (struct s_icmp *) payload;
	/* define/compute ICMP data offset */
	icmp_data = (unsigned char *) (payload + sizeof(struct s_icmp));

	/* decide what type of ICMP we have */
	switch (icmp->type) {
		case ICMP4_ECHO_REPLY:
			printf("       ICMP: Echo Reply\n");

			struct s_icmp_ping *icmp_ping;
			icmp_ping = (struct s_icmp_ping *) icmp_data;

			/* create temporary data entry for finding */
			if ((ent_tmp = (struct stg_conn_icmp *) malloc(sizeof(struct stg_conn_icmp))) == NULL) {
				fprintf(stderr, "Fatal Error! Lack of free memory!\n");
				exit(EXIT_FAILURE);
			}

			/* the only needed field is ID */
			ent_tmp->id = htons(icmp_ping->id);

			/* find the appropriate connection */
			ent = jsw_rbfind(stg_conn_icmp, ent_tmp);

			/* free allocated memory */
			free(ent_tmp);

			/* check if this packet is from wrapped connection */
			if (ent == NULL) {
				fprintf(stderr, "Error: data not found\n");
				return;
			}
			else if (memcmp(&ent->addr_to, &ip_hdr->ip_src, sizeof(struct in_addr))) {
				fprintf(stderr, "Error: data not appropriate\n");
				printf("     Ent-to: %s\n", inet_ntoa(ent->addr_to));
				printf("    IP-from: %s\n", inet_ntoa(ip_hdr->ip_src));
				return;
			}

			/* wrap it back */
			icmp->type = ICMP6_ECHO_REPLY;
			icmp->code = 0;
			icmp->checksum = 0;

			break;
		default:
			printf("       ICMP: unknown (%d/0x%x)\n", icmp->type, icmp->type);
			return;
			break;
	}

	packet_size = data_size + SIZE_ETHERNET + SIZE_IP6;
	packet = (unsigned char *) malloc(packet_size);

	if (packet == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* initialize the packet with zeros */
	memset(packet, 0x0, packet_size);

	/* parse the packet into structures */
	eth	= (struct s_ethernet *)	packet;
	ip	= (struct ip6_hdr *)	(packet + SIZE_ETHERNET);

	/* assemble the ethernet header */
	memcpy(&eth->src, mac, sizeof(struct s_mac_addr));
	eth->dest = ent->mac;
	eth->type = htons(ETHERTYPE_IPV6);

	/* assemble the IPv6 header */
	build_ip6_hdr(ip,			 /* ip6_hdr structure */
		      ipaddr_4to6(ent->addr_to), /* source address */
		      ent->addr_from,		 /* destination address */
		      data_size,		 /* payload length */
		      IPPROTO_ICMPV6,		 /* protocol */
		      255);			 /* ttl */

	char ip6addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ent->addr_from, ip6addr, sizeof(ip6addr));
	printf("    Send to: %s\n", ip6addr);

	/* copy ICMP header */
	memcpy(packet + SIZE_ETHERNET + SIZE_IP6, icmp, sizeof(struct s_icmp));

	/* copy ICMP data */
	memcpy(packet + SIZE_ETHERNET + SIZE_IP6 + sizeof(struct s_icmp), icmp_data, data_size - sizeof(struct s_icmp));

	/* compute the ICMP checksum */
	icmp->checksum = checksum_ipv6(ip->ip6_src, ip->ip6_dst, data_size, ip->ip6_nxt, (unsigned char *) (packet + SIZE_ETHERNET + SIZE_IP6));

	/* return the checksum into the packet */
	memcpy(packet + SIZE_ETHERNET + SIZE_IP6, icmp, sizeof(struct s_icmp));

	/* send the wrapped packet back */
	send_ipv6(packet, packet_size);

	/* free allocated memory */
	free(packet);
}

/*** IPv6 ***/
void process_packet6(const struct s_ethernet *eth, const unsigned char *packet)
{
	struct s_ip6		*ip;		/* the IP header */
	const unsigned char	*payload;	/* packet payload */

	struct in6_addr ip6addr_ndp_multicast;

	/* define/compute IP header offset */
	ip = (struct s_ip6 *) packet;

	/* define/compute IP payload offset */
	payload = packet + SIZE_IP6;

	/* DEBUG: print source and destination IP addresses */
	char ip6addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip->ip_src, ip6addr, sizeof(ip6addr));
	printf("       From: %s\n", ip6addr);
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
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			break;
		case IPPROTO_ICMPV6:
			printf("   Protocol: ICMPv6\n");
			process_icmp6(eth, ip, payload);
			break;
		default:
			printf("   Protocol: unknown (%d/0x%x)\n", ip->next_header, ip->next_header);
			break;
	}
}

void process_icmp6(const struct s_ethernet *eth, struct s_ip6 *ip, const unsigned char *payload)
{
	struct s_icmp *icmp;
	struct in_addr ip4_addr;

	unsigned char	*icmp_data;
	unsigned char	*icmp_packet;
	unsigned char	 ent_save = 0;

	struct stg_conn_icmp *ent;
	struct stg_conn_icmp *ent_tmp;

	unsigned short packet_size = htons(ip->len);

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

			struct s_icmp_ping *icmp_ping = (struct s_icmp_ping *) icmp_data;
			/* DEBUG */
			printf("[id;seq]:[0x%x;0x%x]\n", htons(icmp_ping->id), htons(icmp_ping->seq));

			/* check whether the connection is not already saved */
			/* create temporary data entry for finding */
			if ((ent_tmp = (struct stg_conn_icmp *) malloc(sizeof(struct stg_conn_icmp))) == NULL) {
				fprintf(stderr, "Fatal Error! Lack of free memory!\n");
				exit(EXIT_FAILURE);
			}

			/* the only needed field is ID */
			ent_tmp->id = htons(icmp_ping->id);

			/* find the appropriate connection */
			ent = jsw_rbfind(stg_conn_icmp, ent_tmp);

			/* free allocated memory */
			free(ent_tmp);

			/* check if this packet is from wrapped connection */
			if (ent == NULL) {
				printf("New connection\n");
				/* save the connection */
				ent = (struct stg_conn_icmp *) malloc(sizeof(struct stg_conn_icmp));
				ent->id		= htons(icmp_ping->id);
				ent->addr_from	= ip->ip_src;
				ent->mac	= eth->src;
				ent->is_ping	= 1;
				time(&ent->time);
				memset(&ent->addr_to, 0x0, sizeof(struct in_addr));
				ent_save = 1;
			}
			else {
				printf("Connection found\n");
				printf("     Conn #: %d\n", jsw_rbsize(stg_conn_icmp));
				/* set fresh timestamp */
				time(&ent->time);
			}

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
			printf("       ICMP: unknown: (%d/0x%x)\n", icmp->type, icmp->type);
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
	ip4_addr = ipaddr_6to4(ip->ip_dest);
	printf("    Send to: %s\n", inet_ntoa(ip4_addr));

	/* send */
	send_there(ip4_addr, ip->hop_limit, IPPROTO_ICMP, icmp_packet, packet_size);

	/* save the connection */
	if (ent_save == 1) {
		ent->addr_to = ip4_addr;
		jsw_rbinsert(stg_conn_icmp, ent);
		printf("     Conn #: %d\n", jsw_rbsize(stg_conn_icmp));
		/* the entry is not needed now and should be freed */
		free(ent);
	}

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

	unsigned short		 packet_size;

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
	build_ip6_hdr(ip,			/* ip6_hdr structure */
		      ndp_ns->target,		/* source address */
		      ip_hdr->ip_src,		/* destination address */
		      sizeof(struct s_icmp) + sizeof(struct s_icmp_ndp_na),	/* payload length */
		      IPPROTO_ICMPV6,		/* protocol */
		      255);			/* ttl */

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
	icmp->checksum = checksum_ipv6(ip->ip6_src, ip->ip6_dst, htons(ip->ip6_plen), ip->ip6_nxt, (unsigned char *) icmp);

	/* send the packet */
	send_ipv6(packet, packet_size);

	/* free allocated memory */
	free(packet);
	packet = NULL;
}