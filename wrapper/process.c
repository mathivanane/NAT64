#include <net/ethernet.h>
#include <net/if_arp.h>

#include "wrapper.h"
#include "translate_ip.h"
#include "storage.h"

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct s_ethernet *eth;		/* the ethernet header */
	const unsigned char *payload;		/* the IP header + packet payload */

	/* define ethernet header */
	eth	= (struct s_ethernet*) (packet);
	payload	= packet + SIZE_ETHERNET;

	switch (htons(eth->type)) {
		case ETHERTYPE_IP:
			printf("\n      Proto: IPv4\n");
			process_packet4(eth, payload);
			break;
		case ETHERTYPE_IPV6:
			printf("\n      Proto: IPv6\n");
			process_packet6(eth, payload);
			break;
		case ETHERTYPE_ARP:
			printf("\n      Proto: ARP\n");
			process_arp(eth, payload);
			break;
		default:
			printf("\n      Proto: unknown (%d/0x%x)\n", htons(eth->type), htons(eth->type));
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
	if (memcmp(&ip4addr_wrapsix, &ip->ip_dest, 4)) {
		printf("==> This packet is not ours! <==\n");
		return;
	}

	/* determine protocol */
	switch (ip->proto) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			process_tcp4(eth, ip, payload, htons(ip->pckt_len) - header_length);
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			process_udp4(eth, ip, payload, htons(ip->pckt_len) - header_length);
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

void process_tcp4(const struct s_ethernet *eth_hdr, struct s_ip4 *ip_hdr, const unsigned char *payload, unsigned short data_size)
{
	struct s_ethernet	*eth;
	struct ip6_hdr		*ip;
	struct s_ip6_fragment	*ip_frag;
	struct s_tcp		*tcp;

	unsigned char	*packet;
	unsigned short	 packet_size;
	unsigned char	 do_frag = 0;
	unsigned char	 last_frag = 0;
	unsigned short	 frag_size = 1514 - SIZE_ETHERNET - SIZE_IP6 - 8 - 4;	/* 4 for alignment */
	unsigned short	 data_frag_size;
	unsigned char	*data_offset;
	unsigned short	 data_frag_offset = 0;

	struct stg_conn_tup *ent = NULL;
	struct stg_conn_tup *ent_tmp;

	/* define TCP header */
	tcp = (struct s_tcp *) payload;

	/* create temporary data entry for finding */
	if ((ent_tmp = (struct stg_conn_tup *) malloc(sizeof(struct stg_conn_tup))) == NULL) {
		fprintf(stderr, "Fatal Error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* the only needed field is port */
	ent_tmp->port = htons(tcp->port_dest);

	/* find the appropriate connection */
	ent = jsw_rbfind(stg_conn_tcp, ent_tmp);

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
	ent->packet_num++;

	/* set the checksum to zero */
	tcp->checksum = 0x0;

	/* compute the TCP checksum */
	tcp->checksum = checksum_ipv6(ipaddr_4to6(ent->addr_to), ent->addr_from, data_size, IPPROTO_TCP, (unsigned char *) payload);
	printf("   Checksum: 0x%x\n", tcp->checksum);

	/* handle fragmentation */
	packet_size = data_size + SIZE_ETHERNET + SIZE_IP6;

	/* check if the packet is not too big => fragment */
	if (packet_size > 1514) {
		do_frag = 1;
		printf("...fragmenting: %d B\n", packet_size);
	}

	/* send so many packets how many is needed */
	while (data_size) {
		if (do_frag && data_size > frag_size) {
			packet_size = 1514 - 4;
			data_frag_size = frag_size;
		}
		else if (do_frag) {
			packet_size = SIZE_ETHERNET + SIZE_IP6 + 8 + data_size;
			data_frag_size = data_size;
			last_frag = 1;
			printf("...last fragment\n");
		}
		else {
			data_frag_size = data_size;
			printf("...not fragmenting: %d B\n", packet_size);
		}

		if ((packet = (unsigned char *) malloc(packet_size)) == NULL) {
			fprintf(stderr, "Fatal error! Lack of free memory!\n");
			exit(EXIT_FAILURE);
		}

		/* initialize the packet with zeros */
		memset(packet, 0x0, packet_size);

		/* parse the packet into structures */
		eth	= (struct s_ethernet *)	packet;
		ip	= (struct ip6_hdr *)	(packet + SIZE_ETHERNET);
		if (do_frag) {
			if ((ip_frag = (struct s_ip6_fragment *) malloc(sizeof(struct s_ip6_fragment))) == NULL) {
				fprintf(stderr, "Fatal error! Lack of free memory!\n");
				exit(EXIT_FAILURE);
			}
			data_offset = (unsigned char *) (packet + SIZE_ETHERNET + SIZE_IP6 + sizeof(struct s_ip6_fragment));
			memset(ip_frag, 0x0, sizeof(struct s_ip6_fragment));

			ip_frag->next_header	= IPPROTO_TCP;
			ip_frag->zeros		= 0x0;
			ip_frag->id		= htonl(ent->port + ent->packet_num);
			ip_frag->offset_flag	= (htons((data_frag_offset / 8) << 3));
			if (!last_frag) {
				ip_frag->offset_flag |= htons(0x1);
			}

			// copy it & free it
			memcpy(packet + SIZE_ETHERNET + SIZE_IP6, ip_frag, sizeof(struct s_ip6_fragment));
			free(ip_frag);
		}
		else {
			data_offset = (unsigned char *) (ip + SIZE_IP6);
		}

		/* assemble the ethernet header */
		memcpy(&eth->src, mac, sizeof(struct s_mac_addr));
		eth->dest = ent->mac;
		eth->type = htons(ETHERTYPE_IPV6);

		/* assemble the IPv6 header */
		if (do_frag) {
			build_ip6_hdr(ip,			 /* ip6_hdr structure */
				      ipaddr_4to6(ent->addr_to), /* source address */
				      ent->addr_from,		 /* destination address */
				      data_frag_size + 8,	 /* payload length + fragment header */
				      IPPROTO_FRAGMENT,		 /* protocol */
				      ip_hdr->ttl);		 /* ttl */
		}
		else {
			build_ip6_hdr(ip,			 /* ip6_hdr structure */
				      ipaddr_4to6(ent->addr_to), /* source address */
				      ent->addr_from,		 /* destination address */
				      data_frag_size,		 /* payload length */
				      IPPROTO_TCP,		 /* protocol */
				      ip_hdr->ttl);		 /* ttl */
		}

		char ip6addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ent->addr_from, ip6addr, sizeof(ip6addr));
		printf("    Send to: %s\n", ip6addr);

		/* copy data into the packet */
		if (!do_frag) {
			memcpy(packet + SIZE_ETHERNET + SIZE_IP6, payload, data_frag_size);
		}
		else {
			memcpy(packet + SIZE_ETHERNET + SIZE_IP6 + sizeof(struct s_ip6_fragment), (unsigned char *) (payload + data_frag_offset), data_frag_size);
		}

		/* send the wrapped packet back */
		send_raw(packet, packet_size);

		/* free allocated memory */
		free(packet);
		packet = NULL;
		eth = NULL;
		ip = NULL;

		data_size -= data_frag_size;
		data_frag_offset += data_frag_size;
	}
}

void process_udp4(const struct s_ethernet *eth_hdr, struct s_ip4 *ip_hdr, const unsigned char *payload, unsigned short data_size)
{
	struct s_udp		*udp;
	struct ip6_hdr		*ip;
	struct s_ethernet	*eth;

	unsigned char	*udp_data;
	unsigned char	*packet;
	unsigned int	 packet_size;

	struct stg_conn_tup *ent = NULL;
	struct stg_conn_tup *ent_tmp;

	/* define UDP header */
	udp = (struct s_udp *) payload;
	/* define/compute UDP data offset */
	udp_data = (unsigned char *) (payload + sizeof(struct s_udp));

	/* create temporary data entry for finding */
	if ((ent_tmp = (struct stg_conn_tup *) malloc(sizeof(struct stg_conn_tup))) == NULL) {
		fprintf(stderr, "Fatal Error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* the only needed field is port */
	ent_tmp->port = htons(udp->port_dest);

	/* find the appropriate connection */
	ent = jsw_rbfind(stg_conn_udp, ent_tmp);

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
		      IPPROTO_UDP,		 /* protocol */
		      ip_hdr->ttl);		 /* ttl */

	char ip6addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ent->addr_from, ip6addr, sizeof(ip6addr));
	printf("    Send to: %s\n", ip6addr);

	/* set the checksum to zero */
	udp->checksum = 0x0;

	/* copy UDP header */
	memcpy(packet + SIZE_ETHERNET + SIZE_IP6, udp, sizeof(struct s_udp));

	/* copy UDP data */
	memcpy(packet + SIZE_ETHERNET + SIZE_IP6 + sizeof(struct s_udp), udp_data, data_size - sizeof(struct s_udp));

	/* compute the UDP checksum */
	udp->checksum = checksum_ipv6(ip->ip6_src, ip->ip6_dst, data_size, ip->ip6_nxt, (unsigned char *) (packet + SIZE_ETHERNET + SIZE_IP6));

	/* return the checksum into the packet */
	memcpy(packet + SIZE_ETHERNET + SIZE_IP6, udp, sizeof(struct s_udp));

	/* send the wrapped packet back */
	send_raw(packet, packet_size);

	/* free allocated memory */
	free(packet);
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
		      ip_hdr->ttl);		 /* ttl */

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
	send_raw(packet, packet_size);

	/* free allocated memory */
	free(packet);
}

void process_arp(const struct s_ethernet *eth_hdr, const unsigned char *arp_packet)
{
	struct s_arp		*arp;		/* ARP request packet */
	struct s_arp		*arpr;		/* ARP reply packet */
	struct s_ethernet	*eth;
	unsigned char		*packet;
	unsigned short		 packet_size;

	arp = (struct s_arp *) arp_packet;

	/* process only requests */
	if (htons(arp->opcode) != ARPOP_REQUEST) {
		printf("==> Not ARP request <==\n");
		return;
	}

	/* DEBUG: print source and destination IP addresses */
	printf("    IP From: %s\n", inet_ntoa(arp->ip_src));
	printf("    IP   To: %s\n", inet_ntoa(arp->ip_dest));
	printf("   MAC From: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", arp->mac_src.a, arp->mac_src.b, arp->mac_src.c, arp->mac_src.d, arp->mac_src.e, arp->mac_src.f);
	printf("   MAC   To: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", arp->mac_dest.a, arp->mac_dest.b, arp->mac_dest.c, arp->mac_dest.d, arp->mac_dest.e, arp->mac_dest.f);

	/* check if this packet is ours */
	if (memcmp(&ip4addr_wrapsix, &arp->ip_dest, 4)) {
		printf("==> This packet is not ours! <==\n");
		return;
	}

	/* compute the packet size */
	packet_size = SIZE_ETHERNET + sizeof(struct s_arp);

	/* allocate enough memory */
	if ((packet = (unsigned char *) malloc(packet_size)) == NULL) {
		fprintf(stderr, "Fatal Error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}
	memset(packet, 0x0, packet_size);

	/* define ethernet header and ARP offsets */
	eth  = (struct s_ethernet *) packet;
	arpr = (struct s_arp *) (packet + SIZE_ETHERNET);

	/* assemble the ethernet header */
	eth->dest = eth_hdr->src;
	memcpy(&eth->src, mac, sizeof(struct s_mac_addr));
	eth->type = htons(ETHERTYPE_ARP);

	/* assemble the ARP reply part */
	arpr->hw	= htons(ARPHRD_ETHER);
	arpr->proto	= htons(ETHERTYPE_IP);
	arpr->hw_len	= 0x06;
	arpr->proto_len	= 0x04;
	arpr->opcode	= htons(ARPOP_REPLY);
	arpr->mac_src	= eth->src;
	arpr->mac_dest	= eth->dest;
	arpr->ip_src	= ip4addr_wrapsix;
	arpr->ip_dest	= arp->ip_src;

	/* send ARP reply */
	send_raw(packet, packet_size);
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

	/* check if this packet is ours */
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
			process_tcp6(eth, ip, payload);
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			process_udp6(eth, ip, payload);
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

void process_tcp6(const struct s_ethernet *eth_hdr, struct s_ip6 *ip_hdr, const unsigned char *payload)
{
	struct s_ip4	*ip;
	struct s_tcp	*tcp;
	struct in_addr	 ip4_addr;

	unsigned char	*packet;
	unsigned char	 ent_save = 0;

	struct stg_conn_tup *ent;
	struct stg_conn_tup *ent_tmp;

	unsigned short	 data_size = htons(ip_hdr->len);
	unsigned short	 packet_size = sizeof(struct s_ip4) + data_size;

	/* define TCP header */
	tcp = (struct s_tcp *) payload;

	/* check whether the connection is not already saved */
	/* create temporary data entry for finding */
	if ((ent_tmp = (struct stg_conn_tup *) malloc(sizeof(struct stg_conn_tup))) == NULL) {
		fprintf(stderr, "Fatal Error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* the only needed field is port */
	ent_tmp->port = htons(tcp->port_src);

	/* find the appropriate connection */
	ent = jsw_rbfind(stg_conn_tcp, ent_tmp);

	/* free allocated memory */
	free(ent_tmp);

	/* check if this packet is from wrapped connection */
	if (ent == NULL) {
		printf("New connection\n");
		/* save the connection */
		ent = (struct stg_conn_tup *) malloc(sizeof(struct stg_conn_tup));
		ent->port	= htons(tcp->port_src);
		ent->addr_from	= ip_hdr->ip_src;
		ent->mac	= eth_hdr->src;
		time(&ent->time);
		ent->packet_num	= 0;
		memset(&ent->addr_to, 0x0, sizeof(struct in_addr));
		ent_save = 1;
	}
	else {
		printf("Connection found\n");
		printf("     Conn #: %d\n", jsw_rbsize(stg_conn_tcp));
		/* set fresh timestamp */
		time(&ent->time);
	}

	/* decide where to send this TCP */
	ip4_addr = ipaddr_6to4(ip_hdr->ip_dest);
	printf("    Send to: %s\n", inet_ntoa(ip4_addr));

	/* create one big TCP packet */
	packet = (unsigned char *) malloc(packet_size);

	if (packet == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* assemble IPv4 header */
	ip = (struct s_ip4 *) packet;
	ip->ver_ihl		= 0x45;
	ip->tos			= 0x0;
	ip->pckt_len		= htons(packet_size);
	ip->flags_offset	= htons(0x4000);
	ip->id			= 0x0;
	ip->ttl			= ip_hdr->hop_limit;
	ip->proto		= IPPROTO_TCP;
	ip->checksum		= 0x0;			/* it is computed automatically */
	ip->ip_src		= ip4addr_wrapsix;
	ip->ip_dest		= ip4_addr;

	/* compute the checksum */
	tcp->checksum = 0x0;
	tcp->checksum = checksum_ipv4(ip4addr_wrapsix, ip4_addr, data_size, IPPROTO_TCP, (unsigned char *) payload);

	/* copy data into the packet */
	memcpy(packet + sizeof(struct s_ip4), payload, data_size);

	/* send */
	send_raw_ipv4(ip->ip_dest, packet, packet_size);

	/* save the connection */
	if (ent_save == 1) {
		ent->addr_to = ip4_addr;
		jsw_rbinsert(stg_conn_tcp, ent);
		printf("     Conn #: %d\n", jsw_rbsize(stg_conn_tcp));
		/* the entry is not needed now and should be freed */
		free(ent);
	}

	/* free allocated memory */
	free(packet);
	packet = NULL;
}

void process_udp6(const struct s_ethernet *eth, struct s_ip6 *ip, const unsigned char *payload)
{
	struct s_udp	*udp;
	struct in_addr	 ip4_addr;

	unsigned char	*udp_data;
	unsigned char	*udp_packet;
	unsigned char	 ent_save = 0;

	struct stg_conn_tup *ent;
	struct stg_conn_tup *ent_tmp;

	unsigned short	 packet_size = htons(ip->len);

	/* define UDP header */
	udp = (struct s_udp *) payload;

	/* define/compute UDP data offset */
	udp_data = (unsigned char *) (payload + sizeof(struct s_udp));

	/* check whether the connection is not already saved */
	/* create temporary data entry for finding */
	if ((ent_tmp = (struct stg_conn_tup *) malloc(sizeof(struct stg_conn_tup))) == NULL) {
		fprintf(stderr, "Fatal Error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* the only needed field is port */
	ent_tmp->port = htons(udp->port_src);

	/* find the appropriate connection */
	ent = jsw_rbfind(stg_conn_udp, ent_tmp);

	/* free allocated memory */
	free(ent_tmp);

	/* check if this packet is from wrapped connection */
	if (ent == NULL) {
		printf("New connection\n");
		/* save the connection */
		ent = (struct stg_conn_tup *) malloc(sizeof(struct stg_conn_tup));
		ent->port	= htons(udp->port_src);
		ent->addr_from	= ip->ip_src;
		ent->mac	= eth->src;
		time(&ent->time);
		memset(&ent->addr_to, 0x0, sizeof(struct in_addr));
		ent_save = 1;
	}
	else {
		printf("Connection found\n");
		printf("     Conn #: %d\n", jsw_rbsize(stg_conn_udp));
		/* set fresh timestamp */
		time(&ent->time);
	}

	/* create one big UDP packet */
	udp_packet = (unsigned char *) malloc(packet_size);

	if (udp_packet == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	/* the checksum will not be computed */
	udp->checksum = 0x0;

	/* copy data into the packet */
	memcpy(udp_packet, udp, sizeof(struct s_udp));
	memcpy(udp_packet + sizeof(struct s_udp), udp_data, packet_size - sizeof(struct s_udp));

	/* decide where to send this UDP */
	ip4_addr = ipaddr_6to4(ip->ip_dest);
	printf("    Send to: %s\n", inet_ntoa(ip4_addr));

	/* send */
	send_there(ip4_addr, ip->hop_limit, IPPROTO_UDP, udp_packet, packet_size);

	/* save the connection */
	if (ent_save == 1) {
		ent->addr_to = ip4_addr;
		jsw_rbinsert(stg_conn_udp, ent);
		printf("     Conn #: %d\n", jsw_rbsize(stg_conn_udp));
		/* the entry is not needed now and should be freed */
		free(ent);
	}

	/* free allocated memory */
	free(udp_packet);
	udp_packet = NULL;
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
	icmp = (struct s_icmp *) payload;

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
	icmp->checksum = 0x0;

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
	send_raw(packet, packet_size);

	/* free allocated memory */
	free(packet);
	packet = NULL;
}
