/*
 *  WrapSix
 *  Copyright (C) 2008-2012  Michal Zima <xhire@mujmalysvet.cz>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <netinet/in.h>		/* htons */
#include <stdio.h>
#include <stdlib.h>		/* malloc */
#include <string.h>		/* memcpy, memset */

#include "checksum.h"
#include "icmp.h"
#include "ipv6.h"
#include "nat.h"
#include "transmitter.h"
#include "wrapper.h"

/**
 * Processing of incoming ICMPv4 packets. Directly sends translated ICMPv6
 * packets.
 *
 * @param	eth4		Ethernet header
 * @param	ip4		IPv4 header
 * @param	payload		ICMPv4 data
 * @param	payload_size	Size of payload; needed because IPv4 header has
 * 				dynamic length
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp_ipv4(struct s_ethernet *eth4, struct s_ipv4 *ip4,
	      char *payload, unsigned short payload_size)
{
	struct s_icmp *icmp;
	unsigned char *icmp_data;
	struct s_nat  *connection;
	unsigned short orig_checksum;
	unsigned char *packet;

	struct s_icmp_echo *echo;
	struct s_ethernet *eth6;
	struct s_ipv6 *ip6;

	icmp = (struct s_icmp *) payload;
	icmp_data = (unsigned char *) (payload + sizeof(struct s_icmp));

	/* ICMP checksum recheck */
	orig_checksum = icmp->checksum;
	icmp->checksum = 0;
	icmp->checksum = checksum((unsigned char *) icmp, payload_size);

	if (icmp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		printf("[Debug] Wrong checksum\n");
		return 1;
	}

	switch (icmp->type) {
		case ICMPV4_ECHO_REQUEST:
			/* this is pretty non-sense situation */
			return 1;

		case ICMPV4_ECHO_REPLY:
			echo = (struct s_icmp_echo *) icmp_data;

			connection = nat_in(nat4_icmp, ip4->ip_src,
					    0, echo->id);

			if (connection == NULL) {
				printf("[Debug] Incoming connection wasn't "
				       "found in NAT\n");
				return 1;
			}

			echo->id = connection->ipv6_port_src;

			/* override information in original ICMP header */
			icmp->type = ICMPV6_ECHO_REPLY;

			break;

		default:
			printf("[Debug] ICMPv4 Type: unknown [%d/0x%x]\n",
			       icmp->type, icmp->type);
			return 1;
	}

	/* allocate memory for translated packet */
	if ((packet = (unsigned char *) malloc(sizeof(struct s_ethernet) +
					       sizeof(struct s_ipv6) +
					       payload_size)) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return 1;
	}
	eth6 = (struct s_ethernet *) packet;
	ip6 = (struct s_ipv6 *) (packet + sizeof(struct s_ethernet));

	/* build ethernet header */
	eth6->dest		= connection->mac;
	eth6->src		= mac;
	eth6->type		= htons(ETHERTYPE_IPV6);

	/* build IPv6 packet */
	ip6->ver		= 0x60;
	ip6->traffic_class	= 0x0;
	ip6->flow_label		= 0x0;
	ip6->len		= htons(payload_size);
	ip6->next_header	= IPPROTO_ICMPV6;
	ip6->hop_limit		= ip4->ttl;
	ipv4_to_ipv6(&ip4->ip_src, &ip6->ip_src);
	memcpy(&ip6->ip_dest, &connection->ipv6, sizeof(struct s_ipv6_addr));

	/* compute ICMP checksum */
	icmp->checksum = 0x0;
	icmp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest, payload_size,
				       IPPROTO_ICMPV6, (unsigned char *) icmp);

	/* copy the payload data (with new checksum) */
	memcpy(packet + sizeof(struct s_ethernet) + sizeof(struct s_ipv6),
	       payload, payload_size);

	/* send translated packet */
	transmit_raw(packet, sizeof(struct s_ethernet) + sizeof(struct s_ipv6) +
		     payload_size);

	/* clean-up */
	free(packet);

	return 0;
}

/**
 * Processing of outgoing ICMPv6 packets. Directly sends translated ICMPv4
 * packets.
 *
 * @param	eth6		Ethernet header
 * @param	ip6		IPv6 header
 * @param	payload		ICMPv6 data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp_ipv6(struct s_ethernet *eth6, struct s_ipv6 *ip6, char *payload)
{
	struct s_icmp *icmp;
	unsigned char *icmp_data;
	struct s_nat  *connection;
	unsigned short orig_checksum;
	unsigned char *packet;

	struct s_icmp_echo *echo;
	struct s_ipv4 *ip4;

	icmp = (struct s_icmp *) payload;
	icmp_data = (unsigned char *) (payload + sizeof(struct s_icmp));

	/* checksum recheck */
	orig_checksum = icmp->checksum;
	icmp->checksum = 0;
	icmp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest,
				       htons(ip6->len), IPPROTO_ICMPV6,
				       (unsigned char *) icmp);

	if (icmp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		printf("[Debug] Wrong checksum\n");
		return 1;
	}

	/* decide the type of the ICMP packet */
	switch (icmp->type) {
		case ICMPV6_ECHO_REQUEST:
			echo = (struct s_icmp_echo *) icmp_data;

			connection = nat_out(nat6_icmp, nat4_icmp,
					     eth6->src,
					     ip6->ip_src, ip6->ip_dest,
					     echo->id, 0);

			if (connection == NULL) {
				printf("[Debug] Error! Outgoing connection "
				       "wasn't found/created in NAT!\n");
				return 1;
			}

			echo->id = connection->ipv4_port_src;

			/* override information in original ICMP header */
			icmp->type = ICMPV4_ECHO_REQUEST;

			break;

		case ICMPV6_ECHO_REPLY:
			/* this is pretty non-sense situation */
			return 1;

		case ICMPV6_NDP_NS:
			return icmp_ndp(eth6, ip6,
					(struct s_icmp_ndp_ns *) icmp_data);

		default:
			printf("[Debug] ICMPv6 Type: unknown [%d/0x%x]\n",
			       icmp->type, icmp->type);
			return 1;
	}

	/* allocate memory for translated packet */
	if ((packet = (unsigned char *) malloc(sizeof(struct s_ipv4) +
					       htons(ip6->len))) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return 1;
	}
	ip4 = (struct s_ipv4 *) packet;

	/* build IPv4 packet */
	ip4->ver_hdrlen	  = 0x45;		/* ver 4, header length 20 B */
	ip4->tos	  = 0x0;
	ip4->len	  = htons(sizeof(struct s_ipv4) + htons(ip6->len));
	ip4->id		  = 0x0;
	ip4->flags_offset = htons(IPV4_FLAG_DONT_FRAGMENT);
	ip4->ttl	  = ip6->hop_limit;
	ip4->proto	  = IPPROTO_ICMP;
	ipv6_to_ipv4(&ip6->ip_dest, &ip4->ip_dest);
	memcpy(&ip4->ip_src, &wrapsix_ipv4_addr, sizeof(struct s_ipv4_addr));

	/* compute ICMP checksum */
	icmp->checksum = 0x0;
	icmp->checksum = checksum((unsigned char *) icmp, htons(ip6->len));

	/* copy the payload data (with new checksum) */
	memcpy(packet + sizeof(struct s_ipv4), payload, htons(ip6->len));

	/* compute IPv4 checksum */
	ip4->checksum = checksum_ipv4(ip4->ip_src, ip4->ip_dest,
				      htons(ip4->len), IPPROTO_ICMP,
				      (unsigned char *) icmp);

	/* send translated packet */
	printf("[Debug] transmitting\n");
	transmit_ipv4(&ip4->ip_dest, packet, htons(ip4->len));

	/* clean-up */
	free(packet);

	return 0;
}

/**
 * Processes NDP NS packets and sends NDP NA.
 *
 * @param	ethq		Ethernet header
 * @param	ipq		IPv6 header
 * @param	ndp_ns		NDP NS data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int icmp_ndp(struct s_ethernet *ethq, struct s_ipv6 *ipq,
	     struct s_icmp_ndp_ns *ndp_ns)
{
	unsigned char		*packet;
	struct s_ethernet	*ethr;
	struct s_ipv6		*ipr;
	struct s_icmp		*icmp;
	struct s_icmp_ndp_na	*ndp_na;

	/* first check whether the request belongs to us */
	if (memcmp(&wrapsix_ipv6_prefix, &ndp_ns->target, 12) != 0) {
		printf("[Debug] [NDP] This is unfamiliar packet\n");
		return 1;
	}

	/* allocate memory for reply packet */
	#define NDP_PACKET_SIZE sizeof(struct s_ethernet) + \
				sizeof(struct s_ipv6) + \
				sizeof(struct s_icmp) + \
				sizeof(struct s_icmp_ndp_na)
	if ((packet = (unsigned char *) malloc(NDP_PACKET_SIZE)) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return 1;
	}
	memset(packet, 0x0, NDP_PACKET_SIZE);

	/* divide reply packet into parts */
	ethr	= (struct s_ethernet *)	   packet;
	ipr	= (struct s_ipv6 *)	   (packet + sizeof(struct s_ethernet));
	icmp	= (struct s_icmp *)	   (packet + sizeof(struct s_ethernet) +
					    sizeof(struct s_ipv6));
	ndp_na	= (struct s_icmp_ndp_na *) (packet + sizeof(struct s_ethernet) +
					    sizeof(struct s_ipv6) +
					    sizeof(struct s_icmp));

	/* ethernet */
	ethr->dest = ethq->src;
	ethr->src  = mac;
	ethr->type = ethq->type;

	/* IPv6 */
	ipr->ver = 0x60;
	ipr->len = htons(sizeof(struct s_icmp) + sizeof(struct s_icmp_ndp_na));
	ipr->next_header = IPPROTO_ICMPV6;
	/* hop limit 255 is required by RFC 4861, section 7.1.2. */
	ipr->hop_limit = 255;
	ipr->ip_src = ndp_ns->target;
	ipr->ip_dest = ipq->ip_src;

	/* ICMP */
	icmp->type = ICMPV6_NDP_NA;
	icmp->code = 0;
	icmp->checksum = 0;

	/* NDP NA */
	ndp_na->flags	 = INNAF_S;
	ndp_na->target	 = ndp_ns->target;
	ndp_na->opt_type = 2;
	ndp_na->opt_len	 = 1;
	ndp_na->opt_tlla = ethr->src;

	/* compute ICMP checksum */
	icmp->checksum = checksum_ipv6(ipr->ip_src, ipr->ip_dest,
				       htons(ipr->len), IPPROTO_ICMPV6,
				       (unsigned char *) icmp);

	/* send NDP reply */
	transmit_raw(packet, NDP_PACKET_SIZE);

	/* clean-up */
	free(packet);

	return 0;
}
