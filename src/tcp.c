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
#include <string.h>		/* memcpy */

#include "checksum.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "nat.h"
#include "tcp.h"
#include "transmitter.h"
#include "wrapper.h"

/**
 * Processing of incoming TCPv4 packets. Directly sends translated TCPv6
 * packets.
 *
 * @param	eth4		Ethernet header
 * @param	ip4		IPv4 header
 * @param	payload		TCPv4 data
 * @param	payload_size	Size of payload; needed because IPv4 header has
 * 				dynamic length
 *
 * @return	0 for success
 * @return	1 for failure
 */
int tcp_ipv4(struct s_ethernet *eth, struct s_ipv4 *ip4, char *payload,
	     unsigned short payload_size)
{
	struct s_tcp  *tcp;
	struct s_nat  *connection;
	unsigned short orig_checksum;
	unsigned char *packet;

	struct s_ethernet *eth6;
	struct s_ipv6 *ip6;

	/* parse TCP header */
	tcp = (struct s_tcp *) payload;

	/* checksum recheck */
	if (tcp->checksum != 0x0000) {
		orig_checksum = tcp->checksum;
		tcp->checksum = 0;
		tcp->checksum = checksum_ipv4(ip4->ip_src, ip4->ip_dest,
					      payload_size, IPPROTO_TCP,
					      (unsigned char *) tcp);

		if (tcp->checksum != orig_checksum) {
			/* packet is corrupted and shouldn't be processed */
			printf("[Debug] Wrong checksum\n");
			return 1;
		}
	}

	/* find connection in NAT */
	connection = nat_in(nat4_tcp, ip4->ip_src, tcp->port_src, tcp->port_dest);

	if (connection == NULL) {
		printf("[Debug] Incoming connection wasn't found in NAT\n");
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
	ip6->next_header	= IPPROTO_TCP;
	ip6->hop_limit		= ip4->ttl;
	ipv4_to_ipv6(&ip4->ip_src, &ip6->ip_src);
	memcpy(&ip6->ip_dest, &connection->ipv6, sizeof(struct s_ipv6_addr));

	/* set incoming source port */
	tcp->port_dest = connection->ipv6_port_src;

	/* compute TCP checksum */
	tcp->checksum = checksum_ipv6_update(tcp->checksum,
					     ip4->ip_src, ip4->ip_dest,
					     connection->ipv4_port_src,
					     ip6->ip_src, ip6->ip_dest,
					     connection->ipv6_port_src);

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
 * Processing of outgoing TCPv6 packets. Directly sends translated TCPv4
 * packets.
 *
 * @param	eth6		Ethernet header
 * @param	ip6		IPv6 header
 * @param	payload		TCPv6 data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int tcp_ipv6(struct s_ethernet *eth, struct s_ipv6 *ip6, char *payload)
{
	struct s_tcp  *tcp;
	struct s_nat  *connection;
	unsigned short orig_checksum;
	struct s_ipv4 *ip4;
	unsigned char *packet;
	unsigned int   packet_size;

	/* parse TCP header */
	tcp = (struct s_tcp *) payload;

	/* checksum recheck */
	orig_checksum = tcp->checksum;
	tcp->checksum = 0;
	tcp->checksum = checksum_ipv6(ip6->ip_src, ip6->ip_dest,
				      htons(ip6->len), IPPROTO_TCP,
				      (unsigned char *) payload);

	if (tcp->checksum != orig_checksum) {
		/* packet is corrupted and shouldn't be processed */
		printf("[Debug] Wrong checksum\n");
		return 1;
	}

	/* find connection in NAT */
	connection = nat_out(nat6_tcp, nat4_tcp, eth->src,
			     ip6->ip_src, ip6->ip_dest,
			     tcp->port_src, tcp->port_dest);

	if (connection == NULL) {
		printf("[Debug] Error! Outgoing connection wasn't "
		       "found/created in NAT!\n");
		return 1;
	}

	/* allocate memory for translated packet */
	packet_size = sizeof(struct s_ipv4) + ip6->len;
	if ((packet = (unsigned char *) malloc(packet_size)) == NULL) {
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
	ip4->proto	  = IPPROTO_TCP;
	ipv6_to_ipv4(&ip6->ip_dest, &ip4->ip_dest);
	memcpy(&ip4->ip_src, &wrapsix_ipv4_addr, sizeof(struct s_ipv4_addr));

	/* set outgoing source port */
	tcp->port_src = connection->ipv4_port_src;

	/* compute TCP checksum */
	tcp->checksum = checksum_ipv4_update(tcp->checksum,
					     ip6->ip_src, ip6->ip_dest,
					     connection->ipv6_port_src,
					     ip4->ip_src, ip4->ip_dest,
					     connection->ipv4_port_src);

	/* copy the payload data (with new checksum) */
	memcpy(packet + sizeof(struct s_ipv4), payload, htons(ip6->len));

	/* compute IPv4 checksum */
	ip4->checksum = 0x0;
	ip4->checksum = checksum(ip4, sizeof(struct s_ipv4));

	/* send translated packet */
	transmit_ipv4(&ip4->ip_dest, packet, htons(ip4->len));

	/* clean-up */
	free(packet);

	return 0;
}
