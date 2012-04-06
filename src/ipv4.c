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

#include <netinet/in.h>		/* IPPROTO_* */
#include <stdio.h>
#include <string.h>		/* memcmp */

#include "icmp.h"
#include "ipv4.h"
#include "udp.h"
#include "wrapper.h"

int ipv4(struct s_ethernet *eth, char *packet)
{
	struct s_ipv4	*ip;
	char		*payload;
	unsigned short	 header_size;
	unsigned short	 data_size;

	/* load IP header */
	ip = (struct s_ipv4 *) packet;

	/* test if this packet belongs to us */
	if (memcmp(&wrapsix_ipv4_addr, &ip->ip_dest, 4) != 0) {
		printf("[Debug] [IPv4] This is unfamiliar packet\n");
		return 1;
	}

	/* TODO: verify checksum */

	/* compute sizes and get payload */
	header_size = (ip->ver_hdrlen & 0x0f) * 4;	/* # of 4 byte words */
	data_size = htons(ip->len) - header_size;
	payload = packet + header_size;

	switch (ip->proto) {
		case IPPROTO_TCP:
			printf("[Debug] IPv4 Protocol: TCP\n");
			/*ipv4_tcp(eth, ip, payload, data_size);*/
			break;
		case IPPROTO_UDP:
			printf("[Debug] IPv4 Protocol: UDP\n");
			udp_ipv4(eth, ip, payload, data_size);
			break;
		case IPPROTO_ICMP:
			printf("[Debug] IPv4 Protocol: ICMP\n");
			icmp_ipv4(eth, ip, payload, data_size);
			break;
		default:
			printf("[Debug] IPv4 Protocol: unknown [%d/0x%x]\n",
			       ip->proto, ip->proto);
			return 1;
	}

	return 0;
}
