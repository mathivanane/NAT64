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
#include <string.h>		/* memcmp */

#include "icmp.h"
#include "ipv6.h"
#include "log.h"
#include "tcp.h"
#include "udp.h"
#include "wrapper.h"

/**
 * Processing of IPv6 packets.
 *
 * @param	eth	Ethernet header
 * @param	packet	Packet data
 *
 * @return	0 for success
 * @return	1 for failure
 */
int ipv6(struct s_ethernet *eth, char *packet)
{
	struct s_ipv6	*ip;
	char		*payload;

	/* load data into structures */
	ip = (struct s_ipv6 *) packet;
	payload = packet + sizeof(struct s_ipv6);

	/* test if this packet belongs to us */
	if (memcmp(&wrapsix_ipv6_prefix, &ip->ip_dest, 12) != 0 &&
	    memcmp(&ndp_multicast_addr,  &ip->ip_dest, 13) != 0) {
		log_debug("This is unfamiliar IPv6 packet");
		return 1;
	}

	switch (ip->next_header) {
		case IPPROTO_TCP:
			log_debug("IPv6 Protocol: TCP");
			return tcp_ipv6(eth, ip, payload);
		case IPPROTO_UDP:
			log_debug("IPv6 Protocol: UDP");
			return udp_ipv6(eth, ip, payload);
		case IPPROTO_ICMPV6:
			log_debug("IPv6 Protocol: ICMP");
			return icmp_ipv6(eth, ip, payload);
		default:
			log_debug("IPv6 Protocol: unknown [%d/0x%x]",
				  ip->next_header, ip->next_header);
			return 1;
	}
}
