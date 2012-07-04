/*
 *  WrapSix
 *  Copyright (C) 2008-2012  Michal Zima <xhire@mujmalysvet.cz>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NAT_H
#define NAT_H

#include <time.h>		/* time_t */

#include "ethernet.h"		/* s_mac_addr */
#include "ipv4.h"		/* s_ipv4_addr */
#include "ipv6.h"		/* s_ipv6_addr */
#include "radixtree.h"		/* radixtree_t */

struct s_nat {
	struct s_mac_addr	mac;
	struct s_ipv6_addr	ipv6;
	struct s_ipv4_addr	ipv4;
	unsigned short		ipv6_port_src;
	unsigned short		ipv4_port_src;
	unsigned short		ipv4_port_dst;
	time_t			last_packet;	/* time of processing last
						   packet of the connection */
};

extern radixtree_t *nat6_tcp, *nat6_udp, *nat6_icmp,
		   *nat4_tcp, *nat4_udp, *nat4_icmp,
		   *nat4_tcp_fragments;

void nat_init(void);
void nat_quit(void);

struct s_nat *nat_out(radixtree_t *nat_proto6, radixtree_t *nat_proto4,
		      struct s_mac_addr eth_src,
		      struct s_ipv6_addr ipv6_src, struct s_ipv6_addr ipv6_dst,
		      unsigned short	 port_src, unsigned short     port_dst);
struct s_nat *nat_in(radixtree_t *nat_proto4, struct s_ipv4_addr ipv4_src,
		     unsigned short port_src, unsigned short port_dst);
struct s_nat *nat_in_fragments(radixtree_t *nat_proto4,
			       struct s_ipv4_addr ipv4_src,
			       unsigned short id, struct s_nat *nat);
void nat_in_fragments_cleanup(radixtree_t *nat_proto4,
			      struct s_ipv4_addr ipv4_src, unsigned short id);

#endif /* NAT_H */
