/*
 *  WrapSix
 *  Copyright (C) 2008-2011  Michal Zima <xhire@mujmalysvet.cz>
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

#include <stdio.h>
#include <stdlib.h>		/* malloc */
#include <time.h>		/* time */

#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "nat.h"
#include "radixtree.h"
#include "wrapper.h"

struct s_radixtree_nat6 {
	struct s_ipv6_addr	ipv6;
	struct s_ipv4_addr	ipv4;
	unsigned short		port_src;
	unsigned short		port_dst;
} __attribute__ ((__packed__));

struct s_radixtree_nat4 {
	struct s_ipv4_addr	addr;
	unsigned short		port_src;
	unsigned short		port_dst;
	unsigned char		zeros;		/* unused space */
} __attribute__ ((__packed__));

radixtree_t *nat6_tcp, *nat6_udp, *nat6_icmp,
	    *nat4_tcp, *nat4_udp, *nat4_icmp;

void nat_init(void)
{
	nat6_tcp  = radixtree_create();
	nat6_udp  = radixtree_create();
	nat6_icmp = radixtree_create();

	nat4_tcp  = radixtree_create();
	nat4_udp  = radixtree_create();
	nat4_icmp = radixtree_create();
}

void nat_quit(void)
{
	/* 128 + 16 + 32 + 16 = 192 / 6 = 32 */
	radixtree_destroy(nat6_tcp,  32);
	radixtree_destroy(nat6_udp,  32);
	radixtree_destroy(nat6_icmp, 32);

	/* 32 + 16 + 16 + 8 = 72 / 6 = 12 */
	radixtree_destroy(nat4_tcp,  12);
	radixtree_destroy(nat4_udp,  12);
	radixtree_destroy(nat4_icmp, 12);
}

struct s_nat *nat_out(radixtree_t *nat_proto6, radixtree_t *nat_proto4,
		      struct s_mac_addr eth_src,
		      struct s_ipv6_addr ipv6_src, struct s_ipv6_addr ipv6_dst,
		      unsigned short	 port_src, unsigned short     port_dst)
{
	struct s_nat *result, *connection;

	struct s_radixtree_nat4 radixsearch4;
	struct s_radixtree_nat6 radixsearch6;

	/* create structure to search in the tree */
	radixsearch6.ipv6 = ipv6_src;
	ipv6_to_ipv4(&ipv6_dst, &radixsearch6.ipv4);
	radixsearch6.port_src = port_src;
	radixsearch6.port_dst = port_dst;

	if ((result = (struct s_nat *) radixtree_lookup(nat_proto6,
	    radixtree_ipv6_chunker, &radixsearch6)) == NULL) {
		/* if no connection is found, let's create one */
		if ((connection =
		    (struct s_nat *) malloc(sizeof(struct s_nat))) == NULL) {
			fprintf(stderr, "[Error] Lack of free memory\n");
			return NULL;
		}

		connection->mac = eth_src;
		connection->ipv6 = ipv6_src;
		connection->ipv4 = radixsearch6.ipv4;
		connection->ipv6_port_src = port_src;
		connection->ipv4_port_dst = port_dst;
		connection->last_packet = time(NULL);

		radixsearch4.addr = radixsearch6.ipv4;
		radixsearch4.port_src = port_dst;
		radixsearch4.zeros = 0x0;

		/* generate some outgoing port */
		do {
			/* returns port from range 1024 - 65535 */
			radixsearch4.port_dst = (rand() % 64511) + 1024;

			result = radixtree_lookup(nat_proto4, radixtree_ipv4_chunker, &radixsearch4);
		} while (result != NULL);

		connection->ipv4_port_src = radixsearch4.port_dst;

		/* save this connection to the NAT table (to *both* of them) */
		radixtree_insert(nat_proto6, radixtree_ipv6_chunker, &radixsearch6, connection);
		radixtree_insert(nat_proto4, radixtree_ipv4_chunker, &radixsearch4, connection);

		return connection;
	} else {
		/* when connection is found, refresh it and return */
		result->last_packet = time(NULL);
		return result;
	}
}

struct s_nat *nat_in(radixtree_t *nat_proto4, struct s_ipv4_addr ipv4_src,
		     unsigned short port_src, unsigned short port_dst)
{
	struct s_nat *result;

	/* create structure to search in the tree */
	struct s_radixtree_nat4 radixsearch4;
	radixsearch4.addr = ipv4_src;
	radixsearch4.port_src = port_src;
	radixsearch4.port_dst = port_dst;
	radixsearch4.zeros = 0x0;

	if ((result = (struct s_nat *) radixtree_lookup(nat_proto4, radixtree_ipv4_chunker, &radixsearch4)) == NULL) {
		/* when connection is not found, drop the packet */
		return NULL;
	} else {
		/* when connection is found, refresh it and return */
		result->last_packet = time(NULL);
		return result;
	}
}
