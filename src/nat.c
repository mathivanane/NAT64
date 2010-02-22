/*
 *  WrapSix
 *  Copyright (C) 2008-2010  Michal Zima <xhire@mujmalysvet.cz>
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

#include "radixtree.h"

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

void nat_init()
{
	nat6_tcp  = radixtree_create();
	nat6_udp  = radixtree_create();
	nat6_icmp = radixtree_create();

	nat4_tcp  = radixtree_create();
	nat4_udp  = radixtree_create();
	nat4_icmp = radixtree_create();
}

void nat_quit()
{
	/* 128 + 16 + 32 + 16 = 198 / 6 = 33 */
	radixtree_destroy(&nat6_tcp,  33);
	radixtree_destroy(&nat6_udp,  33);
	radixtree_destroy(&nat6_icmp, 33);

	/* 32 + 16 + 16 + 8 = 72 / 6 = 12 */
	radixtree_destroy(&nat4_tcp,  12);
	radixtree_destroy(&nat4_udp,  12);
	radixtree_destroy(&nat4_icmp, 12);
}

struct s_nat *nat_out(radixtree_t *nat_proto6, radixtree_t *nat_proto4,
		      struct s_ipv6_addr ipv6_src, struct s_ipv6_addr ipv6_dst,
		      unsigned short	 port_src, unsigned short     port_dst)
{
	radixtree_t *result, *connection;

	/* create structure to search in the tree */
	struct s_radixtree_nat6 radixsearch6;
	radixsearch6.ipv6 = ipv6_src;
	radixsearch6.ipv4 = ipv6_to_ipv4(&ipv6_dst);
	radixsearch6.port_src = port_src;
	radixsearch6.port_dst = port_dst;

	if ((result = radixtree_lookup(nat_proto6, radixtree_outgoing_chunker, &radixsearch6)) == NULL) {
		if ((connection = (struct s_nat *) malloc(sizeof(struct s_nat))) == NULL) {
			fprintf(stderr, "[Error] Lack of free memory\n");
			return NULL;
		}

		connection->ipv6 = ipv6_src;
		connection->ipv4 = radixsearch6.ipv4;
		connection->ipv6_port_src = port_src;
		connection->ipv4_port_dst = port_dst;
		result->last_packet = time(NULL);

		/* generate some outgoing port */
		srand((unsigned int) time(NULL));
		do {
			/* return port from range 1024 - 65535 */
			connection->ipv4_port_src = (rand() % 64511) + 1024;

			result = radixtree_lookup(nat_proto6, radixtree_outgoing_chunker, &radixsearch6);
		} while (result != NULL);

		/* save this connection to the NAT table (to *both* of them) */
		struct s_radixtree_nat4 radixsearch4;
		radixsearch4.addr = radixsearch6.ipv4;
		radixsearch4.port_src = port_dst;
		radixsearch4.port_dst = connection->ipv4_port_src;
		radixsearch4.zeros = 0x0;

		radixtree_insert(nat_proto6, radixtree_outgoing_chunker, &radixsearch6, connection);
		radixtree_insert(nat_proto4, radixtree_incoming_chunker, &radixsearch4, connection);

		return connection;
	} else {
		result->last_packet = time(NULL);
		return result;
	}
}

struct s_nat *nat_in(radixtree_t *nat_proto, struct s_ipv4_addr ipv4_src,
		     unsigned short port_src, unsigned short port_dst)
{
	radixtree_t *result;

	/* create structure to search in the tree */
	struct s_radixtree_nat4 radixsearch;
	radixsearch.addr = ipv4_src;
	radixsearch.port_src = port_src;
	radixsearch.port_dst = port_dst;
	radixsearch.zeros = 0x0;

	if ((result = radixtree_lookup(nat_proto, radixtree_outgoing_chunker, &radixsearch)) == NULL) {
		return NULL;
	} else {
		result->last_packet = time(NULL);
		return result;
	}
}
