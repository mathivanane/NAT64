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

#ifndef TCP_H
#define TCP_H

/* TCP header structure */
struct s_tcp {
	unsigned short port_src;	/* 16 b; source port */
	unsigned short port_dest;	/* 16 b; destination port */
	unsigned int   seq;		/* 32 b; sequence number */
	unsigned int   ack;		/* 32 b; acknowledgement number */
	unsigned char  offset;		/*  4 b; data offset
					    6 b; reserved (zeros) */
	unsigned char  flags;		/*  6 b; flags */
	unsigned short window;		/* 16 b; size of the receive window */
	unsigned short checksum;	/* 16 b */
	unsigned short urgent_ptr;	/* 16 b; ptr to last urgent data byte */
} __attribute__ ((__packed__));

int tcp_ipv4(struct s_ethernet *eth4, struct s_ipv4 *ip4, char *payload,
	     unsigned short payload_size);
int tcp_ipv6(struct s_ethernet *eth6, struct s_ipv6 *ip6, char *payload);

#endif /* TCP_H */
