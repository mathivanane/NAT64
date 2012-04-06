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

#include <netinet/in.h>		/* htonl */
#include <stdio.h>
#include <stdlib.h>		/* malloc */
#include <string.h>		/* memcpy */

#include "checksum.h"
#include "ipv4.h"
#include "ipv6.h"

/**
 * General checksum computation function
 *
 * @param	data	Pointer to data of which to compute the checksum
 * @param	length	Length of the data (in bytes)
 *
 * @return		Checksum
 */
unsigned short checksum(const void *data, int length)
{
	const unsigned short *buf = data;
	unsigned int sum = 0;

	while (length >= 2) {
		sum += *buf++;

		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}

		length -= 2;
	}

	if (length) {
		unsigned char temp[2];

		temp[0] = *(unsigned char *) buf;
		temp[1] = 0;

		sum += *(unsigned short *) temp;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/**
 * IPv4 checksum computation function
 *
 * @param	ip_src	Source IPv4 address
 * @param	ip_dest	Destination IPv4 address
 * @param	length	Length of the payload (in bytes)
 * @param	proto	Protocol in the payload
 * @param	payload	Pointer to payload data
 *
 * @return		Checksum
 */
unsigned short checksum_ipv4(struct s_ipv4_addr ip_src,
			     struct s_ipv4_addr ip_dest,
			     unsigned short length, unsigned char proto,
			     unsigned char *payload)
{
	unsigned char		*buffer;
	struct s_ipv4_pseudo	*header;
	unsigned short		 sum;

	if ((buffer = malloc(sizeof(struct s_ipv4_pseudo) + length)) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return 0;
	}

	header = (struct s_ipv4_pseudo *) buffer;

	header->ip_src	= ip_src;
	header->ip_dest = ip_dest;
	header->zeros	= 0x0;
	header->proto	= proto;
	header->len	= htons(length);

	memcpy(buffer + sizeof(struct s_ipv4_pseudo), payload, (int) length);

	sum = checksum(buffer, sizeof(struct s_ipv4_pseudo) + (int) length);

	free(buffer);

	return sum;
}

/**
 * IPv6 checksum computation function
 *
 * @param	ip_src	Source IPv6 address
 * @param	ip_dest	Destionation IPv6 address
 * @param	length	Length of the payload (in bytes)
 * @param	proto	Protocol in the payload
 * @param	payload	Pointer to payload data
 *
 * @return		Checksum
 */
unsigned short checksum_ipv6(struct s_ipv6_addr ip_src,
			     struct s_ipv6_addr ip_dest,
			     unsigned short length, unsigned char proto,
			     unsigned char *payload)
{
	unsigned char		*buffer;
	struct s_ipv6_pseudo	*header;
	unsigned short		 sum;

	if ((buffer = malloc(sizeof(struct s_ipv6_pseudo) + length)) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return 0;
	}

	header = (struct s_ipv6_pseudo *) buffer;

	header->ip_src	    = ip_src;
	header->ip_dest	    = ip_dest;
	header->len	    = htonl((unsigned int) length);
	header->zeros	    = 0x0;
	header->next_header = proto;

	memcpy(buffer + sizeof(struct s_ipv6_pseudo), payload, (int) length);

	sum = checksum(buffer, sizeof(struct s_ipv6_pseudo) + (int) length);

	free(buffer);

	return sum;
}
