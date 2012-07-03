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

#include <net/if.h>		/* struct ifreq */
#include <netinet/if_ether.h>	/* {P,A}F_PACKET, ETH_P_*, socket, SOCK_RAW,
				 * setsockopt, SOL_SOCKET, SO_BINDTODEVICE,
				 * sendto */
#include <netinet/in.h>		/* htons */
#include <netpacket/packet.h>	/* sockaddr_ll, PACKET_OTHERHOST */
#include <stdio.h>		/* fprintf, stderr, perror */
#include <string.h>		/* memcpy */
#include <unistd.h>		/* close */

#include "ipv4.h"
#include "transmitter.h"
#include "wrapper.h"

struct sockaddr_ll	socket_address;
struct sockaddr_in	socket_address_ipv4;
int			sock, sock_ipv4;

/**
 * Initialize sockets and all needed properties. Should be called only once on
 * program startup.
 *
 * @return		0 for success
 * @return		1 for failure
 */
int transmission_init(void)
{
	unsigned char on = 1;

	/** RAW socket **/
	/* prepare settings for RAW socket */
	socket_address.sll_family	= PF_PACKET;	/* raw communication */
	socket_address.sll_protocol	= htons(ETH_P_IP);	/* L3 proto */
	socket_address.sll_ifindex	= interface.ifr_ifindex;
	socket_address.sll_pkttype	= PACKET_OTHERHOST;

	/* initialize RAW socket */
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		fprintf(stderr, "[Error] Couldn't open RAW socket.\n");
		perror("socket()");
		return 1;
	}

	/* bind the socket to the interface */
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface,
	    sizeof(struct ifreq)) == -1) {
		fprintf(stderr, "[Error] Couldn't bind the socket to the "
				"interface.\n");
		perror("setsockopt()");
		return 1;
	}


	/** IPv4 socket **/
	/* prepare settings for RAW IPv4 socket */
	socket_address_ipv4.sin_family	= AF_INET;
	socket_address_ipv4.sin_port	= 0x0;

	/* initialize RAW IPv4 socket */
	if ((sock_ipv4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		fprintf(stderr, "[Error] Couldn't open RAW IPv4 socket.\n");
		perror("socket()");
		return 1;
	}

	/* we will provide our own IPv4 header */
	if (setsockopt(sock_ipv4, IPPROTO_IP, IP_HDRINCL, &on,
	    sizeof(on)) == -1) {
		fprintf(stderr, "[Error] Couldn't apply the socket "
				"settings.\n");
		perror("setsockopt()");
		return 1;
	}

	return 0;
}

/**
 * Close sockets. Should be called only once on program shutdown.
 *
 * @return		0 for success
 * @return		1 for failure
 */
int transmission_quit(void)
{
	/* close the socket */
	if (close(sock) || close(sock_ipv4)) {
		fprintf(stderr, "[Error] Couldn't close the transmission "
				"sockets.\n");
		perror("close()");
		return 1;
	} else {
		return 0;
	}
}

/**
 * Send raw packet -- not doing any modifications to it.
 *
 * @param	data	Raw packet data, including ethernet header
 * @param	length	Length of the whole packet in bytes
 *
 * @return		0 for success
 * @return		1 for failure
 */
int transmit_raw(unsigned char *data, unsigned int length)
{
	if (sendto(sock, data, length, 0, (struct sockaddr *) &socket_address,
	    sizeof(struct sockaddr_ll)) != (int) length) {
		fprintf(stderr, "[Error] Couldn't send a RAW packet.\n");
		perror("sendto()");
		return 1;
	}

	return 0;
}

/**
 * Send IPv4 packet with IPv4 header supplied. Ethernet header is added by OS.
 *
 * @param	ip	Destination IPv4 address
 * @param	data	Raw packet data, excluding ethernet header, but
 * 			including IPv4 header
 * @param	length	Length of the whole packet in bytes
 *
 * @return		0 for success
 * @return		1 for failure
 */
int transmit_ipv4(struct s_ipv4_addr *ip, unsigned char *data,
		  unsigned int length)
{
	/* set the destination IPv4 address */
	memcpy(&socket_address_ipv4.sin_addr.s_addr, ip,
	       sizeof(struct s_ipv4_addr));

	if (sendto(sock_ipv4, data, length, 0,
	    (struct sockaddr *) &socket_address_ipv4,
	    sizeof(struct sockaddr)) != (int) length) {
		fprintf(stderr, "[Error] Couldn't send an IPv4 packet.\n");
		perror("sendto()");
		return 1;
	}

	return 0;
}
