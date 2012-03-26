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
				 * setsockopt, SOL_SOCKET, SO_BINDTODEVICE, sendto */
#include <netinet/in.h>		/* htons */
#include <netpacket/packet.h>	/* sockaddr_ll, PACKET_OTHERHOST */
#include <stdio.h>		/* fprintf, stderr, perror */
#include <unistd.h>		/* close */

#include "ipv4.h"
#include "transmitter.h"
#include "wrapper.h"

struct sockaddr_ll	socket_address;
int			sock;

/**
 * Initialize socket and all needed properties. Should be called only once on program startup.
 *
 * @return		0 for success
 * @return		1 for failure
 */
int transmission_init(void)
{
	/* prepare settings for RAW socket */
	socket_address.sll_family	= PF_PACKET;			/* RAW communication */
	socket_address.sll_protocol	= htons(ETH_P_IP);		/* protocol above the ethernet layer */
	socket_address.sll_ifindex	= interface.ifr_ifindex;	/* set index of the network device */
	socket_address.sll_pkttype	= PACKET_OTHERHOST;		/* target host is another host */

	/* initialize RAW socket */
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		fprintf(stderr, "[Error] Couldn't open RAW socket.\n");
		perror("socket()");
		return 1;
	}

	/* bind the socket to the interface */
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(struct ifreq)) == -1) {
		fprintf(stderr, "[Error] Couldn't bind the socket to the interface.\n");
		perror("setsockopt()");
		return 1;
	}

	return 0;
}

/**
 * Close socket. Should be called only once on program shutdown.
 *
 * @return		0 for success
 * @return		1 for failure
 */
int transmission_quit(void)
{
	/* close the socket */
	if (close(sock)) {
		fprintf(stderr, "[Error] Couldn't close the transmission socket.\n");
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
int transmit(unsigned char *data, unsigned int length)
{
	if (sendto(sock, data, length, 0, (struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll)) != length) {
		fprintf(stderr, "[Error] Couldn't send a RAW packet.\n");
		perror("sendto()");
		return 1;
	}

	return 0;
}
