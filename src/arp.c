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

#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <netinet/in.h>		/* htons */
#include <stdlib.h>		/* malloc */
#include <string.h>		/* memcmp, memset */

#include "arp.h"
#include "log.h"
#include "transmitter.h"
#include "wrapper.h"

/**
 * Process ARP packets and reply to them.
 *
 * @param	ethq	Ethernet header of the packet
 * @param	payload	Data of the packet
 *
 * @return	0 for success
 * @return	1 for failure
 */
int arp(struct s_ethernet *ethq, char *payload)
{
	struct s_arp *arpq, *arpr;	/* request and reply */
	struct s_ethernet *ethr;
	unsigned char *packet;

	arpq = (struct s_arp *) payload;

	/* process only requests */
	if (htons(arpq->opcode) != ARP_OP_REQUEST) {
		/* not an ARP request */
		return 1;
	}

	/* test if this packet belongs to us */
	if (memcmp(&wrapsix_ipv4_addr, &arpq->ip_dest, 4)) {
		log_debug("This is unfamiliar ARP packet");
		return 1;
	}

	/* compute the packet size */
	#define ARP_PACKET_SIZE sizeof(struct s_ethernet) + sizeof(struct s_arp)

	/* allocate enough memory */
	if ((packet = (unsigned char *) malloc(ARP_PACKET_SIZE)) == NULL) {
		log_error("Lack of free memory");
		return 1;
	}
	memset(packet, 0x0, ARP_PACKET_SIZE);

	/* define ethernet header and ARP offsets */
	ethr = (struct s_ethernet *) packet;
	arpr = (struct s_arp *) (packet + sizeof(struct s_ethernet));

	/* assemble the ethernet header */
	ethr->dest = ethq->src;
	ethr->src  = mac;
	ethr->type = htons(ETHERTYPE_ARP);

	/* assemble the ARP reply part */
	arpr->hw        = htons(ARP_HDR_ETHER);
	arpr->proto     = htons(ETHERTYPE_IP);
	arpr->hw_len    = 0x06;
	arpr->proto_len = 0x04;
	arpr->opcode    = htons(ARP_OP_REPLY);
	arpr->mac_src   = ethr->src;
	arpr->mac_dest  = ethr->dest;
	arpr->ip_src    = wrapsix_ipv4_addr;
	arpr->ip_dest   = arpq->ip_src;

	/* send ARP reply */
	transmit_raw(packet, ARP_PACKET_SIZE);

	return 0;
}
