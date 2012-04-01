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

#include <arpa/inet.h>		/* inet_pton */
#include <linux/if_ether.h>	/* ETH_P_ALL */
#include <net/if.h>		/* struct ifreq */
#include <netpacket/packet.h>	/* struct packet_mreq, struct sockaddr_ll */
#include <netinet/in.h>		/* htons */
#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <stdio.h>
#include <stdlib.h>		/* srand */
#include <string.h>		/* strncpy */
#include <sys/ioctl.h>		/* ioctl, SIOCGIFINDEX */
#include <time.h>		/* time */
#include <unistd.h>		/* close */

#include "arp.h"
#include "ethernet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "nat.h"
#include "transmitter.h"
#include "wrapper.h"

#define INTERFACE	"eth0"
#define BUFFER_SIZE	65536
#define PREFIX		"fd77::"
#define IPV4_ADDR	"192.168.0.111"

struct ifreq		interface;
struct s_mac_addr	mac;
struct s_ipv6_addr	ndp_multicast_addr;
struct s_ipv6_addr	wrapsix_ipv6_prefix;
struct s_ipv4_addr	wrapsix_ipv4_addr;

int process(char *packet);

int main(int argc, char **argv)
{
	struct packet_mreq	pmr;

	struct sockaddr_ll	addr;
	size_t			addr_size;

	int	sniff_sock;
	int	length;
	char	buffer[BUFFER_SIZE];

	/* initialize the socket for sniffing */
	if ((sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		fprintf(stderr, "[Error] Unable to create listening socket\n");
		return 1;
	}

	/* get the interface */
	strncpy(interface.ifr_name, INTERFACE, IFNAMSIZ);
	if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
		fprintf(stderr, "[Error] Unable to get the interface\n");
		return 1;
	}

	/* get interface's HW address (i.e. MAC) */
	if (ioctl(sniff_sock, SIOCGIFHWADDR, &interface) == 0) {
		memcpy(&mac, &interface.ifr_hwaddr.sa_data, sizeof(struct s_mac_addr));

		/* reinitialize the interface */
		if (ioctl(sniff_sock, SIOCGIFINDEX, &interface) == -1) {
			fprintf(stderr, "[Error] Unable to reinitialize the interface\n");
			return 1;
		}
	} else {
		fprintf(stderr, "[Error] Unable to get the interface's HW address\n");
		return 1;
	}

	/* set the promiscuous mode */
	memset(&pmr, 0x0, sizeof(pmr));
	pmr.mr_ifindex = interface.ifr_ifindex;
	pmr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *) &pmr, sizeof(pmr)) == -1) {
		fprintf(stderr, "[Error] Unable to set the promiscuous mode on the interface\n");
		return 1;
	}

	/* some preparations */
	/* compute binary IPv6 address of NDP multicast */
	inet_pton(AF_INET6, "ff02::1:ff00:0", &ndp_multicast_addr);

	/* compute binary IPv6 address of WrapSix prefix */
	inet_pton(AF_INET6, PREFIX, &wrapsix_ipv6_prefix);

	/* compute binary IPv4 address of WrapSix */
	inet_pton(AF_INET, IPV4_ADDR, &wrapsix_ipv4_addr);

	/* initiate sending socket */
	if (transmission_init()) {
		fprintf(stderr, "[Error] Unable to initiate sending socket\n");
		return 1;
	}

	/* initiate NAT tables */
	nat_init();

	/* initiate random numbers generator */
	srand((unsigned int) time(NULL));

	/* sniff! :c) */
	for (;;) {
		addr_size = sizeof(addr);
		if ((length = recv(sniff_sock, buffer, BUFFER_SIZE, 0)) == -1) {
			fprintf(stderr, "[Error] Unable to retrieve data from socket\n");
			return 1;
		}

		process((char *) &buffer);
	}

	/* clean-up */
	/* close sending socket */
	transmission_quit();

	/* empty NAT tables */
	nat_quit();

	/* unset the promiscuous mode */
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, (char *) &pmr, sizeof(pmr)) == -1) {
		fprintf(stderr, "[Error] Unable to unset the promiscuous mode on the interface\n");
		/* do not call `return` here as we want to close the socket too */
	}

	/* close the socket */
	close(sniff_sock);

	return 0;
}

int process(char *packet)
{
	struct s_ethernet	*eth;		/* the ethernet header */
	char			*payload;	/* the IP header + packet payload */

	/* parse ethernet header */
	eth     = (struct s_ethernet *) (packet);
	payload = packet + sizeof(struct s_ethernet);

	switch (htons(eth->type)) {
		case ETHERTYPE_IP:
			printf("[Debug] HW Protocol: IPv4\n");
			return -1;
		case ETHERTYPE_IPV6:
			printf("[Debug] HW Protocol: IPv6\n");
			return ipv6(eth, payload);
		case ETHERTYPE_ARP:
			printf("[Debug] HW Protocol: ARP\n");
			return arp(eth, payload);
		default:
			printf("[Debug] HW Protocol: unknown [%d/0x%04x]\n",
			       htons(eth->type), htons(eth->type));
			return 1;
	}
}

/**
 * Translator of IPv6 address with embedded IPv4 address to that IPv4 address.
 *
 * @param	ipv6_addr	IPv6 address (as data source)
 * @param	ipv4_addr	Where to put final IPv4 address
 */
void ipv6_to_ipv4(struct s_ipv6_addr *ipv6_addr, struct s_ipv4_addr *ipv4_addr)
{
	memcpy(ipv4_addr, ipv6_addr->addr + 12, 4);
}

/**
 * Translator of IPv4 address to IPv6 address with WrapSix' prefix.
 *
 * @param	ipv4_addr	IPv4 address (as data source)
 * @param	ipv6_addr	Where to put final IPv6 address
 */
void ipv4_to_ipv6(struct s_ipv4_addr *ipv4_addr, struct s_ipv6_addr *ipv6_addr)
{
	memcpy(ipv6_addr, &wrapsix_ipv6_prefix, 12);
	memcpy(ipv6_addr->addr + 12, ipv4_addr, 4);
}
