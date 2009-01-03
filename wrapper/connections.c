#include <net/if.h>		/* ifreq */
#include <netinet/if_ether.h>	/* ETH_P_IP, ETH_P_ALL */
#include <netpacket/packet.h>	/* sockaddr_ll, PACKET_OTHERHOST */

#include "wrapper.h"

void send_there(struct in_addr ip4_addr, unsigned char ttl, unsigned int type, unsigned char *payload, unsigned int paylen) {
	int sock;
	struct sockaddr_in sock_addr;

	if ((sock = socket(AF_INET, SOCK_RAW, type)) == -1) {
		fprintf(stderr, "Couldn't open RAW socket.\n");
		exit(EXIT_FAILURE);
	}

	setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *) &ttl, sizeof(ttl));

	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = 0;
	sock_addr.sin_addr = ip4_addr;

	sendto(sock, (char *) payload, paylen, 0, (struct sockaddr *) &sock_addr, sizeof(struct sockaddr));

	close(sock);
}

void send_ndp(struct ip6_hdr *ip, unsigned char *packet, int packet_size)
{
	struct sockaddr_ll	socket_address;	/* target address */
	struct ifreq		ifr;		/* interface */

	int sock;

	/* prepare data for RAW socket */
	socket_address.sll_family	= PF_PACKET;		/* RAW communication */
	socket_address.sll_protocol	= htons(ETH_P_IP);	/* protocol above the ethernet layer */
	socket_address.sll_ifindex	= get_dev_index(dev);	/* set index of the network device */
	socket_address.sll_pkttype	= PACKET_OTHERHOST;	/* target host is another host */

	/* initialize with zeros */
	memset(&ifr, 0, sizeof(struct ifreq));

	/* set device */
	strncpy(ifr.ifr_name, dev, strlen(dev));

	/* initialize raw socket */
	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		fprintf(stderr, "Couldn't open RAW socket.\n");
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	/* bind the socket to the interface */
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq)) == -1){
		fprintf(stderr, "Couldn't bind the socket to the interface.\n");
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	/* send the NDP packet */
	if (sendto(sock, packet, packet_size, 0, (struct sockaddr *) &socket_address, sizeof(struct sockaddr_ll)) != packet_size) {
		fprintf(stderr, "      Error: Couldn't send NDP packet.\n");
		perror("sendto()");
		exit(EXIT_FAILURE);
	}

	/* close the socket */
	close(sock);
}
