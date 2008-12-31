#include <unistd.h>

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
