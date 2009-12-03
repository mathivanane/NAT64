/*
 *  WrapSix
 *  Copyright (C) 2008-2009  Michal Zima <xhire@mujmalysvet.cz>
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
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_pton */
#include <unistd.h>		/* close */
#include <string.h>		/* memcpy */

#define BUFFER_SIZE	512		/* maximum of a DNS packet */
#define IP		"::2"
#define RESOLVER	"::1"
#define PORT		53

int resolver_connect(int *sock, struct sockaddr_in6 *sock_addr);
int udp_receive(int *sock, struct sockaddr_in6 *sock_addr, char *buffer, int *length);
int udp_send(int *sock, struct sockaddr_in6 *sock_addr, char *data, int length);

int resolver_connect(int *sock, struct sockaddr_in6 *sock_addr)
{
	int tmp_sock;
	struct sockaddr_in6 tmp_sock_addr;
	char resolver[] = RESOLVER;

	/* create a socket */
	if ((tmp_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		fprintf(stderr, "[Error] Unable to create UDP socket for outgoing connections\n");
		return 1;
	}

	/* setup the socket */
	tmp_sock_addr.sin6_family = AF_INET6;
	tmp_sock_addr.sin6_port = htons(PORT);
	inet_pton(AF_INET6, (char *) &resolver, &(tmp_sock_addr.sin6_addr));

	/* return correct data */
	memcpy(sock, &tmp_sock, sizeof(int));
	memcpy(sock_addr, &tmp_sock_addr, sizeof(struct sockaddr_in6));

	return 0;
}

int udp_receive(int *sock, struct sockaddr_in6 *sock_addr, char *buffer, int *length)
{
	int tmp_length;
	int addrlen;

	addrlen = sizeof(struct sockaddr_in6);
	if ((tmp_length = recvfrom(*sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *) sock_addr, (socklen_t *) &addrlen)) == -1) {
		char str_ip[128];
		inet_ntop(AF_INET6, &(sock_addr->sin6_addr), (char *) &str_ip, 128);

		fprintf(stderr, "[Error] Unable to read from UDP socket [%s]:%d\n", str_ip, PORT);

		return 1;
	}

	memcpy(length, &tmp_length, sizeof(int));

	return 0;
}

int udp_send(int *sock, struct sockaddr_in6 *sock_addr, char *data, int length)
{
	int addrlen;

	addrlen = sizeof(struct sockaddr_in6);
	if (sendto(*sock, data, length, 0, (struct sockaddr *) sock_addr, addrlen) != length) {
		char str_ip[128];
		inet_ntop(AF_INET6, &(sock_addr->sin6_addr), (char *) &str_ip, 128);

		fprintf(stderr, "[Error] Unable to write to UDP socket [%s]:%d\n", str_ip, PORT);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int length;

	char ip[] = IP;
	char buffer[BUFFER_SIZE];

	int sock;
	struct sockaddr_in6 sock_addr,
			    client_sock_addr;

	int resolver_sock;
	struct sockaddr_in6 resolver_sock_addr;

	/* create the socket */
	if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		fprintf(stderr, "[Error] Unable to create UDP socket\n");
		return 1;
	}

	/* setup the socket */
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(PORT);
	inet_pton(AF_INET6, (char *) &ip, &(sock_addr.sin6_addr));

	/* bind the socket to address and port */
	if (bind(sock, (struct sockaddr *) &(sock_addr), sizeof(sock_addr)) == -1) {
		fprintf(stderr, "[Error] Unable to bind UDP socket to %s:%d\n", IP, PORT);
		return 1;
	}

	/* fetch a request */
	udp_receive(&sock, &client_sock_addr, (char *) &buffer, &length);

	/* forward it to resolver */
	resolver_connect(&resolver_sock, &resolver_sock_addr);
	udp_send(&resolver_sock, &resolver_sock_addr, (char *) &buffer, length);

	/* fetch the answer and forward it to the client */
	udp_receive(&resolver_sock, &resolver_sock_addr, (char *) &buffer, (int *) &length);
	udp_send(&sock, &client_sock_addr, (char *) &buffer, length);

	/* clean-up */
	close(resolver_sock);

	/* final clean-up */
	close(sock);

	return 0;
}
