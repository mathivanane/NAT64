#include "wrapper.h"

unsigned short checksum(const void *_buf, int len)
{
	const unsigned short *buf = _buf;
	unsigned int sum = 0;

	while (len >= 2) {
		sum += *buf ++;

		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}

		len -= 2;
	}

	if (len) {
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

unsigned short checksum_ipv6(struct in6_addr ip_src, struct in6_addr ip_dest, unsigned short paylen, unsigned char proto, unsigned char *data)
{
	unsigned char		*buf_ip6_pseudo;
	struct s_ip6_pseudo	*ip6_pseudo;
	unsigned short		sum;
	unsigned int		length = (unsigned int) paylen;

	buf_ip6_pseudo = (unsigned char *) malloc(sizeof(struct s_ip6_pseudo) + length);

	if (buf_ip6_pseudo == NULL) {
		fprintf(stderr, "Fatal error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	ip6_pseudo = (struct s_ip6_pseudo *) buf_ip6_pseudo;

	ip6_pseudo->ip_src	= ip_src;
	ip6_pseudo->ip_dest	= ip_dest;
	ip6_pseudo->len		= htonl(length);
	ip6_pseudo->zeros	= 0x0;
	ip6_pseudo->next_header	= proto;

	memcpy(buf_ip6_pseudo + sizeof(struct s_ip6_pseudo), data, length);

	sum = checksum(buf_ip6_pseudo, sizeof(struct s_ip6_pseudo) + length);

	free(buf_ip6_pseudo);
	buf_ip6_pseudo = NULL;

	return sum;
}
