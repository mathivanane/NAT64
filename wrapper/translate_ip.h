#ifndef TRANSLATE_IP_H
#define TRANSLATE_IP_H

#include <netinet/in.h>		/* in6_addr, in_addr */
#include <netinet/ip6.h>	/* ip6_hdr */

struct ip6addr_ip4part {
	long double	prefix;
	unsigned char	a;
	unsigned char	b;
	unsigned char	c;
	unsigned char	d;
};

struct in_addr  ipaddr_6to4(const struct in6_addr ip6_addr);
struct in6_addr ipaddr_4to6(const struct in_addr  ip_addr);

void build_ip6_hdr(struct ip6_hdr *ip, struct in6_addr ip_src, struct in6_addr ip_dest, unsigned short paylen, unsigned char proto, unsigned char ttl);

#endif
