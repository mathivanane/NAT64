#include "wrapper.h"
#include "translate_ip.h"

struct in_addr ipaddr_6to4(const struct in6_addr ip6_addr)
{
	struct ip6addr_ip4part *addr;
	struct in_addr ip4_addr;
	char ip4_str[15];

	/* define the IPv6 address */
	addr = (struct ip6addr_ip4part *) (&ip6_addr);

	/* build IPv4 address */
	sprintf(ip4_str, "%d.%d.%d.%d", addr->a, addr->b, addr->c, addr->d);
	inet_aton(ip4_str, &ip4_addr);

	return ip4_addr;
}

struct in6_addr ipaddr_4to6(const struct in_addr ip4_addr)
{
	struct ip6addr_ip4part *addr;
	struct in6_addr ip6_addr;
	char ip4_str[15];
	char *ip4_p;
	unsigned int ip4_a[4];

	/* create a temporary IPv6 variable */
	addr = (struct ip6addr_ip4part *) malloc(sizeof(struct ip6addr_ip4part));

	/* copy IPv6 prefix of WrapSix IPv6 addresses */
	memcpy(addr, &ip6addr_wrapsix, 12);

	/* copy the rest of the IPv6 address (the IPv4 address) */
	ip4_p = inet_ntoa(ip4_addr);
	memcpy(&ip4_str, ip4_p, 15);
	sscanf(ip4_str, "%d.%d.%d.%d", &ip4_a[0], &ip4_a[1], &ip4_a[2], &ip4_a[3]);
	addr->a = (unsigned char) ip4_a[0];
	addr->b = (unsigned char) ip4_a[1];
	addr->c = (unsigned char) ip4_a[2];
	addr->d = (unsigned char) ip4_a[3];

	/* copy the complete IPv6 address */
	memcpy(&ip6_addr, addr, sizeof(struct in6_addr));

	/* free allocated memory */
	free(addr);

	return ip6_addr;
}

void build_ip6_hdr(struct ip6_hdr *ip, struct in6_addr ip_src, struct in6_addr ip_dest, unsigned short paylen, unsigned char proto, unsigned char ttl)
{
	ip->ip6_src	= ip_src;
	ip->ip6_dst	= ip_dest;
	ip->ip6_flow	= 0;
	ip->ip6_vfc	= 0x60;
	ip->ip6_plen	= htons(paylen);
	ip->ip6_nxt	= proto;
	ip->ip6_hlim	= ttl;
}
