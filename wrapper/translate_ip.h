#ifndef TRANSLATE_IP_H
#define TRANSLATE_IP_H

struct ip6addr_ip4part {
	long double	prefix;
	unsigned char	a;
	unsigned char	b;
	unsigned char	c;
	unsigned char	d;
};

struct in_addr ipaddr_6to4(struct in6_addr ip6_addr);
//in6_addr ipaddr_4to6(in_addr ip_addr);

#endif
