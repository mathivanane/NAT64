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
