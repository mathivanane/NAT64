#include <sys/ioctl.h>
#include <net/if.h>

#include "wrapper.h"

/*
 * Return the MAC (ie, ethernet hardware) address
 */
int get_mac_addr(const char *dev, struct s_mac_addr *addr)
{
	struct ifreq ifr;
	int s, ret;

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}

	memset(&ifr, 0x00, sizeof(ifr));
	strcpy(ifr.ifr_name, dev);
	
	if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
		memcpy(addr, &ifr.ifr_hwaddr.sa_data, sizeof(struct s_mac_addr));
		ret = 0;
	}
	else {
		ret = -1;
	}

	close(s);

	return ret;
}

/*
 * Return device index
 */
int get_dev_index(const char *dev)
{
	struct ifreq ifr;
	int s;

	memset(&ifr, 0x00, sizeof(ifr));

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}

	strncpy((char *) ifr.ifr_name, dev, IFNAMSIZ);
	if ((ioctl(s, SIOCGIFINDEX, &ifr)) == -1) {
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	close(s);

	return ifr.ifr_ifindex;
}
