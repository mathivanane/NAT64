#ifndef WRAPPER_H
#define WRAPPER_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>	/* ip6_hdr */

/* Default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN	BUFSIZ

/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET	14

/* IPv6 headers are always exactly 40 bytes */
#define SIZE_IP6	40

/* MAC address structure */
struct s_mac_addr {
	unsigned char	a;
	unsigned char	b;
	unsigned char	c;
	unsigned char	d;
	unsigned char	e;
	unsigned char	f;
};

/* Ethernet header structure */
struct s_ethernet {
        struct s_mac_addr	dest;	/* 48 b; destination host (MAC) address */
        struct s_mac_addr	src;	/* 48 b; source host (MAC) address */
        unsigned short		type;	/* 16 b; IP/ARP/RARP/... */
};

/* IPv4 header structure */

/* IPv6 header structure */
struct s_ip6 {
	unsigned char	ver;		/*   8 b; version */
	unsigned char	traffic_class;	/*   8 b; traffic class */
	unsigned short	flow_label;	/*  16 b; flow label (qos) */
	unsigned short	len;		/*  16 b; payload length */
	unsigned char	next_header;	/*   8 b; next header */
	unsigned char	hop_limit;	/*   8 b; hop limit (replaces ttl) */
	struct in6_addr	ip_src;		/* 128 b; source address */	
	struct in6_addr	ip_dest;	/* 128 b; destination address */
};

/* pseudo IPv6 header for checksum */
struct s_ip6_pseudo {
	//unsigned short ip_src[8];
	//unsigned short ip_dest[8];
	struct in6_addr	ip_src;		/* 128 b; source address */	
	struct in6_addr	ip_dest;	/* 128 b; destination address */
	unsigned short	len;		/*  16 b; payload length */
	unsigned int	zeros:24;	/*  24 b; reserved */
	unsigned char	next_header;	/*   8 b; next header */
};

/* TCP structure - only needed fields! */
struct s_tcp {
	unsigned short	port_src;	/* 16 b; source port */
	unsigned short	port_dest;	/* 16 b; destination port */
	long double	data1;		/* 96 b; first data segment */
	unsigned short	checksum;	/* 16 b */
	unsigned short	data2;		/* 16 b; the rest (urgent pointer here) */
};

/* UDP structure */

/* ICMP header structure */
struct s_icmp {
	unsigned char	type;		/*  8 b; ICMP type */
	unsigned char	code;		/*  8 b; further specification of ICMP type */
	unsigned short	checksum;	/* 16 b */
};

/* ICMP - ping structure */
struct s_icmp_ping {
	unsigned short	id;		/* 16 b; ID value for ECHO REPLY */
	unsigned short	seq;		/* 16 b; sequence value for ECHO REPLY */
};

/* ICMPv6 - NDP option structure */
struct s_icmp_ndp_option {
	unsigned char	type;		/*  8 b; type of the option */
	unsigned char	len;		/*  8 b; length of the option (including this header!) */
};

/* ICMPv6 - NDP NS structure */
struct s_icmp_ndp_ns {
	unsigned int	zeros;		/*  32 b; reserved section */
	struct in6_addr	target;		/* 128 b; target IP address */	
};

/* ICMPv6 - NDP NA structure */
struct s_icmp_ndp_na {
	unsigned char	flags;		/*   8 b; 3 flags */
	unsigned int	zeros:24;	/*  24 b; reserved section */
	struct in6_addr	target;		/* 128 b; target IP address */	
	unsigned char	o_type;		/*   8 b; option - type */
	unsigned char	o_len;		/*   8 b; option - length */
	struct s_mac_addr o_tlla;	/*  48 b; option - target link-layer address */
};
/* INNAF = ICMPv6 NDP NA Flag */
#define INNAF_R		0x80		/* router flag */
#define INNAF_S		0x40		/* solicited flag */
#define INNAF_O		0x20		/* override flag */

/* ICMP types */
#define ICMP4_ECHO_REQUEST	0x8
#define ICMP4_ECHO_REPLY	0x0

/* ICMPv6 types */
#define ICMP6_ECHO_REQUEST	0x80
#define ICMP6_ECHO_REPLY	0x81
#define ICMP6_NDP_RS		0x85
#define ICMP6_NDP_RA		0x86
#define ICMP6_NDP_NS		0x87
#define ICMP6_NDP_NA		0x88
#define ICMP6_NDP_RM		0x89

/* Prototypes */
int get_mac_addr(const char *dev, struct s_mac_addr *addr);
int get_dev_index(const char *dev);

void process_packet6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_icmp6(const struct s_ethernet *eth, struct s_ip6 *ip, const unsigned char *payload);
void process_ndp(const struct s_ethernet *eth_hdr, struct s_ip6 *ip_hdr, unsigned char *icmp_data);

void send_there(struct in_addr ip4_addr, unsigned char ttl, unsigned int type, unsigned char *payload, unsigned int paylen);
void send_ndp(struct ip6_hdr *ip, unsigned char *packet, int packet_size);

unsigned short checksum(const void *_buf, int len);

/* Variables */
extern struct s_mac_addr *mac;		/* MAC address of the device */
extern char *dev;			/* capture device name */
extern int  dev_index;			/* capture device index */

#endif
