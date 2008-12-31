#ifndef WRAPPER_H
#define WRAPPER_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN	BUFSIZ

/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET	14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* IPv6 headers are always exactly 40 bytes */
#define SIZE_IP6	40

/* Ethernet header */
struct s_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP/ARP/RARP/... */
};

/* IPv4 header */

/* IPv6 header */
struct s_ip6 {
	unsigned char	ver;		/*   8 b; version */
	unsigned char	traffic_class;	/*   8 b; traffic class */
	unsigned short	flow_label;	/*  16 b; flow label (qos) */
	unsigned short	len;		/*  16 b; payload length */
	unsigned char	next_header;	/*   8 b; next header */
	unsigned char	hop_limit;	/*   8 b; hop limit (replaces ttl) */
	struct in6_addr ip_src;		/* 128 b; source address */	
	struct in6_addr ip_dest;	/* 128 b; destination address */
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
	unsigned short id;		/* 16 b; ID value for ECHO REPLY */
	unsigned short seq;		/* 16 b; sequence value for ECHO REPLY */
};

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
void process_packet6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_icmp6(struct s_ip6 *ip, const unsigned char *payload);

void send_there(struct in_addr ip4_addr, unsigned char ttl, unsigned int type, unsigned char *payload, unsigned int paylen);

unsigned short checksum(const void *_buf, int len);

#endif
