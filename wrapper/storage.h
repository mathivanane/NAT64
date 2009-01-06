#ifndef STORAGE_H
#define STORAGE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include "jsw_rbtree.h"
#include "wrapper.h"

struct stg_conn_icmp {
	unsigned short		id;
	struct in_addr		addr_to;
	struct in6_addr		addr_from;
	struct s_mac_addr	mac;
	unsigned char		is_ping;
	time_t			time;
};

int stg_conn_icmp_cmp(const void *p1, const void *p2);
void *stg_conn_icmp_dup(void *p);
void stg_conn_icmp_rel(void *p);

extern jsw_rbtree_t *stg_conn_icmp;

#endif
