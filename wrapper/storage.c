#include "storage.h"

int stg_conn_icmp_cmp(const void *p1, const void *p2)
{
	struct stg_conn_icmp *pp1 = (struct stg_conn_icmp *) p1;
	struct stg_conn_icmp *pp2 = (struct stg_conn_icmp *) p2;

	if (pp1->id < pp2->id) return -1;
	if (pp1->id > pp2->id) return  1;
	return 0;
}

void *stg_conn_icmp_dup(void *p)
{
	struct stg_conn_icmp *pp = (struct stg_conn_icmp *) p;
	struct stg_conn_icmp *p_new;

	if ((p_new = (struct stg_conn_icmp *) malloc(sizeof(struct stg_conn_icmp))) == NULL) {
		fprintf(stderr, "Fatal Error! Lack of free memory!\n");
		exit(EXIT_FAILURE);
	}

	memcpy(p_new, pp, sizeof(struct stg_conn_icmp));

	return (void *) p_new;
}

void stg_conn_icmp_rel(void *p)
{
	free(p);
	p = NULL;
}
