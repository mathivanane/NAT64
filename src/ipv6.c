/*
 *  WrapSix
 *  Copyright (C) 2008-2010  Michal Zima <xhire@mujmalysvet.cz>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>		/* memcpy */

#include "wrapper.h"
#include "ipv6.h"

int ipv6(struct s_ethernet *eth, char *packet)
{
	struct s_ipv6	*ip;
	char		*payload;

	/* load data into structures */
	ip = (struct s_ipv6*) packet;
	payload = packet + sizeof(struct s_ipv6);

	if (memcmp(&wrapsix_ipv6_prefix, &ip->ip_dest, 12) != 0 &&
	    memcmp(&ndp_multicast_addr,  &ip->ip_dest, 13) != 0) {
		printf("[Debug] This is unfamiliar packet\n");
		return 1;
	}

	return 0;
}
