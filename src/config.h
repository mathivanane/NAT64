/*
 *  WrapSix
 *  Copyright (C) 2008-2013  xHire <xhire@wrapsix.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "ipv4.h"
#include "ipv6.h"

struct s_cfg_opts {
	char interface[128];
	char prefix[128];
	char ipv4_address[16];
};

int cfg_parse(const char *config_file, unsigned short *cmtu,
	      struct s_cfg_opts *oto, unsigned char init);
int cfg_host_ips(char *cinterface, struct s_ipv6_addr *ipv6_addr,
		 struct s_ipv4_addr *ipv4_addr, char *default_ipv4_addr);

#endif /* CONFIG_H */
