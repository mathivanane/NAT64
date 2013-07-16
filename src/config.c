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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "wrapper.h"

#define SYNTAX_ERROR(file, line, pos, fatal) { \
			log_error("Syntax error in configuration file %s on " \
				  "line %d, position %d", file, line, pos); \
			fclose(f); \
			if (fatal) { \
				exit(1); \
			} else { \
				return 1; \
			} \
		}

#define	C_DEFAULT_MTU		1280
#define	C_DEFAULT_INTERFACE	"eth0"
#define	C_DEFAULT_PREFIX	"64:ff9b::"

/**
 * Configuration file parser.
 *
 * @param	config_file	Configuration file (with path) to parse
 * @param	cmtu		Pointer to variable where to save MTU
 * @param	oto		One-time configuration options (used only
 * 				locally to init other things)
 * @param	init		0 or 1, whether or not to initialize
 * 				configuration with defaults
 */
int cfg_parse(const char *config_file, unsigned short *cmtu,
	      struct s_cfg_opts *oto, unsigned char init)
{
	FILE *f;
	unsigned int ln = 0;
	char c;

	unsigned short opt_len, wht_len, val_len;
	char tmp_opt[32], tmp_val[128];

	/* set defaults */
	*cmtu = C_DEFAULT_MTU;
	/* TODO: get automatically the first available interface */
	strncpy(oto->interface, C_DEFAULT_INTERFACE, sizeof(oto->interface));
	strncpy(oto->prefix, C_DEFAULT_PREFIX, sizeof(oto->prefix));
	oto->ipv4_address[0] = '\0';

	f = fopen(config_file, "r");

	if (f == NULL) {
		/* set defaults */
		log_warn("Configuration file %s doesn't exist, using defaults",
			 config_file);

		if (init) {
			log_error("IPv4 address unconfigured! Exiting");
			exit(1);
		}

		return 0;
	}

	while (c = getc(f), !feof(f)) {
		ln++;

		/* comments */
		if (c == '#') {
			/* skip this line */
			while (c = getc(f), c != '\n');

			continue;
		}

		/* empty lines */
		if (c == '\n') {
			continue;
		}

		/* option is only of small letters */
		if (c < 'a' || c > 'z') {
			SYNTAX_ERROR(config_file, ln, 0, init);
		}

		/* read option */
		for (opt_len = 0; c != ' ' && c != '\t'; opt_len++,
		    c = getc(f)) {
			if (feof(f) || !((c >= 'a' && c <= 'z') || c == '_' ||
			    (c >= '0' && c <= '9'))) {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}

			if (opt_len < 32 - 1) {
				tmp_opt[opt_len] = c;
			} else {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}
		}
		tmp_opt[opt_len] = '\0';

		/* skip white space */
		for (wht_len = 0; c == ' ' || c == '\t'; wht_len++,
		    c = getc(f)) {
			if (feof(f)) {
				SYNTAX_ERROR(config_file, ln, opt_len + wht_len,
					     init);
			}
		}

		/* read value */
		for (val_len = 0; c != ' ' && c != '\t' && c != '\n'; val_len++,
		    c = getc(f)) {
			if (feof(f)) {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}

			if (val_len < 128 - 1) {
				tmp_val[val_len] = c;
			} else {
				SYNTAX_ERROR(config_file, ln, opt_len, init);
			}
		}
		tmp_val[val_len] = '\0';

		/* skip rest of this line */
		if (c != '\n') {
			while (c = getc(f), c != '\n');
		}

		/* recognize the option */
		if (!strcmp(tmp_opt, "mtu")) {
			*cmtu = atoi(tmp_val);
			if (*cmtu > MAX_MTU) {
				log_warn("MTU setting is over maximum (%d), "
					 "falling to default value (%d)",
					 MAX_MTU, C_DEFAULT_MTU);
				*cmtu = C_DEFAULT_MTU;
			}
		} else if (!strcmp(tmp_opt, "interface")) {
			strncpy(oto->interface, tmp_val, sizeof(oto->interface));
		} else if (!strcmp(tmp_opt, "prefix")) {
			strncpy(oto->prefix, tmp_val, sizeof(oto->prefix));
		} else if (!strcmp(tmp_opt, "ipv4_address")) {
			if (val_len < sizeof(oto->ipv4_address)) {
				strncpy(oto->ipv4_address, tmp_val, sizeof(oto->ipv4_address));
			} else {
				SYNTAX_ERROR(config_file, ln, opt_len + wht_len, init);
			}
		} else {
			log_error("Unknown configuration option");
			SYNTAX_ERROR(config_file, ln, 0, init);
		}
	}

	fclose(f);

	if (init && oto->ipv4_address[0] == '\0') {
		log_error("IPv4 address unconfigured! Exiting");
		exit(1);
	}

	return 0;
}
