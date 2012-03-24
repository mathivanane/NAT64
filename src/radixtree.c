/*
 *  WrapSix
 *  Copyright (C) 2008-2012  Michal Zima <xhire@mujmalysvet.cz>
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

#include <stdio.h>		/* fprintf */
#include <stdlib.h>		/* free, malloc */
#include <string.h>		/* memcpy */

#include "radixtree.h"

radixtree_t *radixtree_create(void)
{
	radixtree_t *radixtree;

	if ((radixtree = (radixtree_t *) malloc(sizeof(radixtree_t))) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return NULL;
	}
	memset(radixtree, 0, sizeof(radixtree_t));
	radixtree->count = 0;

	return radixtree;
}

void radixtree_destroy(radixtree_t *t, unsigned char depth)
{
	unsigned char i;

	for (i = 0; i < ARRAY_SIZE; i++) {
		if (depth != 1 && t->array[i] != NULL) {
			radixtree_destroy(t->array[i], depth - 1);
		} else if (depth == 1) {
			free(t->array[i]);
		}
	}

	free(t);
}

void radixtree_insert(radixtree_t *root,
		      unsigned char *(chunker)(void *data, unsigned char *count),
		      void *search_data, void *data)
{
	radixtree_t *tmp;
	unsigned char i, chunk_count;
	unsigned char *chunks;

	chunks = chunker(search_data, &chunk_count);

	tmp = root;
	tmp->count++;

	for (i = 0; i < chunk_count; i++) {
		unsigned char id;

		id = chunks[i];

		if (i == chunk_count - 1) {
			tmp->array[id] = data;
			return;
		}

		if (tmp->array[id] == NULL) {
			tmp->array[id] = radixtree_create();
		}

		tmp = tmp->array[id];
		tmp->count++;
	}

	free(chunks);
}

void radixtree_delete(radixtree_t *root,
		      unsigned char *(chunker)(void *data, unsigned char *count),
		      void *data)
{
	radixtree_t *tmp,
		    *next;
	unsigned char i, chunk_count;
	unsigned char *chunks;

	chunks = chunker(data, &chunk_count);

	tmp = root;
	tmp->count--;

	for (i = 0; i < chunk_count; i++) {
		unsigned char id;

		id = chunks[i];

		/* already deleted? may cause data inconsistency! */
		if (tmp->array[id] == NULL) {
			return;
		}

		if (i == chunk_count - 1) {
			if (tmp->count == 0) {
				free(tmp);
			} else {
				tmp->array[id] = NULL;
			}

			/**
			 * now you *have to* call free on data too
			 * but probably not here...
			 **/

			return;
		}

		next = tmp->array[id];

		/* if it is the last entry in this tree branch */
		if (next->count == 1) {
			tmp->array[id] = NULL;
		}

		if (i != 0 && tmp->count == 0) {
			free(tmp);
		}

		tmp = next;
		tmp->count--;
	}

	free(chunks);
}

void *radixtree_lookup(radixtree_t *root,
		       unsigned char *(chunker)(void *data, unsigned char *count),
		       void *data)
{
	radixtree_t *tmp;
	unsigned char i, chunk_count, id;
	unsigned char *chunks;

	chunks = chunker(data, &chunk_count);

	tmp = root;

	for (i = 0;; i++) {
		id = chunks[i];

		/* leave the for cycle before tmp gets overwritten,
		 * if the final result was found */
		if (i == chunk_count - 1) {
			free(chunks);
			return tmp->array[id];
		}

		/* leave if there is no result */
		if (tmp->array[id] == NULL) {
			free(chunks);
			return NULL;
		}

		/* go deeper */
		tmp = tmp->array[id];
	}

	/* we never get here ;c) */
}

unsigned char *radixtree_ipv6_chunker(void *data, unsigned char *count)
{
	short i;
	unsigned char counter;
	unsigned char *chunks;
	unsigned char *cdata = (unsigned char *) data;

	counter = 192 / 6;
	memcpy(count, &counter, sizeof(unsigned char));

	if ((chunks = (unsigned char *) malloc(counter * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return NULL;
	}

	/*
	 *   3 == 0000 0011 == 0x03
	 *  15 == 0000 1111 == 0x0f
	 *  48 == 0011 0000 == 0x30
	 *  60 == 0011 1100 == 0x3c
	 *  63 == 0011 1111 == 0x3f
	 * 192 == 1100 0000 == 0xc0
	 * 240 == 1111 0000 == 0xf0
	 * 252 == 1111 1100 == 0xfc
	 */
	for (i = 0, counter = 0; counter < *count; i++) {
		chunks[counter++] = cdata[i] & 0x3f;
		chunks[counter++] = ((cdata[i] & 0xc0) >> 6) | ((cdata[i + 1] & 0x0f) << 2);
		i++;
		chunks[counter++] = ((cdata[i] & 0xf0) >> 4) | ((cdata[i + 1] & 0x03) << 4);
		i++;
		chunks[counter++] = ((cdata[i] & 0xfc) >> 2);
	}

	return chunks;
}

unsigned char *radixtree_ipv4_chunker(void *data, unsigned char *count)
{
	short i;
	unsigned char counter;
	unsigned char *chunks;
	unsigned char *cdata = (unsigned char *) data;

	counter = 72 / 6;
	memcpy(count, &counter, sizeof(unsigned char));

	if ((chunks = (unsigned char *) malloc(counter * sizeof(unsigned char))) == NULL) {
		fprintf(stderr, "[Error] Lack of free memory\n");
		return NULL;
	}

	for (i = 0, counter = 0; counter < *count; i++) {
		chunks[counter++] = cdata[i] & 0x3f;
		chunks[counter++] = ((cdata[i] & 0xc0) >> 6) | ((cdata[i + 1] & 0x0f) << 2);
		i++;
		chunks[counter++] = ((cdata[i] & 0xf0) >> 4) | ((cdata[i + 1] & 0x03) << 4);
		i++;
		chunks[counter++] = ((cdata[i] & 0xfc) >> 2);
	}

	return chunks;
}
