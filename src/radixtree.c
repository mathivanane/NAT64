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

radixtree_t *radixtree_create()
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

		id = chunk[i];

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

		id = chunk[i];

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
}

radixtree_t *radixtree_lookup(radixtree_t *root,
			      unsigned char *(chunker)(void *data, unsigned char *count),
			      void *data)
{
	radixtree_t *tmp;
	unsigned char i, chunk_count;
	unsigned char *chunks;

	chunks = chunker(data, &chunk_count);

	tmp = root;

	for (i = 0; i < chunk_count; i++) {
		unsigned char id;

		id = chunk[i];

		if (i == chunk_count - 1) {
			return tmp->array[id];
		}

		if (tmp->array[id] == NULL) {
			return NULL;
		}

		tmp = tmp->array[id];
	}
}

unsigned char *radixtree_outgoing_chunker(void *data, unsigned char *count)
{
	short i;
	unsigned char counter;

	counter = 198 / 6;
	memcpy(count, &counter, sizeof(unsigned char));

	unsigned char chunks[counter];

	/* 128 + 16 + 32 + 16 - 6 = 192 */
	for (i = 192, counter = 0; i >= 0; i -= 6, counter++) {
		chunks[counter] = (*data >> i) & 63;	/* 63 == 0011 1111 */
	}

	return chunks;
}

unsigned char *radixtree_incoming_chunker(void *data, unsigned char *count)
{
	short i;
	unsigned char counter;

	counter = 72 / 6;
	memcpy(count, &counter, sizeof(unsigned char));

	unsigned char chunks[counter];

	/* 32 + 16 + 16 + 8 - 6 = 66 */
	for (i = 66, counter = 0; i >= 0; i -= 6, counter++) {
		chunks[counter] = (*data >> i) & 63;	/* 63 == 0011 1111 */
	}

	return chunks;
}
