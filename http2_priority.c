#include <stdlib.h>
#include <assert.h>

#include "http2_priority.h"

static uint32_t http2_priority_hash_index(uint32_t id)
{
	return (id >> 1) % HTTP2_BUCKET_SIZE;
}

static void http2_priority_hash_add(struct http2_connection *c, struct http2_priority *p)
{
	uint32_t index = http2_priority_hash_index(p->id);
	wuy_hlist_insert(&c->priority_buckets[index], &p->hash_node);
}

static void http2_priority_hash_delete(struct http2_priority *p)
{
	wuy_hlist_delete(&p->hash_node);
}

struct http2_priority *http2_priority_hash_search(struct http2_connection *c, uint32_t id)
{
	uint32_t index = http2_priority_hash_index(id);
	struct http2_priority *p;
	wuy_hlist_iter_type(&c->priority_buckets[index], p, hash_node) {
		if (p->id == id) {
			return p;
		}
	}
	return NULL;
}

static void http2_priority_set_dependency(struct http2_priority *p,
		struct http2_priority *parent, struct http2_connection *c)
{
	p->parent = parent;

	wuy_list_t *children = (parent != NULL) ? &parent->children : &c->priority_root_children;

	if (p->exclusive) {
		/* If exclusive, we do not make a new tree level as RFC,
		 * which increases tree depth and brings some more cost
		 * to maintain the tree. */
		wuy_list_insert(children, &p->brother);
	} else {
		wuy_list_append(children, &p->brother);
	}
}

struct http2_priority *http2_priority_new(struct http2_connection *c, uint32_t id)
{
	struct http2_priority *p = calloc(1, sizeof(struct http2_priority));
	if (p == NULL) {
		return NULL;
	}

	p->id = id;
	http2_priority_hash_add(c, p);
	wuy_list_node_init(&p->brother);
	wuy_list_init(&p->children);
	return p;
}

void http2_priority_close(struct http2_priority *p)
{
	struct http2_connection *c = p->s->c;

	assert(p->s != NULL);
	p->s = NULL;

	c->priority_closed_num++;
	wuy_list_append(&c->priority_closed_lru, &p->closed_node);
}

static void http2_priority_clean(struct http2_connection *c)
{
	if (c->priority_closed_num <= 20) {
		return;
	}
	c->priority_closed_num--;

	struct http2_priority *p;
	wuy_list_pop_type(&c->priority_closed_lru, p, closed_node);
	assert(p != NULL);

	wuy_list_delete(&p->brother);
	http2_priority_hash_delete(p);

	struct http2_priority *pc;
	while (wuy_list_pop_type(&p->children, pc, brother)) {
		http2_priority_set_dependency(pc, p->parent, c);
	}

	free(p);

	http2_priority_clean(c);
}

void http2_priority_update(struct http2_priority *p, struct http2_connection *c,
		bool exclusive, uint32_t dependency, uint8_t weight)
{
	http2_log_debug(c, "http2_priority_update %u on %u, weight=%d, exclusive=%d",
			p->id, dependency, weight, exclusive);

	p->exclusive = exclusive;
	p->weight = weight;

	/* delete from origin relationship */
	wuy_list_delete(&p->brother);

	/* set to new relationship */
	struct http2_priority *parent = http2_priority_hash_search(c, dependency);

	http2_priority_set_dependency(p, parent, c);

	/* update closed priority nodes */
	p = p->parent;
	while (p) {
		if (p->s == NULL) {
			wuy_list_delete(&p->closed_node);
			wuy_list_append(&c->priority_closed_lru, &p->closed_node);
		}
		p = p->parent;
	}
}

void http2_priority_consume(struct http2_priority *p, int length)
{
	float consumed = (float)length;
	wuy_list_t *root = &p->s->c->priority_root_children;

	for (; p != NULL; p = p->parent) {
		p->consumed += consumed / p->weight;

		if (p->exclusive) {
			continue;
		}

		/* sort the non-exclusive priority in consumed order */
		wuy_list_t *children = (p->parent != NULL) ? &p->parent->children : root;

		struct http2_priority *older;
		wuy_list_iter_reverse_type(children, older, brother) {
			if (older == p) {
				break;
			}
			if (older->exclusive || older->consumed <= p->consumed) {
				wuy_list_delete(&p->brother);
				wuy_list_add_after(&older->brother, &p->brother);
				break;
			}
		}
	}
}

static bool http2_priority_schedular(struct http2_connection *c, wuy_list_t *children)
{
	struct http2_priority *p, *safe;
	wuy_list_iter_safe_type(children, p, safe, brother) {

		if (p->s != NULL) {
			http2_log_debug(c, "schedular stream=%u", p->id);

			if (!http2_hooks->stream_response(p->s)) {
				/* the connection has been closed */
				return false;
			}
		}

		/* call its children */
		if (!http2_priority_schedular(c, &p->children)) {
			return false;
		}
	}

	return true;
}

void http2_schedular(struct http2_connection *c)
{
	http2_log_debug(c, "[[[ http2_schedular");

	http2_priority_schedular(c, &c->priority_root_children);

	http2_log_debug(c, "]]] end of schedular");

	http2_priority_clean(c);
}
