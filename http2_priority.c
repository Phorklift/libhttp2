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
	p->active = true;
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
	http2_log(c, "http2_priority_update %u on %u, weight=%d, exclusive=%d",
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

static int http2_priority_schedular(wuy_list_t *children)
{
	int actives = 0;

	struct http2_priority *p, *safe;
	wuy_list_iter_safe_type(children, p, safe, brother) {
		if (p->s != NULL && p->active) {
			http2_log(p->s->c, "[debug] schedular pick stream: %u", p->id);

			/* Clear p->active in case the stream becomes inactive.
			 * We will active it later in http2_make_frame_body() if still active. */
			p->active = false;

			if (!http2_hook_stream_response(p->s, 0)) {
				return -1;
			}

			if (p->s != NULL && p->active) {
				actives++;
			}
		}

		/* search an active stream from its children */
		int ret = http2_priority_schedular(&p->children);
		if (ret == -1) {
			return -1;
		}
		actives += ret;
	}
	return actives;
}

void http2_schedular(struct http2_connection *c)
{
	http2_log(c, "~~~ start http2_schedular");
	while (http2_priority_schedular(&c->priority_root_children) > 0)
		printf("http2_schedular again\n"); // do nothing
	http2_log(c, "~~~ end of http2_schedular");

	http2_priority_clean(c);
}
