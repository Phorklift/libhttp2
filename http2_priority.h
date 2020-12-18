#ifndef HTTP2_PRIORITY_H
#define HTTP2_PRIORITY_H

#include <stdint.h>

#include "libwuya/wuy_list.h"
#include "libwuya/wuy_hlist.h"

#include "http2_internal.h"
#include "http2.h"

struct http2_priority {
	bool			exclusive;
	uint8_t			weight;

	float			consumed;

	uint32_t		id;
	struct http2_stream	*s;

	struct http2_priority	*parent;
	wuy_list_node_t		brother;
	wuy_list_t		children;

	wuy_hlist_node_t	hash_node;
	wuy_list_node_t		closed_node;
};

struct http2_priority *http2_priority_new(struct http2_connection *c, uint32_t id);

void http2_priority_close(struct http2_priority *p);

void http2_priority_update(struct http2_priority *p, struct http2_connection *c,
		bool exclusive, uint32_t dependency, uint8_t weight);

void http2_priority_consume(struct http2_priority *p, int length);

struct http2_priority *http2_priority_hash_search(struct http2_connection *c, uint32_t id);

#endif
