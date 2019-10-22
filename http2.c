#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "hpack.h"
#include "wuy_pool.h"
#include "wuy_list.h"
#include "wuy_hlist.h"

#include "http2.h"


struct http2_connection_s {

	wuy_list_node_t		list_node;

#define HTTP2_BUCKET_SIZE	8
	/* all priority nodes (include open and closed) are indexed here for searching */
	wuy_hlist_head_t	priority_buckets[HTTP2_BUCKET_SIZE];

	/* all priority nodes (include open and closed) are listed here as dependency tree */
	wuy_list_t		priority_root_children;

	/* only closed priority nodes are listed here in LRU order */
	wuy_list_t		priority_closed_lru;
	int			priority_closed_num;

	int			stream_num;

	uint32_t		last_stream_id_in;
	uint32_t		last_stream_id_out;
	uint32_t		last_stream_id_reset;
	uint32_t		last_stream_id_processed;

	uint32_t		goaway_error_code;

	uint32_t		send_window;

	/* current frame in parse */
	struct {
		uint8_t			type;
		uint8_t			flags;
		int			left;
		uint32_t		stream_id;
	}			frame;

	hpack_t			*hpack_decode;

	http2_settings_t	remote_settings;
	const http2_settings_t	*local_settings;

	void			*app_data;

	bool			recv_goaway;
	bool			want_ping_ack;
	bool			want_settings_ack;
};

typedef struct http2_priority_s http2_priority_t;
struct http2_priority_s {
	bool			active;
	bool			exclusive;
	uint8_t			weight;

	float			consumed;

	uint32_t		id;
	http2_stream_t		*s;

	http2_priority_t	*parent;
	wuy_list_node_t		brother;
	wuy_list_t		children;

	wuy_hlist_node_t	hash_node;
	wuy_list_node_t		closed_node;
};

struct http2_stream_s {
	http2_connection_t	*c;

	http2_priority_t	*p;

	uint32_t		send_window;

	unsigned		end_headers:1;
	unsigned		end_stream:1;

	void			*app_data;
};



static wuy_pool_t *http2_pool_connection;
static wuy_pool_t *http2_pool_stream;
static wuy_pool_t *http2_pool_priority;
static WUY_LIST(http2_active_connection);

enum http2_frame_type {
	HTTP2_FRAME_DATA = 0x0,
	HTTP2_FRAME_HEADERS,
	HTTP2_FRAME_PRIORITY,
	HTTP2_FRAME_RST_STREAM,
	HTTP2_FRAME_SETTINGS,
	HTTP2_FRAME_PUSH_PROMISE,
	HTTP2_FRAME_PING,
	HTTP2_FRAME_GOAWAY,
	HTTP2_FRAME_WINDOW_UPDATE,
	HTTP2_FRAME_CONTINUATION,
	HTTP2_FRAME_UNKNOWN,
	HTTP2_FRAME_HEADERS_REMAINING,
	HTTP2_FRAME_PREFACE,
};

#define HTTP2_FLAG_ACK			0x01
#define HTTP2_FLAG_END_STREAM		0x01
#define HTTP2_FLAG_END_HEADERS		0x04
#define HTTP2_FLAG_PADDED		0x08
#define HTTP2_FLAG_PRIORITY		0x20

enum http2_error_code {
	HTTP2_NO_ERROR = 0,
	HTTP2_PROTOCOL_ERROR,
	HTTP2_INTERNAL_ERROR,
	HTTP2_FLOW_CONTROL_ERROR,
	HTTP2_SETTINGS_TIMEOUT,
	HTTP2_STREAM_CLOSED,
	HTTP2_FRAME_SIZE_ERROR,
	HTTP2_REFUSED_STREAM,
	HTTP2_CANCEL,
	HTTP2_COMPRESSION_ERROR,
	HTTP2_CONNECT_ERROR,
	HTTP2_ENHANCE_YOUR_CALM,
	HTTP2_INADEQUATE_SECURITY,
	HTTP2_HTTP_1_1_REQUIRED,
};


static http2_hook_stream_new_f http2_hook_stream_new;
static http2_hook_stream_header_f http2_hook_stream_header;
static http2_hook_stream_body_f http2_hook_stream_body;
static http2_hook_stream_end_f http2_hook_stream_end;
static http2_hook_stream_reset_f http2_hook_stream_reset;
static http2_hook_control_frame_f http2_hook_control_frame;
static http2_hook_log_f http2_hook_log;

#define http2_log(c, fmt, ...) \
	if (http2_hook_log != NULL) http2_hook_log(c, fmt, ##__VA_ARGS__)


/* == build and send frame */

typedef struct {
	uint8_t		len1, len2, len3;
	uint8_t		type;
	uint8_t		flags;
	uint8_t		sid1, sid2, sid3, sid4;
} http2_frame_header_t;

static void http2_build_frame_header(uint8_t *buf, int length,
		uint8_t type, uint8_t flags, uint32_t stream_id)
{
	http2_frame_header_t *fh = (http2_frame_header_t *)buf;
	fh->len1 = length >> 16;
	fh->len2 = (length & 0xFF00) >> 8;
	fh->len3 = length & 0xFF;
	fh->type = type;
	fh->flags = flags;
	fh->sid1 = stream_id >> 24;
	fh->sid2 = (stream_id & 0xFF0000) >> 16;
	fh->sid3 = (stream_id & 0xFF00) >> 8;
	fh->sid4 = stream_id & 0xFF;
}

int http2_make_status_code(uint8_t *out_pos, int out_len, int status_code)
{
	// TODO trasfer return error-code
	return hpack_encode_status(status_code, out_pos, out_pos + out_len);
}
int http2_make_content_length(uint8_t *out_pos, int out_len, size_t content_length)
{
	// TODO trasfer return error-code
	return hpack_encode_content_length(content_length, out_pos, out_pos + out_len);
}
int http2_make_header(http2_stream_t *s, uint8_t *out_pos, int out_len,
		const char *name_str, int name_len, const char *value_str, int value_len)
{
	// TODO encode_hpack -> NULL
	return hpack_encode_header(NULL, name_str, name_len, value_str, value_len, out_pos, out_pos + out_len);
}
void http2_make_frame_headers(http2_stream_t *s, uint8_t *frame_pos,
		int length, bool is_stream_end, bool is_headers_end)
{
	uint8_t flags = 0;
	if (is_stream_end) {
		flags |= HTTP2_FLAG_END_STREAM;
	}
	if (is_headers_end) {
		flags |= HTTP2_FLAG_END_HEADERS;
	}
	http2_build_frame_header(frame_pos, length, HTTP2_FRAME_HEADERS, flags, s->p->id);
}

void http2_make_frame_body(http2_stream_t *s, uint8_t *frame_pos,
		int length, bool is_stream_end)
{
	uint8_t flags = 0;
	if (is_stream_end) {
		flags |= HTTP2_FLAG_END_STREAM;
	}
	http2_build_frame_header(frame_pos, length, HTTP2_FRAME_DATA, flags, s->p->id);

	/* set active back */
	s->p->active = true;

	/* update all ancients' consumed */
	float consumed = (float)length;
	http2_priority_t *p;
	for (p = s->p; p != NULL; p = p->parent) {
		p->consumed += consumed / p->weight;

		if (p->exclusive) {
			continue;
		}

		/* sort the non-exclusive priority in consumed order */
		wuy_list_t *children = (p->parent != NULL) ? &p->parent->children
				: &s->c->priority_root_children;
		wuy_list_node_t *node;
		wuy_list_iter_reverse(children, node) {
			http2_priority_t *older = wuy_containerof(node, http2_priority_t, brother);
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

static void http2_send_frame_ping(http2_connection_t *c, const uint8_t *ack)
{
	uint8_t buffer[sizeof(http2_frame_header_t) + 8];

	uint8_t flags = 0;
	if (ack != NULL) {
		memcpy(buffer + sizeof(http2_frame_header_t), ack, 8);
		flags = HTTP2_FLAG_ACK;
	}

	http2_build_frame_header(buffer, 8, HTTP2_FRAME_PING, flags, 0);
	http2_hook_control_frame(c, buffer, sizeof(buffer));
}

void http2_connection_keep_alive(http2_connection_t *c)
{
	http2_send_frame_ping(c, NULL);
	c->want_ping_ack = true;
}

static void http2_send_frame_settings(http2_connection_t *c)
{
	uint8_t payload[] = {0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x04, 0x00, 0x60, 0x00, 0x00,};

	uint8_t buffer[100];
	memcpy(buffer + sizeof(http2_frame_header_t), payload, sizeof(payload));

	http2_build_frame_header(buffer, sizeof(payload), HTTP2_FRAME_SETTINGS, 0, 0);
	http2_hook_control_frame(c, buffer, sizeof(http2_frame_header_t) + sizeof(payload));
}

static int http2_send_frame_settings_ack(http2_connection_t *c)
{
	uint8_t buffer[sizeof(http2_frame_header_t)];
	http2_build_frame_header(buffer, 0, HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0);
	http2_hook_control_frame(c, buffer, sizeof(buffer));
	return 0;
}

static void http2_send_frame_rst_stream(http2_connection_t *c, uint32_t id, uint32_t error_code)
{
	if (id == c->last_stream_id_reset) {
		return;
	}

	uint8_t buffer[sizeof(http2_frame_header_t) + 4];

	memcpy(buffer + sizeof(http2_frame_header_t), &error_code, 4); // bigendian??

	http2_build_frame_header(buffer, 4, HTTP2_FRAME_RST_STREAM, 0, id);
	http2_hook_control_frame(c, buffer, sizeof(buffer));

	c->last_stream_id_reset = id;
}

static void http2_send_frame_goaway(http2_connection_t *c, uint32_t error_code)
{
	struct http2_goaway {
		uint32_t	last_stream_id;
		uint32_t	error_code;
		char		additional_debug[0];
	};

	uint8_t buffer[sizeof(http2_frame_header_t) + sizeof(struct http2_goaway)];
	struct http2_goaway *goaway = (struct http2_goaway *)(buffer + sizeof(http2_frame_header_t));
	goaway->last_stream_id = c->last_stream_id_in; // XXX should count processed only
	goaway->error_code = error_code;

	http2_build_frame_header(buffer, sizeof(struct http2_goaway), HTTP2_FRAME_GOAWAY, 0, 0);
	http2_hook_control_frame(c, buffer, sizeof(buffer));
}


/* === priority operations */

static uint32_t http2_priority_hash_index(uint32_t id)
{
	return (id >> 1) % HTTP2_BUCKET_SIZE;
}
static void http2_priority_hash_add(http2_connection_t *c, http2_priority_t *p)
{
	uint32_t index = http2_priority_hash_index(p->id);
	wuy_hlist_insert(&c->priority_buckets[index], &p->hash_node);
}
static void http2_priority_hash_delete(http2_priority_t *p)
{
	wuy_hlist_delete(&p->hash_node);
}
static http2_priority_t *http2_priority_hash_search(http2_connection_t *c, uint32_t id)
{
	uint32_t index = http2_priority_hash_index(id);
	wuy_hlist_node_t *node;
	wuy_hlist_iter(&c->priority_buckets[index], node) {
		http2_priority_t *p = wuy_containerof(node, http2_priority_t, hash_node);
		if (p->id == id) {
			return p;
		}
	}
	return NULL;
}

static void http2_priority_set_dependency(http2_priority_t *p,
		http2_priority_t *parent, http2_connection_t *c)
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

static http2_priority_t *http2_priority_new(http2_connection_t *c, uint32_t id)
{
	http2_priority_t *p = wuy_pool_alloc(http2_pool_priority);
	if (p == NULL) {
		return NULL;
	}
	bzero(p, sizeof(http2_priority_t));

	p->id = id;
	p->active = true;
	http2_priority_hash_add(c, p);
	wuy_list_node_init(&p->brother);
	wuy_list_init(&p->children);
	return p;
}

static void http2_priority_close(http2_priority_t *p)
{
	http2_connection_t *c = p->s->c;

	p->s = NULL;

	wuy_list_insert(&c->priority_closed_lru, &p->closed_node);

	if (c->priority_closed_num < 20) {
		c->priority_closed_num++;
		return;
	}

	/* delete the last one */
	wuy_list_node_t *node = wuy_list_last(&c->priority_closed_lru);
	p = wuy_containerof(node, http2_priority_t, closed_node);
	wuy_list_delete(node);
	wuy_list_delete(&p->brother);
	http2_priority_hash_delete(p);

	wuy_list_node_t *safe;
	wuy_list_iter_safe(&p->children, node, safe) {
		http2_priority_t *pc = wuy_containerof(node, http2_priority_t, brother);
		http2_priority_set_dependency(pc, p->parent, c);
	}

	wuy_pool_free(p);
}

static http2_stream_t *http2_do_schedular(wuy_list_t *children)
{
	wuy_list_node_t *node;
	wuy_list_iter(children, node) {
		http2_priority_t *p = wuy_containerof(node, http2_priority_t, brother);
		if (p->s != NULL && p->active) {
			http2_log(p->s->c, "[debug] schedular pick stream: %u", p->id);

			/* Clear p->active in case the stream becomes inactive.
			 * We will active it later in http2_make_frame_body() if still active. */
			p->active = false;

			return p->s;
		}

		/* search an active stream from its children */
		http2_stream_t *s = http2_do_schedular(&p->children);
		if (s != NULL) {
			return s;
		}
	}
	return NULL;
}
http2_stream_t *http2_schedular(http2_connection_t *c)
{
	return http2_do_schedular(&c->priority_root_children);
}


/* == stream operations */

static http2_stream_t *http2_stream_new(http2_connection_t *c)
{
	http2_log(c, "new stream: %u", c->frame.stream_id);

	http2_stream_t *s = wuy_pool_alloc(http2_pool_stream);
	if (s == NULL) {
		return NULL;
	}

	bzero(s, sizeof(http2_stream_t));

	s->c = c;
	s->send_window = c->remote_settings.initial_window_size;
	if (c->frame.flags & HTTP2_FLAG_END_HEADERS) {
		s->end_headers = 1;
	}
	if (c->frame.flags & HTTP2_FLAG_END_STREAM) {
		s->end_stream = 1;
	}

	c->stream_num++;
	c->last_stream_id_in = c->frame.stream_id;

	http2_hook_stream_new(s);
	return s;
}

void http2_stream_close(http2_stream_t *s)
{
	http2_connection_t *c = s->c;

	c->stream_num--;

	http2_priority_close(s->p);

	wuy_pool_free(s);
}

static http2_stream_t *http2_stream_current(http2_connection_t *c)
{
	http2_priority_t *p = http2_priority_hash_search(c, c->frame.stream_id);
	if (p == NULL) {
		return NULL;
	}
	return p->s;
}


/* == connection operations */

http2_connection_t *http2_connection_new(const http2_settings_t *settings)
{
	http2_connection_t *c = wuy_pool_alloc(http2_pool_connection);
	if (c == NULL) {
		return NULL;
	}

	http2_log(c, "[debug] new connection %p", c);

	bzero(c, sizeof(http2_connection_t));

	c->frame.type = HTTP2_FRAME_PREFACE;
	c->frame.left = 24; /* length of preface */
	c->send_window = settings->initial_window_size;
	c->local_settings = settings;
	c->hpack_decode = hpack_new(4096); /* see RFC7540 section 6.5.2 */
	wuy_list_init(&c->priority_root_children);
	wuy_list_init(&c->priority_closed_lru);

	int i;
	for (i = 0; i < HTTP2_BUCKET_SIZE; i++) {
		wuy_hlist_head_init(&c->priority_buckets[i]);
	}

	wuy_list_append(&http2_active_connection, &c->list_node);

	return c;
}

void http2_connection_close(http2_connection_t *c)
{
	http2_log(c, "[debug] close connection %p", c);

	http2_send_frame_goaway(c, c->goaway_error_code);

	hpack_free(c->hpack_decode);

	int i;
	for (i = 0; i < HTTP2_BUCKET_SIZE; i++) {
		wuy_hlist_node_t *node, *safe;
		wuy_hlist_iter_safe(&c->priority_buckets[i], node, safe) {
			http2_priority_t *p = wuy_containerof(node, http2_priority_t, hash_node);
			if (p->s != NULL) {
				/* http2_stream_close() is expected to be called in the hook */
				http2_hook_stream_reset(p->s);
			}
		}
	}

	wuy_list_node_t *node, *safe;
	wuy_list_iter_safe(&c->priority_closed_lru, node, safe) {
		http2_priority_t *p = wuy_containerof(node, http2_priority_t, closed_node);
		wuy_pool_free(p);
	}

	wuy_pool_free(c);
}


/* == process input buffer */

static int http2_process_frame_unknown(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	return length;
}

static int http2_process_frame_settings(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	if (c->frame.flags & HTTP2_FLAG_ACK) {
		return length;
	}
	if (c->frame.left % 6 != 0) {
		http2_log(c, "invalid SETTINGS frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}
	if (c->frame.left > 6 * 10) {
		http2_log(c, "too long SETTINGS frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}
	if (length < c->frame.left) {
		return 0;
	}

	const uint8_t *p = buffer;
	int i;
	for (i = 0; i < length; i += 6, p += 6) {
		uint16_t id = p[0] << 8 | p[1];
		uint32_t value = p[2] << 24 | p[3] << 16 | p[4] << 8 | p[5];

		switch (id) {
		case 0x1:
			c->remote_settings.header_table_size = value;
			hpack_max_size(c->hpack_decode, value);
			break;
		case 0x2:
			c->remote_settings.enable_push = value;
			break;
		case 0x3:
			c->remote_settings.max_concurrent_streams = value;
			break;
		case 0x4:
			if (value > 0x7FFFFFFF) {
				http2_log(c, "too big WINDOW_SIZE");
				return HTTP2_PROTOCOL_ERROR;
			}
			c->remote_settings.initial_window_size = value;
			break;
		case 0x5:
			c->remote_settings.max_frame_size = value;
			break;
		case 0x6:
			c->remote_settings.max_header_list_size = value;
			break;
		default:
			;
		}
	}

	http2_send_frame_settings_ack(c);

	return length;
}

static int http2_process_frame_ping(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	if (c->frame.flags & HTTP2_FLAG_ACK) {
		if (!c->want_ping_ack) {
			// TODO
		}
		c->want_ping_ack = false;
		return length;
	}
	if (c->frame.left != 8) {
		http2_log(c, "invalid PING frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}
	if (length < c->frame.left) {
		return 0;
	}

	http2_send_frame_ping(c, buffer);
	return length;
}

static int http2_process_frame_goaway(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	if (length < c->frame.left) {
		return 0;
	}

	struct http2_goaway {
		uint32_t	last_stream_id;
		uint32_t	error_code;
		char		additional_debug[0];
	} *goaway = (struct http2_goaway *)buffer;

	if (length < sizeof(struct http2_goaway)) {
		http2_log(c, "invalid GOAWAY frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}

	goaway->additional_debug[length - sizeof(struct http2_goaway) - 1] = '\0';
	http2_log(c, "GOAWAY: %x %s", goaway->error_code, goaway->additional_debug);

	c->recv_goaway = true;
	return length;
}


static int http2_process_frame_window_update(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	if (length < c->frame.left) {
		return 0;
	}
	if (c->frame.left != 4) {
		return HTTP2_FRAME_SIZE_ERROR;
	}

	const uint8_t *p = buffer;
	if ((p[0] & 0x80) != 0) {
		return HTTP2_FRAME_SIZE_ERROR;
	}
	uint32_t size = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];

	if (c->frame.stream_id == 0) {
		c->send_window += size;
	} else {
		http2_stream_t *s = http2_stream_current(c);
		if (s != NULL) {
			s->send_window += size;
		}
	}

	http2_log(c, "WINDOW_UPDATE %u %u", c->frame.stream_id, size);

	return length;
}

static void http2_priority_update(http2_priority_t *p, http2_connection_t *c,
		bool exclusive, uint32_t dependency, uint8_t weight)
{
	http2_log(c, "http2_priority_update %u on %u, weight=%d, exclusive=%d",
			p->id, dependency, weight, exclusive);

	p->exclusive = exclusive;
	p->weight = weight;

	/* delete from origin relationship */
	wuy_list_delete(&p->brother);

	/* set to new relationship */
	http2_priority_t *parent = http2_priority_hash_search(c, dependency);

	http2_priority_set_dependency(p, parent, c);

	/* update closed priority nodes */
	p = p->parent;
	while (p) {
		if (p->s == NULL) {
			wuy_list_delete(&p->closed_node);
			wuy_list_insert(&c->priority_closed_lru, &p->closed_node);
		}
		p = p->parent;
	}
}

static int http2_process_priority(const uint8_t *p, int length,
		bool *exclusive, uint32_t *dependency, uint8_t *weight)
{
	if (length < 5) {
		return 0;
	}
	*exclusive = p[0] > 7;
	*dependency = (p[0] & 0x7F) << 24 | p[1] << 16 | p[2] << 8 | p[3];
	*weight = p[4];
	return 5;
}

static int http2_process_frame_priority(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	bool exclusive = 0;
	uint32_t dependency = 0;
	uint8_t weight = 16;
	int proc_len = http2_process_priority(buffer, length,
			&exclusive, &dependency, &weight);
	if (proc_len == 0) {
		return 0;
	}
	if (proc_len != length) {
		return HTTP2_FRAME_SIZE_ERROR;
	}

	uint32_t id = c->frame.stream_id;
	http2_priority_t *p = http2_priority_hash_search(c, id);
	if (p == NULL) {
		if (id <= c->last_stream_id_in) { /* has been closed */
			return length;
		}

		p = http2_priority_new(c, id);
		if (p == NULL) {
			return length;
		}

		wuy_list_insert(&c->priority_closed_lru, &p->closed_node);
	}

	http2_priority_update(p, c, exclusive, dependency, weight);
	return length;
}


static void http2_stream_request_finish(http2_stream_t *s, int proc_len)
{
	http2_connection_t *c = s->c;

	if (!(c->frame.flags & HTTP2_FLAG_END_STREAM)) {
		http2_log(c, "stream %u request not end for flags", s->p->id);
		return;
	}
	if (c->frame.left != proc_len) {
		http2_log(c, "stream %u request not end for length: %d %d",
				s->p->id, c->frame.left, proc_len);
		return;
	}

	http2_log(c, "stream %u request end", s->p->id);

	http2_hook_stream_end(s);
}

static int http2_process_frame_data(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	http2_stream_t *s = http2_stream_current(c);
	if (s == NULL) { /* has been closed */
		return HTTP2_STREAM_CLOSED;
	}
	if (s->end_stream) {
		http2_log(c, "data to end_stream");
		return HTTP2_PROTOCOL_ERROR;
	}

	http2_hook_stream_body(s, buffer, length);

	http2_stream_request_finish(s, length);

	return length;
}

static int http2_process_header_entry(http2_stream_t *s,
		const uint8_t *buffer, int length)
{
	const char *name_str, *value_str;
	int name_len, value_len;

	int proc_len = hpack_decode_header(s->c->hpack_decode,
			buffer, buffer + length, &name_str, &name_len,
			&value_str, &value_len);

	if (proc_len < 0) {
		if (proc_len == HPERR_AGAIN) {
			return 0;
		}
		http2_log(s->c, "hpack decode fail");
		return HTTP2_PROTOCOL_ERROR;
	}

	http2_hook_stream_header(s, name_str, name_len, value_str, value_len);

	return proc_len;
}

static int http2_process_payload_headers(http2_stream_t *s,
		const uint8_t *buffer, int length, int extra_len)
{
	const uint8_t *buf_pos = buffer;
	int buf_left = length;
	while (buf_left > 0) {
		int proc_len = http2_process_header_entry(s, buf_pos, buf_left);
		if (proc_len < 0) {
			return proc_len;
		}
		if (proc_len == 0) {
			break;
		}
		buf_pos += proc_len;
		buf_left -= proc_len;
	}

	int total_len = buf_pos - buffer + extra_len;

	http2_stream_request_finish(s, total_len);

	s->c->frame.type = HTTP2_FRAME_HEADERS_REMAINING;
	return total_len;
}

static int http2_process_frame_continuation(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	http2_stream_t *s = http2_stream_current(c);
	if (s == NULL) {
		return (c->frame.stream_id == c->last_stream_id_reset)
			? HTTP2_STREAM_CLOSED : HTTP2_PROTOCOL_ERROR;
	}
	if (s->end_headers) {
		http2_log(c, "header on end_headers");
		return HTTP2_PROTOCOL_ERROR;
	}

	return http2_process_payload_headers(s, buffer, length, 0);
}

static int http2_process_frame_headers_remaining(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	http2_stream_t *s = http2_stream_current(c);
	if (s == NULL) {
		return HTTP2_STREAM_CLOSED;
	}
	return http2_process_payload_headers(s, buffer, length, 0);
}

static int http2_process_frame_headers(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	int priority_len = 0;

	/* parse priority */
	bool exclusive = 0;
	uint32_t dependency = 0;
	uint8_t weight = 16;
	if (c->frame.flags & HTTP2_FLAG_PRIORITY) {
		priority_len = http2_process_priority(buffer, length,
				&exclusive, &dependency, &weight);
		if (priority_len == 0) {
			return 0;
		}
	}

	/* create new stream */
	uint32_t stream_id = c->frame.stream_id;
	if (stream_id <= c->last_stream_id_in || (stream_id % 2) == 0) {
		http2_log(c, "invalid stream id");
		return HTTP2_PROTOCOL_ERROR;
	}
	if (c->stream_num == c->local_settings->max_concurrent_streams) {
		http2_log(c, "exceed max_concurrent_streams");
		return HTTP2_REFUSED_STREAM;
	}

	http2_stream_t *s = http2_stream_new(c);
	if (s == NULL) {
		return HTTP2_INTERNAL_ERROR;
	}

	/* init priority */
	s->p = http2_priority_new(c, stream_id);
	if (s->p == NULL) {
		return HTTP2_INTERNAL_ERROR;
	}
	s->p->s = s;

	http2_priority_update(s->p, c, exclusive, dependency, weight);

	return http2_process_payload_headers(s, buffer + priority_len,
			length - priority_len, priority_len);
}

static int http2_process_preface(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	if (length < 24) {
		return 0;
	}
	if (memcmp(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) {
		http2_log(c, "invalid preface");
		return HTTP2_PROTOCOL_ERROR;
	}

	http2_send_frame_settings(c);

	return 24;
}

typedef int http2_process_f(http2_connection_t *, const uint8_t *, int);

static http2_process_f *http2_frame_handlers[] = {
	http2_process_frame_data,
	http2_process_frame_headers,
	http2_process_frame_priority,
	http2_process_frame_unknown,
	http2_process_frame_settings,
	http2_process_frame_unknown,
	http2_process_frame_ping,
	http2_process_frame_goaway,
	http2_process_frame_window_update,
	http2_process_frame_continuation,
	http2_process_frame_unknown,
	http2_process_frame_headers_remaining,
	http2_process_preface,
};

static bool http2_error_code_is_connection(int ec)
{
	return ec != HTTP2_STREAM_CLOSED && ec != HTTP2_REFUSED_STREAM && ec != HTTP2_CANCEL;
}

static int http2_process_frame_header(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	if (length < sizeof(http2_frame_header_t)) {
		return 0;
	}

	http2_frame_header_t *header = (http2_frame_header_t *)buffer;
	c->frame.type = header->type;
	c->frame.flags = header->flags;
	c->frame.left = (header->len1 << 16) + (header->len2 << 8) + header->len3;
	c->frame.stream_id = (header->sid1 << 24) + (header->sid2 << 16)
			+ (header->sid3 << 8) + header->sid4;

	http2_log(c, "[debug] receive frame type=%d len=%d flags=0x%x sid=%d",
			c->frame.type, c->frame.left, c->frame.flags, c->frame.stream_id);

	if (c->frame.type >= HTTP2_FRAME_UNKNOWN) {
		printf("[info] unknow frame type %d\n", c->frame.type);
		c->frame.type = HTTP2_FRAME_UNKNOWN;
	}

	c->frame.left += sizeof(http2_frame_header_t); /* subtracted later */
	return sizeof(http2_frame_header_t);
}

#define MIN(a,b) (a)<(b)?(a):(b)
int http2_process_input(http2_connection_t *c, const uint8_t *buf_pos, int buf_len)
{
	http2_log(c, "[debug] http2_process_input %d", buf_len);

	if (c->goaway_error_code != 0) {
		return -2;
	}

	int buf_left = buf_len;
	while (buf_left > 0) {
		int proc_len;
		if (c->frame.left == 0) {
			proc_len = http2_process_frame_header(c, buf_pos, buf_left);
		} else {
			proc_len = http2_frame_handlers[c->frame.type](c,
					buf_pos, MIN(buf_left, c->frame.left));
		}

		if (proc_len == 0) { /* need more input */
			break;
		}
		if (proc_len < 0) {
			uint32_t error_code = -proc_len;

			/* if connection error, close the connection */
			if (http2_error_code_is_connection(proc_len)) {
				c->goaway_error_code = error_code;
				return -1;
			}

			/* else, stream error, send RST_STREAM and skip the buffer */
			http2_send_frame_rst_stream(c, c->frame.stream_id, error_code);
			proc_len = MIN(buf_left, c->frame.left);
		}

		c->frame.left -= proc_len;
		buf_pos += proc_len;
		buf_left -= proc_len;
	}

	http2_log(c, "[debug] process end with total %d", buf_len - buf_left);
	return buf_len - buf_left;
}


/* == some getters and setters */

void http2_connection_set_app_data(http2_connection_t *c, void *data)
{
	c->app_data = data;
}
void *http2_connection_get_app_data(http2_connection_t *c)
{
	return c->app_data;
}
uint32_t http2_connection_get_send_window(http2_connection_t *c)
{
	return c->send_window;
}

void http2_stream_set_app_data(http2_stream_t *s, void *data)
{
	s->app_data = data;
}
void *http2_stream_get_app_data(http2_stream_t *s)
{
	return s->app_data;
}
http2_connection_t *http2_stream_get_connection(http2_stream_t *s)
{
	return s->c;
}
uint32_t http2_stream_get_send_window(http2_stream_t *s)
{
	return MIN(s->send_window, s->c->send_window);
}


void http2_library_init(http2_hook_stream_new_f stream_new, http2_hook_stream_header_f stream_header,
		http2_hook_stream_body_f stream_body, http2_hook_stream_end_f stream_end,
		http2_hook_stream_reset_f stream_reset, http2_hook_control_frame_f control_frame,
		http2_hook_log_f log)
{
	hpack_library_init(true);

	http2_pool_connection = wuy_pool_new_type(http2_connection_t);
	http2_pool_stream = wuy_pool_new_type(http2_stream_t);
	http2_pool_priority = wuy_pool_new_type(http2_priority_t);

	http2_hook_stream_new = stream_new;
	http2_hook_stream_header = stream_header;
	http2_hook_stream_body = stream_body;
	http2_hook_stream_end = stream_end;
	http2_hook_stream_reset = stream_reset;
	http2_hook_control_frame = control_frame;
	http2_hook_log = log;
}
