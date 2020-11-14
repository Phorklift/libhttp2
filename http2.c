#include <stdlib.h>

#include "libwuya/wuy_list.h"
#include "libwuya/wuy_hlist.h"

#include "libhpack/hpack.h"

#include "http2_internal.h"
#include "http2_priority.h"

#include "http2.h"


http2_stream_header_f http2_hook_stream_header;
http2_stream_body_f http2_hook_stream_body;
http2_stream_close_f http2_hook_stream_close;
http2_stream_response_f http2_hook_stream_response;
http2_control_frame_f http2_hook_control_frame;
http2_log_f http2_hook_log;


void http2_build_frame_header(uint8_t *buf, int length,
		uint8_t type, uint8_t flags, uint32_t stream_id)
{
	struct http2_frame_header *fh = (struct http2_frame_header *)buf;
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
int http2_make_header(struct http2_stream *s, uint8_t *out_pos, int out_len,
		const char *name_str, int name_len, const char *value_str, int value_len)
{
	// TODO encode_hpack -> NULL
	return hpack_encode_header(NULL, name_str, name_len, value_str, value_len, out_pos, out_pos + out_len);
}
void http2_make_frame_headers(struct http2_stream *s, uint8_t *frame_pos,
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

void http2_stream_active_tmp(struct http2_stream *s)
{
	s->p->active = true;
}
void http2_make_frame_body(struct http2_stream *s, uint8_t *frame_pos,
		int length, bool is_stream_end)
{
	uint8_t flags = 0;
	if (is_stream_end) {
		flags |= HTTP2_FLAG_END_STREAM;
	}
	http2_build_frame_header(frame_pos, length, HTTP2_FRAME_DATA, flags, s->p->id);

	if (length == 0) {
		return;
	}

	/* set active back */
	s->p->active = true;

	s->send_window -= length;
	s->c->send_window -= length;

	/* update all ancients' consumed */ // TODO move to http2_priority.c
	float consumed = (float)length;
	struct http2_priority *p;
	for (p = s->p; p != NULL; p = p->parent) {
		p->consumed += consumed / p->weight;

		if (p->exclusive) {
			continue;
		}

		/* sort the non-exclusive priority in consumed order */
		wuy_list_t *children = (p->parent != NULL) ? &p->parent->children
				: &s->c->priority_root_children;

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

static void http2_send_frame_goaway(struct http2_connection *c, uint32_t error_code)
{
	struct http2_goaway {
		uint32_t	last_stream_id;
		uint32_t	error_code;
		char		additional_debug[0];
	};

	uint8_t buffer[sizeof(struct http2_frame_header) + sizeof(struct http2_goaway)];
	struct http2_goaway *goaway = (struct http2_goaway *)(buffer + sizeof(struct http2_frame_header));
	goaway->last_stream_id = c->last_stream_id_in; // XXX should count processed only
	goaway->error_code = error_code;

	http2_build_frame_header(buffer, sizeof(struct http2_goaway), HTTP2_FRAME_GOAWAY, 0, 0);
	http2_hook_control_frame(c, buffer, sizeof(buffer));
}


/* == stream operations */

struct http2_stream *http2_stream_new(struct http2_connection *c)
{
	http2_log(c, "new stream: %u", c->frame.stream_id);

	struct http2_stream *s = calloc(1, sizeof(struct http2_stream));
	if (s == NULL) {
		return NULL;
	}

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

	return s;
}

bool http2_stream_close(struct http2_stream *s)
{
	struct http2_connection *c = s->c;

	http2_priority_close(s->p);

	free(s);

	c->stream_num--;
	return c->stream_num == 0;
}

void http2_stream_set_app_data(struct http2_stream *s, void *data)
{
	s->app_data = data;
}
void *http2_stream_get_app_data(struct http2_stream *s)
{
	return s->app_data;
}
struct http2_connection *http2_stream_get_connection(struct http2_stream *s)
{
	return s->c;
}
#define MIN(a,b) (a)<(b)?(a):(b)
uint32_t http2_stream_get_send_window(struct http2_stream *s)
{
	return MIN(s->send_window, s->c->send_window);
}


/* == connection operations */

struct http2_connection *http2_connection_new(const struct http2_settings *settings)
{
	struct http2_connection *c = calloc(1, sizeof(struct http2_connection));
	if (c == NULL) {
		return NULL;
	}

	http2_log(c, "[debug] new connection %p", c);

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

	return c;
}

void http2_connection_close(struct http2_connection *c)
{
	http2_log(c, "[debug] close connection %p", c);

	http2_send_frame_goaway(c, c->goaway_error_code);

	hpack_free(c->hpack_decode);

	int i;
	for (i = 0; i < HTTP2_BUCKET_SIZE; i++) {
		struct http2_priority *p;
		wuy_hlist_iter_type(&c->priority_buckets[i], p, hash_node) {
			if (p->s != NULL) {
				/* http2_stream_close() is expected to be called in the hook */
				http2_hook_stream_close(p->s);
			}
		}
	}

	struct http2_priority *p;
	while(wuy_list_pop_type(&c->priority_closed_lru, p, closed_node)) {
		free(p);
	}

	free(c);
}

void http2_connection_set_app_data(struct http2_connection *c, void *data)
{
	c->app_data = data;
}
void *http2_connection_get_app_data(struct http2_connection *c)
{
	return c->app_data;
}
uint32_t http2_connection_get_send_window(struct http2_connection *c)
{
	return c->send_window;
}


/* == library init */

void http2_library_init(bool (*stream_header)(struct http2_stream *, const char *name_str,
			int name_len, const char *value_str, int value_len),
		bool (*stream_body)(struct http2_stream *, const uint8_t *buf, int len),
		void (*stream_close)(struct http2_stream *),
		bool (*stream_response)(struct http2_stream *, int window),
		bool (*control_frame)(struct http2_connection *, const uint8_t *buf, int len))
{
	http2_hook_stream_header = stream_header;
	http2_hook_stream_body = stream_body;
	http2_hook_stream_close = stream_close;
	http2_hook_stream_response = stream_response;
	http2_hook_control_frame = control_frame;
}

void http2_set_log(http2_log_f log)
{
	http2_hook_log = log;
}
