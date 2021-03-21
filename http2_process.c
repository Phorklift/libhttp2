#include <string.h>

#include "http2_priority.h"
#include "http2_internal.h"
#include "http2.h"

/* == control frame sending */
static void http2_send_frame_ping(struct http2_connection *c, const uint8_t *ack)
{
	uint8_t buffer[sizeof(struct http2_frame_header) + 8];

	uint8_t flags = 0;
	if (ack != NULL) {
		memcpy(buffer + sizeof(struct http2_frame_header), ack, 8);
		flags = HTTP2_FLAG_ACK;
	}

	http2_build_frame_header(buffer, 8, HTTP2_FRAME_PING, flags, 0);
	http2_hooks->control_frame(c, buffer, sizeof(buffer));
}

void http2_connection_ping(struct http2_connection *c)
{
	http2_send_frame_ping(c, NULL);
	c->want_ping_ack = true;
}

static void http2_send_frame_settings(struct http2_connection *c)
{
	uint8_t payload[] = {0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x04, 0x00, 0x60, 0x00, 0x00,};

	uint8_t buffer[100];
	memcpy(buffer + sizeof(struct http2_frame_header), payload, sizeof(payload));

	http2_build_frame_header(buffer, sizeof(payload), HTTP2_FRAME_SETTINGS, 0, 0);
	http2_hooks->control_frame(c, buffer, sizeof(struct http2_frame_header) + sizeof(payload));
}

static int http2_send_frame_settings_ack(struct http2_connection *c)
{
	uint8_t buffer[sizeof(struct http2_frame_header)];
	http2_build_frame_header(buffer, 0, HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0);
	http2_hooks->control_frame(c, buffer, sizeof(buffer));
	return 0;
}

static void http2_send_frame_rst_stream(struct http2_connection *c, uint32_t id, uint32_t error_code)
{
	if (id == c->last_stream_id_reset) {
		return;
	}

	uint8_t buffer[sizeof(struct http2_frame_header) + 4];

	memcpy(buffer + sizeof(struct http2_frame_header), &error_code, 4); // bigendian??

	http2_build_frame_header(buffer, 4, HTTP2_FRAME_RST_STREAM, 0, id);
	http2_hooks->control_frame(c, buffer, sizeof(buffer));

	c->last_stream_id_reset = id;
}


/* == process input */
static struct http2_stream *http2_process_current(struct http2_connection *c)
{
	struct http2_priority *p = http2_priority_hash_search(c, c->frame.stream_id);
	return p == NULL ? NULL : p->s;
}

static int http2_process_frame_unknown(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	return length;
}

static int http2_process_frame_push_promise(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	http2_log_error(c, "not-expect PUSH_PROMISE frame");
	return length;
}

static int http2_process_frame_settings(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	if (c->frame.flags & HTTP2_FLAG_ACK) {
		return length;
	}
	if (c->frame.left % 6 != 0) {
		http2_log_error(c, "invalid SETTINGS frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}
	if (c->frame.left > 6 * 10) {
		http2_log_error(c, "too long SETTINGS frame");
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
				http2_log_error(c, "too big WINDOW_SIZE");
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

static int http2_process_frame_ping(struct http2_connection *c,
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
		http2_log_error(c, "invalid PING frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}
	if (length < c->frame.left) {
		return 0;
	}

	http2_send_frame_ping(c, buffer);
	return length;
}

static int http2_process_frame_rst_stream(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	uint32_t code = *(uint32_t *)buffer;

	http2_log_debug(c, "RST_STREAM: 0x%x, sid=%d", code, c->frame.stream_id);

	struct http2_stream *s = http2_process_current(c);
	if (s != NULL) {
		http2_stream_close_internal(s);
	}
	return length;
}

static int http2_process_frame_goaway(struct http2_connection *c,
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
		http2_log_error(c, "invalid GOAWAY frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}

	goaway->additional_debug[length - sizeof(struct http2_goaway) - 1] = '\0';
	http2_log_debug(c, "GOAWAY: %x %s", goaway->error_code, goaway->additional_debug);

	c->recv_goaway = true;
	return length;
}

static int http2_process_frame_window_update(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	if (length < c->frame.left) {
		return 0;
	}
	if (c->frame.left != 4) {
		http2_log_error(c, "invalid WINDOW_UPDATE frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}

	const uint8_t *p = buffer;
	if ((p[0] & 0x80) != 0) {
		http2_log_error(c, "invalid WINDOW_UPDATE frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}
	uint32_t size = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];

	if (c->frame.stream_id == 0) {
		c->send_window += size;
		if (c->send_window < 0) {
			http2_log_error(c, "connection WINDOW_UPDATE size exceed");
			return HTTP2_FLOW_CONTROL_ERROR;
		}
	} else {
		struct http2_stream *s = http2_process_current(c);
		if (s != NULL) {
			s->send_window += size;
			if (s->send_window < 0) {
				http2_log_error(c, "stream WINDOW_UPDATE size exceed");
				return HTTP2_FLOW_CONTROL_ERROR;
			}
		}
	}

	http2_log_debug(c, "WINDOW_UPDATE %u %u", c->frame.stream_id, size);

	return length;
}

static int http2_process_priority(const uint8_t *p, int length,
		bool *exclusive, uint32_t *dependency, uint8_t *weight)
{
	if (length < 5) {
		return 0;
	}
	*exclusive = p[0] >> 7;
	*dependency = (p[0] & 0x7F) << 24 | p[1] << 16 | p[2] << 8 | p[3];
	*weight = p[4];
	return 5;
}

static int http2_process_frame_priority(struct http2_connection *c,
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
		http2_log_error(c, "invalid PRIORITY frame");
		return HTTP2_FRAME_SIZE_ERROR;
	}

	uint32_t id = c->frame.stream_id;
	struct http2_priority *p = http2_priority_hash_search(c, id);
	if (p == NULL) {
		if (id <= c->last_stream_id_in) { /* has been closed */
			return length;
		}

		p = http2_priority_new(c, id);
		if (p == NULL) {
			return length;
		}

		c->priority_closed_num++;
		wuy_list_append(&c->priority_closed_lru, &p->closed_node);
	}

	http2_priority_update(p, c, exclusive, dependency, weight);
	return length;
}


static int http2_process_frame_data(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	struct http2_stream *s = http2_process_current(c);
	if (s == NULL) { /* has been closed */
		return HTTP2_STREAM_CLOSED;
	}
	if (s->end_stream) {
		http2_log_error(c, "data to end_stream");
		return HTTP2_PROTOCOL_ERROR;
	}

	http2_hooks->stream_body(s, buffer, length);

	/* check end_stream */
	if (length == s->c->frame.left && (c->frame.flags & HTTP2_FLAG_END_STREAM)) {
		s->end_stream = true;
		http2_hooks->stream_body(s, NULL, 0);
	}

	return length;
}

static int http2_process_header_entry(struct http2_stream *s,
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
		http2_log_error(s->c, "hpack decode fail");
		return HTTP2_PROTOCOL_ERROR;
	}

	http2_hooks->stream_header(s, name_str, name_len, value_str, value_len);

	return proc_len;
}

static int http2_process_payload_headers(struct http2_stream *s,
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

	/* check end_headers and end_stream */
	if (total_len == s->c->frame.left && s->end_headers) {
		/* @name_len argument is used to info end_stream */
		http2_hooks->stream_header(s, NULL, s->end_stream, NULL, 0);
	}

	s->c->frame.type = HTTP2_FRAME_HEADERS_REMAINING;
	return total_len;
}

static int http2_process_frame_continuation(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	struct http2_stream *s = http2_process_current(c);
	if (s == NULL) {
		return (c->frame.stream_id == c->last_stream_id_reset)
			? HTTP2_STREAM_CLOSED : HTTP2_PROTOCOL_ERROR;
	}
	if (s->end_headers) {
		http2_log_error(c, "header on end_headers");
		return HTTP2_PROTOCOL_ERROR;
	}

	return http2_process_payload_headers(s, buffer, length, 0);
}

static int http2_process_frame_headers_remaining(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	struct http2_stream *s = http2_process_current(c);
	if (s == NULL) {
		return HTTP2_STREAM_CLOSED;
	}
	return http2_process_payload_headers(s, buffer, length, 0);
}

static int http2_process_frame_headers(struct http2_connection *c,
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
		http2_log_error(c, "invalid stream id");
		return HTTP2_PROTOCOL_ERROR;
	}
	if (c->stream_num == c->local_settings->max_concurrent_streams) {
		http2_log_error(c, "exceed max_concurrent_streams %d", c->stream_num);
		return HTTP2_REFUSED_STREAM;
	}

	struct http2_stream *s = http2_stream_new(c);
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

static int http2_process_preface(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	if (length < 24) {
		return 0;
	}
	if (memcmp(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) {
		http2_log_error(c, "invalid preface");
		return HTTP2_PROTOCOL_ERROR;
	}

	http2_send_frame_settings(c);

	return 24;
}

typedef int http2_process_f(struct http2_connection *, const uint8_t *, int);

static http2_process_f *http2_frame_handlers[] = {
	http2_process_frame_data,
	http2_process_frame_headers,
	http2_process_frame_priority,
	http2_process_frame_rst_stream,
	http2_process_frame_settings,
	http2_process_frame_push_promise,
	http2_process_frame_ping,
	http2_process_frame_goaway,
	http2_process_frame_window_update,
	http2_process_frame_continuation,

	/* internal */
	http2_process_frame_unknown,
	http2_process_frame_headers_remaining,
	http2_process_preface,
};

static bool http2_error_code_is_connection(int ec)
{
	return ec != HTTP2_STREAM_CLOSED && ec != HTTP2_REFUSED_STREAM && ec != HTTP2_CANCEL;
}

static int http2_process_frame_header(struct http2_connection *c,
		const uint8_t *buffer, int length)
{
	if (length < sizeof(struct http2_frame_header)) {
		return 0;
	}

	struct http2_frame_header *header = (struct http2_frame_header *)buffer;
	c->frame.type = header->type;
	c->frame.flags = header->flags;
	c->frame.left = (header->len1 << 16) + (header->len2 << 8) + header->len3;
	c->frame.stream_id = (header->sid1 << 24) + (header->sid2 << 16)
			+ (header->sid3 << 8) + header->sid4;

	http2_log_debug(c, "receive frame type=%d len=%d flags=0x%x sid=%d",
			c->frame.type, c->frame.left, c->frame.flags, c->frame.stream_id);

	if (c->frame.type >= HTTP2_FRAME_UNKNOWN) {
		http2_log_error(c, "unknown frame type %d", c->frame.type);
		c->frame.type = HTTP2_FRAME_UNKNOWN;
	}

	c->frame.left += sizeof(struct http2_frame_header); /* subtracted later */
	return sizeof(struct http2_frame_header);
}

#define MIN(a,b) (a)<(b)?(a):(b)
int http2_process_input(struct http2_connection *c, const uint8_t *buf_pos, int buf_len)
{
	http2_log_debug(c, "[[[ http2_process_input %d", buf_len);

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

	http2_log_debug(c, "]]] process end with total %d", buf_len - buf_left);
	return buf_len - buf_left;
}
