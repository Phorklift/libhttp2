#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "hpack.h"
#include "wuy_pool.h"
#include "wuy_list.h"

#include "http2.h"

#define error_log(...)
#define connection_close(...)
#define FTRACE_CONN

typedef int http2_process_f(http2_connection_t *, const uint8_t *, int);

struct http2_connection_s {

	wuy_list_t		streams_in_request;
	wuy_list_t		streams_in_response;
	int			stream_num;

	uint32_t		last_stream_id_in;
	uint32_t		last_stream_id_out;

	uint32_t		send_window;
	uint32_t		initial_window_size;

	/* current frame in parse */
	struct {
		uint8_t			type;
		uint8_t			flags;
		int			left;
		uint32_t		stream_id;
	}			frame;

	hpack_t			*hpack_decode;

	const http2_conf_t	*conf;

	void			*app_data;

	bool			recv_goaway;
	bool			want_ping_ack;
	bool			want_settings_ack;
};

struct http2_stream_s {
	wuy_list_node_t		list_node;

	http2_connection_t	*h2c;

	uint32_t		id;

	uint32_t		send_window;

	uint32_t		dependency;
	uint8_t			weight;

	unsigned		exclusive:1;
	unsigned		end_headers:1;
	unsigned		end_stream:1;
	unsigned		closed:1;

	void			*app_data;
};


typedef struct {
	uint8_t		len1, len2, len3;
	uint8_t		type;
	uint8_t		flags;
	uint8_t		sid1, sid2, sid3, sid4;
} http2_frame_header_t;


static wuy_pool_t *http2_pool_h2c;
static wuy_pool_t *http2_pool_stream;

#define HTTP2_FRAME_DATA		0x0
#define HTTP2_FRAME_HEADERS		0x1
#define HTTP2_FRAME_PRIORITY		0x2
#define HTTP2_FRAME_RST_STREAM		0x3
#define HTTP2_FRAME_SETTINGS		0x4
#define HTTP2_FRAME_PUSH_PROMISE	0x5
#define HTTP2_FRAME_PING		0x6
#define HTTP2_FRAME_GOAWAY		0x7
#define HTTP2_FRAME_WINDOW_UPDATE	0x8
#define HTTP2_FRAME_CONTINUATION	0x9
#define HTTP2_FRAME_UNKNOWN		0xa
#define HTTP2_FRAME_HEADERS_REMAIN	0xb
#define HTTP2_FRAME_PREFACE		0xc

#define HTTP2_FLAG_ACK			0x01
#define HTTP2_FLAG_END_STREAM		0x01
#define HTTP2_FLAG_END_HEADERS		0x04
#define HTTP2_FLAG_PADDED		0x08
#define HTTP2_FLAG_PRIORITY		0x20

static http2_hook_stream_new_f http2_hook_stream_new;
static http2_hook_stream_header_f http2_hook_stream_header;
static http2_hook_stream_body_f http2_hook_stream_body;
static http2_hook_stream_end_f http2_hook_stream_end;
static http2_hook_stream_reset_f http2_hook_stream_reset;
static http2_hook_control_frame_f http2_hook_control_frame;
static http2_hook_error_f http2_hook_error;
static http2_hook_log_f http2_hook_log;

#define http2_log(h2c, fmt, ...) \
	if (http2_hook_log != NULL) http2_hook_log(h2c, fmt, ##__VA_ARGS__)

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
int http2_make_header(http2_stream_t *stream, uint8_t *out_pos, int out_len,
		const char *name_str, int name_len, const char *value_str, int value_len)
{
	// TODO encode_hpack -> NULL
	return hpack_encode_header(NULL, name_str, name_len, value_str, value_len, out_pos, out_pos + out_len);
}
void http2_make_frame_headers(http2_stream_t *stream, uint8_t *frame_pos,
		int length, bool is_stream_end, bool is_headers_end)
{
	uint8_t flags = 0;
	if (is_stream_end) {
		flags |= HTTP2_FLAG_END_STREAM;
	}
	if (is_headers_end) {
		flags |= HTTP2_FLAG_END_HEADERS;
	}
	http2_build_frame_header(frame_pos, length, HTTP2_FRAME_HEADERS, flags, stream->id);
}

void http2_make_frame_body(http2_stream_t *stream, uint8_t *frame_pos,
		int length, bool is_stream_end)
{
	uint8_t flags = 0;
	if (is_stream_end) {
		flags |= HTTP2_FLAG_END_STREAM;
	}
	http2_build_frame_header(frame_pos, length, HTTP2_FRAME_DATA, flags, stream->id);
}


static void http2_send_frame_ping(http2_connection_t *h2c, const uint8_t *ack)
{
	uint8_t buffer[sizeof(http2_frame_header_t) + 8];

	uint8_t flags = 0;
	if (ack != NULL) {
		memcpy(buffer + sizeof(http2_frame_header_t), ack, 8);
		flags = HTTP2_FLAG_ACK;
	}

	http2_build_frame_header(buffer, 8, HTTP2_FRAME_PING, flags, 0);
	http2_hook_control_frame(h2c, buffer, sizeof(buffer));
}

void http2_connection_keep_alive(http2_connection_t *h2c)
{
	http2_send_frame_ping(h2c, NULL);
	h2c->want_ping_ack = true;
}

static void http2_send_frame_settings(http2_connection_t *h2c)
{
	uint8_t payload[] = {0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x04, 0x00, 0x60, 0x00, 0x00,};

	uint8_t buffer[100];
	memcpy(buffer + sizeof(http2_frame_header_t), payload, sizeof(payload));

	http2_build_frame_header(buffer, sizeof(payload), HTTP2_FRAME_SETTINGS, 0, 0);
	http2_hook_control_frame(h2c, buffer, sizeof(http2_frame_header_t) + sizeof(payload));
}

static int http2_send_frame_settings_ack(http2_connection_t *h2c)
{
	uint8_t buffer[sizeof(http2_frame_header_t)];
	http2_build_frame_header(buffer, 0, HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0);
	http2_hook_control_frame(h2c, buffer, sizeof(buffer));
	return 0;
}

static int http2_process_frame_unknown(http2_connection_t *c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	return length;
}

static int http2_process_frame_settings(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	if (h2c->frame.flags & HTTP2_FLAG_ACK) {
		return length;
	}
	if (h2c->frame.left % 6 != 0) {
		http2_log(h2c, "invalid SETTINGS frame");
		return HTTP2_ERROR;
	}
	if (h2c->frame.left > 6 * 10) {
		http2_log(h2c, "too long SETTINGS frame");
		return HTTP2_ERROR;
	}
	if (length < h2c->frame.left) {
		return 0;
	}

	const uint8_t *p = buffer;
	int i;
	for (i = 0; i < length; i += 6, p += 6) {
		uint16_t id = p[0] << 8 | p[1];
		uint32_t value = p[2] << 24 | p[3] << 16 | p[4] << 8 | p[5];

		switch (id) {
		case 0x1:
			// hpack_max_size(&h2c->hpack_decode, value);
			break;
		case 0x2:
			break;
		case 0x3:
			// h2c->peer_settings.concur_stream_max = value;
			break;
		case 0x4:
			if (value > 0x7FFFFFFF) {
				http2_log(h2c, "too big WINDOW_SIZE");
				return HTTP2_ERROR;
			}
			// h2c->peer_settings.initial_window_size = value;
			break;
		case 0x5:
		case 0x6:
			break;
		default:
			;
		}
	}

	http2_send_frame_settings_ack(h2c);

	return length;
}

static int http2_process_frame_ping(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	if (h2c->frame.flags & HTTP2_FLAG_ACK) {
		if (!h2c->want_ping_ack) {
			// TODO
		}
		h2c->want_ping_ack = false;
		return length;
	}
	if (h2c->frame.left != 8) {
		http2_log(h2c, "invalid PING frame");
		return HTTP2_ERROR;
	}
	if (length < h2c->frame.left) {
		return 0;
	}

	http2_send_frame_ping(h2c, buffer);
	return length;
}

static int http2_process_frame_goaway(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	if (length < h2c->frame.left) {
		return 0;
	}

	struct http2_goaway {
		uint32_t	last_stream_id;
		uint32_t	error_code;
		char		additional_debug[0];
	} *goaway = (struct http2_goaway *)buffer;

	if (length < sizeof(struct http2_goaway)) {
		http2_log(h2c, "invalid GOAWAY frame");
		return HTTP2_ERROR;
	}

	goaway->additional_debug[length - sizeof(struct http2_goaway) - 1] = '\0';
	http2_log(h2c, "GOAWAY: %x %s", goaway->error_code, goaway->additional_debug);

	h2c->recv_goaway = true;
	return length;
}

static http2_stream_t *http2_current_stream(http2_connection_t *h2c)
{
	wuy_list_node_t *node;
	wuy_list_iter(&h2c->streams_in_request, node) {
		http2_stream_t *stream = wuy_containerof(node, http2_stream_t, list_node);
		if (stream->id == h2c->frame.stream_id) {
			return stream;
		}
	}
	return NULL;
}

static http2_stream_t *http2_stream_new(http2_connection_t *h2c)
{
	error_log(h2c->connection->error_log, http2_LOG_DEBUG, "new stream: %u",
			h2c->frame.stream_id);

	http2_stream_t *stream = wuy_pool_alloc(http2_pool_stream);
	if (stream == NULL) {
		return NULL;
	}

	bzero(stream, sizeof(http2_stream_t));

	stream->id = h2c->frame.stream_id;
	stream->h2c = h2c;
	stream->send_window = h2c->initial_window_size;
	if (h2c->frame.flags & HTTP2_FLAG_END_HEADERS) {
		stream->end_headers = 1;
	}
	if (h2c->frame.flags & HTTP2_FLAG_END_STREAM) {
		stream->end_stream = 1;
	}
	wuy_list_append(&h2c->streams_in_request, &stream->list_node);

	h2c->stream_num++;
	h2c->last_stream_id_in = stream->id;

	http2_hook_stream_new(stream);
	return stream;
}

void http2_stream_close(http2_stream_t *stream)
{
	if (stream->closed) {
		return;
	}
	stream->closed = 1;

	// TODO

	wuy_list_delete(&stream->list_node);

	wuy_pool_free(stream);
	return;
}

static int http2_process_frame_window_update(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	if (length < h2c->frame.left) {
		return 0;
	}
	if (h2c->frame.left != 4) {
		connection_close(c, "invalid WINDOW_UPDATE frame", "");
		return HTTP2_ERROR;
	}

	const uint8_t *p = buffer;
	if ((p[0] & 0x80) != 0) {
		connection_close(c, "invalid WINDOW_UPDATE size", "");
		return HTTP2_ERROR;
	}
	uint32_t size = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];

	if (h2c->frame.stream_id == 0) {
		h2c->send_window += size;
	} else {
		http2_stream_t *stream = http2_current_stream(h2c);
		if (stream != NULL) {
			stream->send_window += size;
		}
	}

	error_log(c->error_log, http2_LOG_DEBUG, "WINDOW_UPDATE %d %d",
			h2c->frame.stream_id, size);

	return length;
}

/* move stream from streams_in_request to x, if end */
static void http2_stream_check_end(http2_stream_t *stream, int proc_len)
{
	http2_connection_t *h2c = stream->h2c;

	if (!(h2c->frame.flags & HTTP2_FLAG_END_STREAM)) {
		http2_log(h2c, "http2_stream_check_end no 1");
		return;
	}
	if (h2c->frame.left != proc_len) {
		http2_log(h2c, "http2_stream_check_end no 2 %d %d", h2c->frame.left, proc_len);
		return;
	}

	http2_log(h2c, "http2_stream_check_end yes");

	http2_hook_stream_end(stream);

	wuy_list_delete(&stream->list_node);
	// TODO
	wuy_list_append(&h2c->streams_in_response, &stream->list_node);
}

static int http2_process_frame_data(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	http2_stream_t *stream = http2_current_stream(h2c);
	if (stream == NULL) { /* has been closed */
		return length;
	}
	if (stream->end_stream) {
		http2_log(h2c, "data to end_stream");
		return HTTP2_ERROR;
	}

	http2_hook_stream_body(stream, buffer, length);

	http2_stream_check_end(stream, length);

	return length;
}

static int http2_process_header_entry(http2_stream_t *stream,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	const char *name_str, *value_str;
	int name_len, value_len;

	int proc_len = hpack_decode_header(stream->h2c->hpack_decode,
			buffer, buffer + length, &name_str, &name_len,
			&value_str, &value_len);

	if (proc_len < 0) {
		if (proc_len == HPERR_AGAIN) {
			return 0;
		}
		http2_log(stream->h2c, "hpack decode fail");
		return HTTP2_ERROR;
	}

	error_log(c->error_log, http2_LOG_DEBUG,
			"hpack decode header %d %s", proc_len, name_str);

	http2_hook_stream_header(stream, name_str, name_len, value_str, value_len);

	return proc_len;
}

static int http2_process_headers(http2_stream_t *stream,
		const uint8_t *buffer, int length, int extra_len)
{
	const uint8_t *buf_pos = buffer;
	int buf_left = length;
	while (buf_left > 0) {
		int proc_len = http2_process_header_entry(stream, buf_pos, buf_left);
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

	http2_stream_check_end(stream, total_len);

	stream->h2c->frame.type = HTTP2_FRAME_HEADERS_REMAIN;
	return total_len;
}

static int http2_process_frame_continuation(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	http2_stream_t *stream = http2_current_stream(h2c);
	if (stream == NULL) {
		return HTTP2_ERROR;
	}
	if (stream->end_headers) {
		http2_log(h2c, "header on end_headers");
		return HTTP2_ERROR;
	}

	return http2_process_headers(stream, buffer, length, 0);
}

static int http2_process_frame_headers_remain(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	http2_stream_t *stream = http2_current_stream(h2c);
	if (stream == NULL) {
		return HTTP2_ERROR;
	}
	return http2_process_headers(stream, buffer, length, 0);
}

static int http2_process_frame_headers(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	int priority_len = 0;

	/* parse priority */
	uint8_t exclusive = 0;
	uint32_t dependency = 0;
	uint8_t weight = 0;
	if (h2c->frame.flags & HTTP2_FLAG_PRIORITY) {
		if (length < 5) {
			return 0;
		}
		const uint8_t *p = buffer;
		exclusive = p[0] > 7;
		dependency = (p[0] & 0x7F) << 24 | p[1] << 16 | p[2] << 8 | p[3];
		weight = p[4];
		priority_len = 5;
	}

	/* create new stream */
	uint32_t stream_id = h2c->frame.stream_id;
	if (stream_id <= h2c->last_stream_id_in || (stream_id % 2) == 0) {
		http2_log(h2c, "invalid stream id");
		return HTTP2_ERROR;
	}
	if (h2c->stream_num == h2c->conf->max_concurrenct_streams) {
		printf(" -- too many streams\n");
		return HTTP2_ERROR; // XXX return what?
	}

	http2_stream_t *stream = http2_stream_new(h2c);
	if (stream == NULL) {
		http2_log(h2c, "new stream fails");
		return HTTP2_ERROR;
	}

	stream->exclusive = exclusive;
	stream->dependency = dependency;
	stream->weight = weight;

	return http2_process_headers(stream, buffer + priority_len,
			length - priority_len, priority_len);
}

static int http2_process_preface(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	if (length < 24) {
		return 0;
	}
	if (memcmp(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) {
		return HTTP2_ERROR;
	}

	http2_send_frame_settings(h2c);

	return 24;
}

static http2_process_f *http2_frame_handlers[] = {
	http2_process_frame_data,
	http2_process_frame_headers,
	http2_process_frame_unknown,
	http2_process_frame_unknown,
	http2_process_frame_settings,
	http2_process_frame_unknown,
	http2_process_frame_ping,
	http2_process_frame_goaway,
	http2_process_frame_window_update,
	http2_process_frame_continuation,
	http2_process_frame_unknown,
	http2_process_frame_headers_remain,
	http2_process_preface,
};

static int http2_process_frame_header(http2_connection_t *h2c,
		const uint8_t *buffer, int length)
{
	FTRACE_CONN;

	if (length < sizeof(http2_frame_header_t)) {
		return 0;
	}

	http2_frame_header_t *header = (http2_frame_header_t *)buffer;
	h2c->frame.type = header->type;
	h2c->frame.flags = header->flags;
	h2c->frame.left = (header->len1 << 16) + (header->len2 << 8) + header->len3;
	h2c->frame.stream_id = (header->sid1 << 24) + (header->sid2 << 16)
			+ (header->sid3 << 8) + header->sid4;

	http2_log(h2c, "receive frame type=%d len=%d flags=0x%x sid=%d",
			h2c->frame.type, h2c->frame.left, h2c->frame.flags, h2c->frame.stream_id);

	if (h2c->frame.type >= HTTP2_FRAME_UNKNOWN) {
		printf("unknow frame type %d\n", h2c->frame.type);
		h2c->frame.type = HTTP2_FRAME_UNKNOWN;
	}

	h2c->frame.left += sizeof(http2_frame_header_t); /* subtracted later */
	return sizeof(http2_frame_header_t);
}

#define MIN(a,b) (a)<(b)?(a):(b)
int http2_connection_process(http2_connection_t *h2c, const uint8_t *buf_pos, int buf_len)
{
	http2_log(h2c, "http2_connection_process %d", buf_len);

	int buf_left = buf_len;
	while (buf_left > 0) {
		int proc_len;
		if (h2c->frame.left == 0) {
			proc_len = http2_process_frame_header(h2c, buf_pos, buf_left);
		} else {
			proc_len = http2_frame_handlers[h2c->frame.type](h2c,
					buf_pos, MIN(buf_left, h2c->frame.left));
		}

		http2_log(h2c, "process length %d", proc_len);

		if (proc_len == 0) {
			break;
		}
		if (proc_len < 0) {
			return proc_len;
		}

		h2c->frame.left -= proc_len;
		buf_pos += proc_len;
		buf_left -= proc_len;
	}

	http2_log(h2c, "process total %d", buf_len - buf_left);
	return buf_len - buf_left;
}

http2_stream_t *http2_response_stream(http2_connection_t *h2c)
{
	wuy_list_node_t *node = wuy_list_first(&h2c->streams_in_response);
	if (node == NULL) {
		return NULL;
	}
	return wuy_containerof(node, http2_stream_t, list_node);
}

http2_connection_t *http2_connection_new(const http2_conf_t *conf)
{
	http2_connection_t *h2c = wuy_pool_alloc(http2_pool_h2c);
	if (h2c == NULL) {
		return NULL;
	}

	bzero(h2c, sizeof(http2_connection_t));

	h2c->frame.type = HTTP2_FRAME_PREFACE;
	h2c->frame.left = 24; /* length of preface */
	h2c->initial_window_size = 65535;
	h2c->send_window = h2c->initial_window_size;
	h2c->conf = conf;
	h2c->hpack_decode = hpack_new(4096); /* see RFC7540 section 6.5.2 */
	wuy_list_init(&h2c->streams_in_request);
	wuy_list_init(&h2c->streams_in_response);

	return h2c;
}

void http2_connection_set_app_data(http2_connection_t *h2c, void *data)
{
	h2c->app_data = data;
}
void *http2_connection_get_app_data(http2_connection_t *h2c)
{
	return h2c->app_data;
}

void http2_stream_set_app_data(http2_stream_t *stream, void *data)
{
	stream->app_data = data;
}
void *http2_stream_get_app_data(http2_stream_t *stream)
{
	return stream->app_data;
}
http2_connection_t *http2_stream_get_connection(http2_stream_t *stream)
{
	return stream->h2c;
}

void http2_connection_close(http2_connection_t *h2c)
{
}

void http2_library_init(http2_hook_stream_new_f stream_new, http2_hook_stream_header_f stream_header,
		http2_hook_stream_body_f stream_body, http2_hook_stream_end_f stream_end,
		http2_hook_stream_reset_f stream_reset, http2_hook_control_frame_f control_frame,
		http2_hook_error_f error, http2_hook_log_f log)
{
	hpack_library_init(true);

	http2_pool_h2c = wuy_pool_new_type(http2_connection_t);
	http2_pool_stream = wuy_pool_new_type(http2_stream_t);

	http2_hook_stream_new = stream_new;
	http2_hook_stream_header = stream_header;
	http2_hook_stream_body = stream_body;
	http2_hook_stream_end = stream_end;
	http2_hook_stream_reset = stream_reset;
	http2_hook_control_frame = control_frame;
	http2_hook_error = error;
	http2_hook_log = log;
}
