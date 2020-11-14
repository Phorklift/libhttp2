#ifndef HTTP2_INTERNAL_H
#define HTTP2_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>

#include "libwuya/wuy_list.h"
#include "libwuya/wuy_hlist.h"
#include "libhpack/hpack.h"

#include "http2.h"


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

enum http2_frame_flag {
	HTTP2_FLAG_ACK = 0x01,
	HTTP2_FLAG_END_STREAM = 0x01,
	HTTP2_FLAG_END_HEADERS = 0x04,
	HTTP2_FLAG_PADDED = 0x08,
	HTTP2_FLAG_PRIORITY = 0x20,
};

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


struct http2_frame_header {
	uint8_t		len1, len2, len3;
	uint8_t		type;
	uint8_t		flags;
	uint8_t		sid1, sid2, sid3, sid4;
};

struct http2_connection {

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

	struct http2_settings	remote_settings;
	const struct http2_settings	*local_settings;

	void			*app_data;

	enum http2_log_level	log_level;

	bool			recv_goaway;
	bool			want_ping_ack;
	bool			want_settings_ack;
};

struct http2_stream {
	struct http2_connection	*c;

	struct http2_priority	*p;

	uint32_t		send_window;

	unsigned		end_headers:1;
	unsigned		end_stream:1;

	void			*app_data;
};

extern const struct http2_hooks *http2_hooks;

#define http2_log(c, level, fmt, ...) \
	if (level <= c->log_level) http2_hooks->log(c, level, fmt, ##__VA_ARGS__)

#define http2_log_debug(c, fmt, ...) http2_log(c, HTTP2_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define http2_log_error(c, fmt, ...) http2_log(c, HTTP2_LOG_ERROR, fmt, ##__VA_ARGS__)


struct http2_stream *http2_stream_new(struct http2_connection *c);

void http2_build_frame_header(uint8_t *buf, int length,
		uint8_t type, uint8_t flags, uint32_t stream_id);

#endif
