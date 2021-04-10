#ifndef HTTP2_H
#define HTTP2_H

#include <stdint.h>
#include <stdbool.h>


typedef struct http2_connection http2_connection_t;

typedef struct http2_stream http2_stream_t;

struct http2_settings {
	uint32_t	header_table_size;
	uint32_t	enable_push;
	uint32_t	max_concurrent_streams;
	uint32_t	initial_window_size;
	uint32_t	max_frame_size;
	uint32_t	max_header_list_size;
};

struct http2_hooks {
	/* on creating new stream */
	bool (*stream_new)(http2_stream_t *, http2_connection_t *);

	/* on receiving stream request header */
	bool (*stream_header)(http2_stream_t *, const char *name_str,
				int name_len, const char *value_str, int value_len);

	/* on receiving stream request body */
	bool (*stream_body)(http2_stream_t *, const uint8_t *buf, int len);

	/* on closing stream */
	void (*stream_close)(http2_stream_t *);

	/* on ready to response stream */
	bool (*stream_response)(http2_stream_t *);

	/* on sending control frame */
	bool (*control_frame)(http2_connection_t *, const uint8_t *buf, int len);

	/* log */
	void (*log)(http2_connection_t *, const char *fmt, ...);
};

/* library init */
void http2_library_init(const struct http2_hooks *);

/* connection */
http2_connection_t *http2_connection_new(const struct http2_settings *settings);

void http2_connection_close(http2_connection_t *c);

int http2_process_input(http2_connection_t *c, const uint8_t *buf_pos, int buf_len);

void http2_schedular(http2_connection_t *c);

void http2_connection_ping(http2_connection_t *c);

bool http2_connection_in_reading(const http2_connection_t *c);

bool http2_connection_in_idle(const http2_connection_t *c);

void http2_connection_set_app_data(http2_connection_t *c, void *data);

void *http2_connection_get_app_data(const http2_connection_t *c);

void http2_connection_enable_log(http2_connection_t *c);

/* stream */
void http2_stream_close(http2_stream_t *s);

void http2_stream_set_app_data(http2_stream_t *s, void *data);

void *http2_stream_get_app_data(const http2_stream_t *s);

int32_t http2_stream_window(struct http2_stream *s);

/* frame */
#define HTTP2_FRAME_HEADER_SIZE 9
int http2_make_status_code(uint8_t *out_pos, int out_len, int status_code);

int http2_make_content_length(uint8_t *out_pos, int out_len, size_t content_length);

int http2_make_header(http2_stream_t *s, uint8_t *out_pos, int out_len,
		const char *name_str, int name_len, const char *value_str, int value_len);

void http2_make_frame_headers(http2_stream_t *s, uint8_t *frame_pos,
		int length, bool is_stream_end, bool is_headers_end);

void http2_make_frame_body(http2_stream_t *s, uint8_t *frame_pos,
		int length, bool is_stream_end);

#endif
