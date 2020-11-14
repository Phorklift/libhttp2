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


/* hook type on receiving stream request header */
typedef bool (*http2_stream_header_f)(http2_stream_t *, const char *name_str,
			int name_len, const char *value_str, int value_len);

/* hook type on receiving stream request body */
typedef bool (*http2_stream_body_f)(http2_stream_t *, const uint8_t *buf, int len);

/* hook type on closing stream */
typedef void (*http2_stream_close_f)(http2_stream_t *);

/* hook type on ready to response stream */
typedef bool (*http2_stream_response_f)(http2_stream_t *, int window);

/* hook type on sending control frame */
typedef bool (*http2_control_frame_f)(http2_connection_t *, const uint8_t *buf, int len);

/* hook type of log */
typedef bool (*http2_log_f)(http2_connection_t *, const char *fmt, ...);

/* library init */
void http2_library_init(http2_stream_header_f, http2_stream_body_f,
		http2_stream_close_f, http2_stream_response_f,
		http2_control_frame_f);

/* set log hook */
void http2_set_log(http2_log_f); // TODO add level


/* connection */
http2_connection_t *http2_connection_new(const struct http2_settings *settings);
void http2_connection_close(http2_connection_t *c);

void http2_connection_set_app_data(http2_connection_t *c, void *data);
void *http2_connection_get_app_data(http2_connection_t *c);

int http2_process_input(http2_connection_t *c, const uint8_t *buf_pos, int buf_len);

void http2_schedular(http2_connection_t *c);

void http2_connection_ping(http2_connection_t *c);

bool http2_connection_in_reading(http2_connection_t *c);

/* stream */
void http2_stream_set_app_data(http2_stream_t *s, void *data);
void *http2_stream_get_app_data(http2_stream_t *s);
http2_connection_t *http2_stream_get_connection(http2_stream_t *s); // removed if add hook-stream-new
bool http2_stream_close(http2_stream_t *s);

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
