#ifndef HTTP2_H
#define HTTP2_H

#include <stdint.h>

#define HTTP2_ERROR -1

typedef struct http2_connection_s http2_connection_t;

typedef struct http2_stream_s http2_stream_t;

typedef struct {
	uint32_t		max_concurrenct_streams;
} http2_conf_t;


/* library init */
typedef void (*http2_hook_stream_new_f)(http2_stream_t *);
typedef void (*http2_hook_stream_header_f)(http2_stream_t *, const char *name_str,
		int name_len, const char *value_str, int value_len);
typedef void (*http2_hook_stream_body_f)(http2_stream_t *, const uint8_t *buf, int len);
typedef void (*http2_hook_stream_end_f)(http2_stream_t *);
typedef void (*http2_hook_stream_reset_f)(http2_stream_t *);
typedef void (*http2_hook_control_frame_f)(http2_connection_t *, const uint8_t *, int);
typedef void (*http2_hook_error_f)(http2_connection_t *);
typedef void (*http2_hook_log_f)(http2_connection_t *, const char *fmt, ...);

void http2_library_init(http2_hook_stream_new_f, http2_hook_stream_header_f,
		http2_hook_stream_body_f, http2_hook_stream_end_f,
		http2_hook_stream_reset_f, http2_hook_control_frame_f,
		http2_hook_error_f, http2_hook_log_f);

/* connection */
http2_connection_t *http2_connection_new(const http2_conf_t *conf);
void http2_connection_close(http2_connection_t *h2c);

void http2_connection_set_app_data(http2_connection_t *h2c, void *data);
void *http2_connection_get_app_data(http2_connection_t *h2c);

int http2_connection_process(http2_connection_t *h2c, const uint8_t *buf_pos, int buf_len);

http2_stream_t *http2_response_stream(http2_connection_t *h2c);

int http2_connection_idle_time(http2_connection_t *h2c);

void http2_connection_keep_alive(http2_connection_t *h2c);

/* stream */
void http2_stream_set_app_data(http2_stream_t *stream, void *data);
void *http2_stream_get_app_data(http2_stream_t *stream);
http2_connection_t *http2_stream_get_connection(http2_stream_t *stream);
void http2_stream_close(http2_stream_t *stream);

/* frame */
#define HTTP2_FRAME_HEADER_SIZE 9
int http2_make_status_code(uint8_t *out_pos, int out_len, int status_code);

int http2_make_content_length(uint8_t *out_pos, int out_len, size_t content_length);

int http2_make_header(http2_stream_t *stream, uint8_t *out_pos, int out_len,
		const char *name_str, int name_len, const char *value_str, int value_len);

void http2_make_frame_headers(http2_stream_t *stream, uint8_t *frame_pos,
		int length, bool is_stream_end, bool is_headers_end);

void http2_make_frame_body(http2_stream_t *stream, uint8_t *frame_pos,
		int length, bool is_stream_end);


#endif
