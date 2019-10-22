#ifndef HTTP2_H
#define HTTP2_H

#include <stdint.h>
#include <stdbool.h>


typedef struct http2_connection_s http2_connection_t;

typedef struct http2_stream_s http2_stream_t;

typedef struct {
	uint32_t	header_table_size;
	uint32_t	enable_push;
	uint32_t	max_concurrent_streams;
	uint32_t	initial_window_size;
	uint32_t	max_frame_size;
	uint32_t	max_header_list_size;
} http2_settings_t;


/* library init */
void http2_library_init(bool (*stream_header)(http2_stream_t *, const char *name_str,
			int name_len, const char *value_str, int value_len),
		bool (*stream_body)(http2_stream_t *, const uint8_t *buf, int len),
		void (*stream_reset)(http2_stream_t *),
		bool (*control_frame)(http2_connection_t *, const uint8_t *buf, int len));

void http2_set_log(void (*log)(http2_connection_t *, const char *fmt, ...));

/* connection */
http2_connection_t *http2_connection_new(const http2_settings_t *settings);
void http2_connection_close(http2_connection_t *c);

void http2_connection_set_app_data(http2_connection_t *c, void *data);
void *http2_connection_get_app_data(http2_connection_t *c);

int http2_process_input(http2_connection_t *c, const uint8_t *buf_pos, int buf_len);

http2_stream_t *http2_schedular(http2_connection_t *c);

int http2_connection_idle_time(http2_connection_t *c);

void http2_connection_keep_alive(http2_connection_t *c);

/* stream */
void http2_stream_set_app_data(http2_stream_t *s, void *data);
void *http2_stream_get_app_data(http2_stream_t *s);
http2_connection_t *http2_stream_get_connection(http2_stream_t *s);
void http2_stream_close(http2_stream_t *s);

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
