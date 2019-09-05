#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "loop.h"
#include "http2.h"
#include "wuy_pool.h"

typedef struct {
	loop_stream_t		*loop_stream;
	http2_connection_t	*h2c;

	uint8_t			*buffer;
	uint8_t			*buf_start;
	uint8_t			*buf_end;
} example_connection_t;

typedef struct {
	example_connection_t	*c;
	http2_stream_t		*http2_stream;

	char			*path;
	FILE			*fp;
	size_t			content_length;
	size_t			response_length;

	bool			response_headers;
} example_request_t;


static wuy_pool_t *pool_connection;
static wuy_pool_t *pool_request;

static inline void display_char(const uint8_t *p, int len)
{
	printf("  |");

	int i;
	for (i = 0; i < len; i++) {
		if (p[i] > 0x7F) {
			printf("#");
		} else if (p[i] < 0x20 || p[i] == 0x7F) {
			printf(".");
		} else {
			printf("%c", p[i]);
		}
	}
	printf("|\n");
}
static inline void hexdump(const uint8_t *p, int len, const char *preface)
{
	if (preface != NULL) {
		printf("%s\n", preface);
	}

	int i;
	for (i = 0; i < len; i++) {
		if (i > 0 && (i % 16 == 0)) {
			display_char(p + i - 16, 16);
		}

		printf("%02x ", p[i]);
	}

	if (len % 16 != 0) {
		display_char(p + (i / 16 * 16), i % 16);
	}
}


int ssl_alpn_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
		const unsigned char *in, unsigned int inlen, void *arg)
{
#define ALPN_ADVERTISE       (unsigned char *)"\x02h2\x08http/1.1"
	int ret = SSL_select_next_proto((unsigned char **)out, outlen, ALPN_ADVERTISE, sizeof(ALPN_ADVERTISE)-1, in, inlen);
	if (ret != OPENSSL_NPN_NEGOTIATED) {
		printf("ssl alpn fail\n");
		return SSL_TLSEXT_ERR_NOACK;
	}
	printf("ssl alpn: %d\n", *outlen);
	return SSL_TLSEXT_ERR_OK;
}

void connection_close(example_connection_t *c)
{
	http2_connection_close(c->h2c);

	/* send GOAWAY */
	loop_stream_write(c->loop_stream, c->buf_start, c->buf_end - c->buf_start);
	c->buf_end = c->buf_start = c->buffer;

	loop_stream_close(c->loop_stream);
	wuy_pool_free(c);
}

#define BUFFER_SIZE (16*4096)
bool on_accept(loop_tcp_listen_t *tl, loop_stream_t *s, struct sockaddr *addr)
{
	printf("accept\n");

	/* create example_connection_t */
	example_connection_t *c = wuy_pool_alloc(pool_connection);
	c->buffer = malloc(BUFFER_SIZE);
	c->buf_start = c->buf_end = c->buffer;
	printf("  = c %p %p\n", c, c->buffer);

	/* attach loop_stream with example_connection_t */
	loop_stream_set_app_data(s, c);
	c->loop_stream = s;

	/* create http2_connection_t and attach it with example_connection_t */
	static http2_settings_t settings = {
		.max_concurrent_streams = 100,
	};
	http2_connection_t *h2c = http2_connection_new(&settings);
	http2_connection_set_app_data(h2c, c);
	c->h2c = h2c;
	return true;
}
void exm_http2_hook_stream_new(http2_stream_t *s)
{
	/* create example_request_t */
	example_request_t *r = wuy_pool_alloc(pool_request);

	bzero(r, sizeof(example_request_t));
	r->c = http2_connection_get_app_data(http2_stream_get_connection(s));
	r->http2_stream = s;
	printf("  = r %p %p\n", r->c, r->c->buffer);

	http2_stream_set_app_data(s, r);
}
void exm_http2_hook_stream_header(http2_stream_t *s, const char *name_str,
		int name_len, const char *value_str, int value_len)
{
	/* read request header :path only */
	if (name_len == 5 && memcmp(name_str, ":path", 5) == 0) {
		example_request_t *r = http2_stream_get_app_data(s);
		r->path = malloc(value_len + 1);
		memcpy(r->path, value_str, value_len);
		r->path[value_len] = '\0';
	}
}
void exm_http2_hook_stream_body(http2_stream_t *s, const uint8_t *buf, int len)
{
	/* ignore request body */
}
void exm_http2_hook_stream_end(http2_stream_t *s)
{
	/* request done, open local file with :path */
	example_request_t *r = http2_stream_get_app_data(s);
	if (r->path == NULL) {
		printf("no path\n");
		return;
	}

	char path[1024];
	strcpy(path, ".");
	strcpy(path + strlen(path), r->path);
	r->fp = fopen(path, "r");
	printf("open file: %s\n", path);

	if (r->fp != NULL) {
		struct stat st_buf;
		stat(path, &st_buf);
		r->content_length = st_buf.st_size;
	} else {
		r->content_length = 0;
	}
}
void exm_http2_hook_control_frame(http2_connection_t *h2c, const uint8_t *buf, int len)
{
	example_connection_t *c = http2_connection_get_app_data(h2c);
	memcpy(c->buf_end, buf, len);
	c->buf_end += len;
}


void request_close(example_request_t *r)
{
	http2_stream_close(r->http2_stream);
	if (r->fp != NULL) {
		fclose(r->fp);
	}
	if (r->path != NULL) {
		free(r->path);
	}
	wuy_pool_free(r);
}

void response_headers(example_request_t *r, int status_code)
{
	printf("response header %d\n", status_code);

	uint8_t *buf_pos = r->c->buf_end;
	uint8_t *buf_end = r->c->buffer + BUFFER_SIZE;

	uint8_t *frame = buf_pos;

	buf_pos += HTTP2_FRAME_HEADER_SIZE;
	uint8_t *payload = buf_pos;

	int proc_len = http2_make_status_code(buf_pos, buf_end - buf_pos, status_code);
	buf_pos += proc_len;

	proc_len = http2_make_content_length(buf_pos, buf_end - buf_pos, r->content_length);
	buf_pos += proc_len;

	http2_make_frame_headers(r->http2_stream, frame, buf_pos - payload, r->content_length==0, true);

	r->response_headers = true;
	r->c->buf_end = buf_pos;
}

void response(example_request_t *r)
{
	if (r->fp == NULL) {
		response_headers(r, 404);
		request_close(r);
		return;
	}

	if (!r->response_headers) {
		response_headers(r, 200);
	}

	uint8_t *buf_pos = r->c->buf_end;
	uint8_t *buf_end = r->c->buffer + BUFFER_SIZE;

	uint8_t *frame = buf_pos;
	buf_pos += HTTP2_FRAME_HEADER_SIZE;

	ssize_t read_len = fread(buf_pos, 1, buf_end - buf_pos, r->fp);
	r->response_length += read_len;
	buf_pos += read_len;
	r->c->buf_end = buf_pos;

	bool is_done = r->response_length == r->content_length;

	http2_make_frame_body(r->http2_stream, frame, read_len, is_done);

	printf("response body : %ld %d\n", read_len, is_done);

	if (is_done) {
		request_close(r);
	}
}

ssize_t on_read(loop_stream_t *s, void *data, size_t len)
{
	example_connection_t *c = loop_stream_get_app_data(s);

	int proc_len = http2_process_input(c->h2c, data, len);
	if (proc_len < 0) {
		connection_close(c);
		return -1;
	}

	http2_stream_t *h2s;
	while ((h2s = http2_schedular(c->h2c)) != NULL) {
		response(http2_stream_get_app_data(h2s));
	}

	if (c->buf_end > c->buf_start) {
		printf("send: %ld %p %p\n", c->buf_end - c->buf_start, c->buffer, c->buf_start);
                // hexdump(c->buf_start, c->buf_end - c->buf_start, "data");
		loop_stream_write(s, c->buf_start, c->buf_end - c->buf_start);
		c->buf_end = c->buf_start = c->buffer;
	}

	return proc_len;
}

void on_close(loop_stream_t *s, const char *reason, int err)
{
	printf(" -- close: %s %d %s\n", reason, err, ERR_error_string(ERR_get_error(), NULL));

	connection_close(loop_stream_get_app_data(s));
}

void exm_http2_hook_log(http2_connection_t *h2c, const char *fmt, ...)
{
	char buffer[1000];
	va_list ap;
	va_start(ap, fmt);
	vsprintf(buffer, fmt, ap);
	va_end(ap);

	struct timeval now;
	gettimeofday(&now, NULL);

	printf("%ld.%06ld [HTTP2] %s\n", now.tv_sec, now.tv_usec, buffer);
}

int main()
{
	/* library init */
	http2_library_init(exm_http2_hook_stream_new, exm_http2_hook_stream_header,
			exm_http2_hook_stream_body, exm_http2_hook_stream_end, NULL,
			exm_http2_hook_control_frame, exm_http2_hook_log);

	SSL_load_error_strings();	
	OpenSSL_add_ssl_algorithms();

	signal(SIGPIPE, SIG_IGN); /* for network */

	/* example init */
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);
	SSL_CTX_set_alpn_select_cb(ctx, ssl_alpn_callback, NULL);

	pool_connection = wuy_pool_new_type(example_connection_t);
	pool_request = wuy_pool_new_type(example_request_t);

	/* run loop */
	loop_tcp_listen_ops_t listen_ops = { .on_accept = on_accept };
	loop_stream_ops_t stream_ops = { .on_read = on_read, .on_close = on_close, .ssl_ctx = ctx };
	loop_t *loop = loop_new();
	loop_tcp_listen(loop, "1234", &listen_ops, &stream_ops);
	loop_run(loop);
	return 0;
}
