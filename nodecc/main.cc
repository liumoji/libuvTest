#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "use-libuv.h"
#include "./../http-parser/http_parser.h"

struct header
{
	char field[1024];
	char value[1024];
};
typedef enum { NONE = 0, FIELD, VALUE } head_type;
struct message
{
	int header_num;
	char url[1024];
	header headers[15];
	head_type last_header_element;
};

int on_message_begin(http_parser* parser);
int on_headers_complete(http_parser* parser);
int on_message_complete(http_parser* parser);
int on_url(http_parser* parser, const char* at, size_t length);
int on_status(http_parser* parser, const char* at, size_t length);
int on_header_field(http_parser* parser, const char* at, size_t length);
int on_header_value(http_parser* parser, const char* at, size_t length);
int on_body(http_parser* parser, const char* at, size_t length);
int on_chunk_header(http_parser* parser);
int on_chunk_complete(http_parser* parser);

/* strnlen() is a POSIX.2008 addition. Can't rely on it being available so
* define it ourselves.
*/
size_t
strnlen(const char *s, size_t maxlen)
{
	const char *p;

	p = (const char *)memchr(s, '\0', maxlen);
	if (p == NULL)
		return maxlen;

	return p - s;
}

size_t
strlncat(char *dst, size_t len, const char *src, size_t n)
{
	size_t slen;
	size_t dlen;
	size_t rlen;
	size_t ncpy;

	slen = strnlen(src, n);
	dlen = strnlen(dst, len);

	if (dlen < len) {
		rlen = len - dlen;
		ncpy = slen < rlen ? slen : (rlen - 1);
		memcpy(dst + dlen, src, ncpy);
		dst[dlen + ncpy] = '\0';
	}
	return slen + dlen;
}

size_t
strlcat(char *dst, const char *src, size_t len)
{
	return strlncat(dst, len, src, (size_t)-1);
}

size_t
strlncpy(char *dst, size_t len, const char *src, size_t n)
{
	size_t slen;
	size_t ncpy;

	slen = strnlen(src, n);

	if (len > 0) {
		ncpy = slen < len ? slen : (len - 1);
		memcpy(dst, src, ncpy);
		dst[ncpy] = '\0';
	}

	return slen;
}

size_t
strlcpy(char *dst, const char *src, size_t len)
{
	return strlncpy(dst, len, src, (size_t)-1);
}

#define CHECK(r, msg) \
if (r) { \
fprintf(stderr, "%s: %s\n", msg, uv_strerror(r)); \
exit(1); \
}

#if 0

#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_strerror(err))
#define LOG(msg) puts(msg);
#define LOGF(fmt, ...) printf(fmt, ##__VA_ARGS__);
#define LOG_ERROR(msg) puts(msg);

#else

#define UVERR(err, msg) 
#define LOG(msg) 
#define LOGF(fmt, ...) 
#define LOG_ERROR(msg)

#endif


#define RESPONSE \
"HTTP/1.1 200 OK\r\n" \
"Content-Type: text/plain\r\n" \
"Content-Length: 12\r\n" \
"\r\n" \
"hello world\n"

static uv_loop_t* uv_loop;
static uv_tcp_t server;
static http_parser_settings parser_settings;

static uv_buf_t resbuf;

static uv_async_t async;//异步任务

typedef struct {
	uv_tcp_t handle;
	http_parser parser;
	uv_write_t write_req;
	int request_num;
	message msg;
} client_t;

void on_close(uv_handle_t* handle) {
	client_t* client = (client_t*)handle->data;

	LOGF("[ %5d ] connection closed\n", client->request_num);

	free(client);
	printf("on_close\n");
}

void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	//suggested_size = 10;
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
	LOGF("on_alloc %p\n", buf->base);
}

void on_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
	size_t parsed;

	client_t* client = (client_t*)tcp->data;

	if (nread >= 0) {
		parsed = http_parser_execute(
			&client->parser, &parser_settings, buf->base, nread);
		if (parsed < nread) {
			struct sockaddr_in addr;
			char ipv4addr[64];
			int namelen = sizeof(addr);
			uv_tcp_getpeername((const uv_tcp_t*)tcp, (struct sockaddr*)&addr, &namelen);
			uv_ip4_name(&addr, ipv4addr, 64);

			LOGF("parse error,peer addr %s\n", ipv4addr);
			printf("parse error,peer addr %s\n", ipv4addr);

			uv_close((uv_handle_t*)&client->handle, on_close);
		}
	}
	else {
		if (nread != UV_EOF)
			UVERR(nread, uv_err_name(nread));
		printf("on_read nread==0\n");
		uv_close((uv_handle_t*)client, on_close);
	}

	LOGF("free alloc %p\n", buf->base);
	free(buf->base);

	uv_async_send(&async);
}

static int request_num = 0;
static int request_pre = request_num;

void on_connect(uv_stream_t* server_handle, int status) {
	CHECK(status, "connect");

	int r;

	client_t* client = (client_t*)malloc(sizeof(client_t));
	client->request_num = request_num;
	client->msg.last_header_element = NONE;
	client->msg.header_num = 0;
	memset(&client->msg, 0, sizeof(client->msg));
	++request_num;
	//LOGF("[ %5d ] new connection\n", request_num++);

	uv_tcp_init(uv_loop, &client->handle);
	http_parser_init(&client->parser, HTTP_REQUEST);

	client->parser.data = client;
	client->handle.data = client;

	r = uv_accept(server_handle, (uv_stream_t*)&client->handle);
	CHECK(r, "accept");

	uv_read_start((uv_stream_t*)&client->handle, on_alloc, on_read);
}

void fake_job(uv_timer_t *handle)
{
	fprintf(stdout, "rate %d\n", request_num - request_pre);
	request_pre = request_num;
}

void after_write(uv_write_t* req, int status) {
	CHECK(status, "write");

	uv_close((uv_handle_t*)req->handle, on_close);
}

//异步处理过程
void on_async_cb(uv_async_t* handle)
{
	printf("on_async_cb\n");
}

int main() {
	int r;
	struct sockaddr_in addr;
	char listen_ip[] = "0.0.0.0";
	int port = 3000;

	parser_settings.on_message_begin = on_message_begin;
	parser_settings.on_url = on_url;
	parser_settings.on_status = on_status;
	parser_settings.on_header_field = on_header_field;
	parser_settings.on_header_value = on_header_value;
	parser_settings.on_headers_complete = on_headers_complete;
	parser_settings.on_body = on_body;
	parser_settings.on_message_complete = on_message_complete;
	parser_settings.on_chunk_header = on_chunk_header;
	parser_settings.on_chunk_complete = on_chunk_complete;

	resbuf.base = RESPONSE;
	resbuf.len = strlen(RESPONSE);

	uv_loop = uv_default_loop();

	r = uv_tcp_init(uv_loop, &server);
	CHECK(r, "bind");

	uv_ip4_addr(listen_ip, port, &addr);

	r = uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
	CHECK(r, "bind");
	uv_listen((uv_stream_t*)&server, 128, on_connect);

	printf("listening on %s:%d\n", listen_ip, port);

	//uv_timer_t fake_job_req;
	//uv_timer_init(uv_loop, &fake_job_req);
	//uv_timer_start(&fake_job_req, fake_job, 1000, 1000);
	uv_async_init(uv_loop, &async, on_async_cb);

	uv_run(uv_loop, UV_RUN_DEFAULT);
}


int on_message_begin(http_parser* parser) {
	//printf("\n***MESSAGE BEGIN***\n\n");
	return 0;
}

int on_headers_complete(http_parser* parser) {
	client_t* client = (client_t*)parser->data;

	LOGF("[ %5d ] http message parsed\n", client->request_num);

	return 0;
}

int on_message_complete(http_parser* parser) {
	//printf("\n***MESSAGE COMPLETE***\n\n");

	client_t* client = (client_t*)parser->data;
	uv_write(&client->write_req, (uv_stream_t*)&client->handle, &resbuf, 1, after_write);

	return 0;
}

int on_url(http_parser* parser, const char* at, size_t length) {
	client_t * client = (client_t*)parser->data;
	strlncat(client->msg.url,
		1024, at, length);
	printf("Url: %d,%s\n", (int)length, client->msg.url);

	return 0;
}

int on_status(http_parser* parser, const char* at, size_t length) {
	client_t * client = (client_t*)parser->data;
	strlncat(client->msg.url,
		1024, at, length);
	//printf("status: %d,%s\n", (int)length, client->msg.url);

	return 0;
}


int on_header_field(http_parser* parser, const char* at, size_t length) {
	//printf("Header field: %d,%p\n", (int)length, at);
	client_t * client = (client_t*)parser->data;
	if (client->msg.last_header_element != FIELD)
	{
		++client->msg.header_num;
	}

	strlncat(client->msg.headers[client->msg.header_num - 1].field,
		1024, at, length);
	client->msg.last_header_element = FIELD;
	return 0;
}

int on_header_value(http_parser* parser, const char* at, size_t length) {
	//printf("Header value: %d,%p\n", (int)length, at);
	client_t * client = (client_t*)parser->data;
	strlncat(client->msg.headers[client->msg.header_num - 1].value,
		1024, at, length);
	client->msg.last_header_element = VALUE;
	return 0;
}

int on_body(http_parser* parser, const char* at, size_t length) {
	//printf("Body: %d,%p\n", (int)length, at);
	return 0;
}

int on_chunk_header(http_parser* parser) {
	//printf("\n***chunk_header***\n\n");
	return 0;
}

int on_chunk_complete(http_parser* parser) {
	//printf("\n***chunk_complete***\n\n");
	return 0;
}