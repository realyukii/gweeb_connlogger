#include <arpa/inet.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif
#define VERBOSE 3
#define DEBUG 2
#define DEFAULT_REQ_QUEUE_SZ 16
#define DEFAULT_POOL_SZ 100
#define DEFAULT_RAW_CAP 1024
#define MAX_HTTP_METHOD_LEN 8
#define MAX_HTTP_VER_LEN 8
#define MAX_HOST_LEN 512
#define MAX_INSANE_URI_LENGTH 300000

#define pr_debug(lvl, fmt, ...)				\
do {							\
	if (DEBUG_LEVEL >= (lvl)) {			\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	}						\
} while (0)

struct http_req_queue {
	size_t head;
	size_t tail;
	size_t capacity;
	size_t occupied;
	struct http_req *req;
};

typedef enum {
	HTTP_REQ_LINE = 0,
	HTTP_REQ_HDR,
	HTTP_REQ_BODY,
	HTTP_RES_LINE = 0,
	HTTP_RES_HDR,
	HTTP_RES_BODY
} parser_state;

struct http_hdr {
	char *key;
	char *value;
	char *line;
	char *next_line;
};

struct http_req {
	char method[MAX_HTTP_METHOD_LEN];
	char host[MAX_HOST_LEN];
	char response_code[4];
	char *begin_req;
	char *begin_res;
	char *end_of_hdr_req;
	char *end_of_hdr_res;
	char *uri;
};

struct concated_buf {
	char *raw_bytes;
	size_t len;
	size_t cap;
};

/* TODO:
* is there any problem if we use same buffer for raw request and response?
* it seems the scenario so far never call recv and send at once at the same time
* so maybe we can just overwrite the old one by using same buffer address for recv and send?
* because each sockfd use different buffer address, maybe it's safe? I dunno...
*/
typedef struct concated_buf http_req_raw;
typedef struct concated_buf http_res_raw;

struct http_ctx {
	int sockfd;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port_addr;
	struct http_req_queue req_queue;
	http_req_raw raw_req;
	http_res_raw raw_res;
	parser_state state;
	size_t content_length;
	bool is_chunked;
};

static size_t current_pool_sz = DEFAULT_POOL_SZ;
static size_t occupied_pool = 0;
static struct http_ctx *ctx_pool = NULL;
static FILE *file_log = NULL;

static void init_queue(struct http_req_queue *q)
{
	q->capacity = DEFAULT_REQ_QUEUE_SZ;
	q->req = malloc(DEFAULT_REQ_QUEUE_SZ * sizeof(struct http_req));
}

static int queue_grow(struct http_req_queue *q, size_t new_cap)
{
	void *tmp = realloc(q->req, new_cap * sizeof(struct http_req));
	if (tmp == NULL)
	 	return -1;
	
	q->req = tmp;
	q->tail = q->capacity;
	q->capacity = new_cap;
	return 0;
}

static struct http_req *back(struct http_req_queue *q)
{
	return &q->req[q->tail];
}

static struct http_req *front(struct http_req_queue *q)
{
	/* make sure the queue is not empty */
	if (q->occupied == 0)
		return NULL;

	struct http_req *req = &q->req[q->head];

	return req;
}

static int enqueue(struct http_req_queue *q, struct http_req req)
{
	/* if the queue is full, re-size the default size twice */
	if (q->occupied == q->capacity) {
		size_t new_cap = q->capacity * 2;
		/* abort the enqueue operation if it fail to re-size */
		if (queue_grow(q, new_cap) < 0)
			return -1;
	}

	q->req[q->tail] = req;
	q->tail = (q->tail + 1) % q->capacity;
	q->occupied++;

	return 0;
}

static void dequeue(struct http_req_queue *q)
{
	/* make sure the queue is not empty */
	if (q->occupied == 0)
		return;

	memset(&q->req[q->head], 0, sizeof(struct http_req));
	q->head = (q->head + 1) % q->capacity;
	q->occupied--;
}

static void generate_current_time(char *buf)
{
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	/*
	* the manual says atleast 26 bytes of buf is provided
	* 24 ascii character + newline + null terminated bytes
	*/
	asctime_r(timeinfo, buf);
	buf[26 - 2] = '\0';
}

static void write_log(struct http_ctx *h, struct http_req *req)
{
	char human_readable_time[26] = {0};
	generate_current_time(human_readable_time);

	int ret = fprintf(
		file_log,
		"[%s]|%s:%d|Host: %s|Method: %s|URI %s|Status: %s\n",
		human_readable_time,
		h->ip_addr, h->port_addr,
		req->host, req->method, req->uri, req->response_code
	);
	pr_debug(VERBOSE, "URI will be freed: %p\n", req->uri);
	free(req->uri);

	if (ret < 0) {
		pr_debug(DEBUG, "failed to write parsed data to the file\n");
	} else {
		pr_debug(DEBUG, "parsed data successfully written to the file\n");
	}
}

static int init(void)
{
	/* already initialised, skip duplicate init, exit. */
	if (file_log != NULL && ctx_pool != NULL)
		return 0;

	const char *log_file = getenv("GWLOG_PATH");

	/* do not init if there's no destination for parsed data to write */
	if (log_file == NULL)
		return -1;

	file_log = fopen(log_file, "a");
	if (file_log == NULL)
		return -1;

	setvbuf(file_log, NULL, _IOLBF, 0);
	ctx_pool = calloc(DEFAULT_POOL_SZ, sizeof(struct http_ctx));
	if (ctx_pool == NULL)
		return -1;

	pr_debug(
		DEBUG,
		"init the pool context and file handle for the first time\n"
	);
	pr_debug(VERBOSE, "allocated address of context pool: %p\n", ctx_pool);
	return 0;
}

static void advance(struct concated_buf *ptr, size_t len)
{
	if (len > ptr->len)
		ptr->len = 0;
	else
		ptr->len -= len;

	if (ptr->len > 0)
		memmove(ptr->raw_bytes, ptr->raw_bytes + len, ptr->len);
}

static void push_sockfd(int sockfd)
{
	struct http_ctx **_c = &ctx_pool;
	struct http_ctx *c = *_c;
	if (occupied_pool == current_pool_sz) {
		void *tmp = realloc(c, current_pool_sz * 2);
		if (tmp == NULL)
			return;
		
		*_c = tmp;
		pr_debug(
			VERBOSE,
			"new address is allocated for context pool: %p\n",
			ctx_pool
		);
	}

	for (size_t i = 0; i < current_pool_sz; i++) {
		if (c[i].sockfd != 0)
			continue;

		c[i].raw_req.raw_bytes = calloc(1, DEFAULT_RAW_CAP);
		c[i].raw_res.raw_bytes = calloc(1, DEFAULT_RAW_CAP);
		/*
		* do not push current connection to the pool
		* if we fail to allocate some memory
		*/
		if (c[i].raw_req.raw_bytes == NULL || c[i].raw_res.raw_bytes == NULL) {
			void *to_free = (c[i].raw_req.raw_bytes != NULL)
				? c[i].raw_req.raw_bytes
				: c[i].raw_res.raw_bytes;

			/* if both null, it is still safe to call free */
			free(to_free);
			break;
		}

		init_queue(&c[i].req_queue);
		if (c[i].req_queue.req == NULL)
			break;
		pr_debug(
			VERBOSE,
			"init queue for sockfd %d\n",
			sockfd
		);

		pr_debug(
			DEBUG,
			"new sockfd %d is registered to the pool\n",
			sockfd
		);
		c[i].sockfd = sockfd;
		c[i].raw_req.cap = DEFAULT_RAW_CAP;
		c[i].raw_res.cap = DEFAULT_RAW_CAP;

		occupied_pool++;
		break;
	}
}

static void unwatch_sockfd(struct http_ctx *h, char *reason)
{
	pr_debug(
		DEBUG,
		"sockfd %d is unregistered from the pool: %s\n",
		h->sockfd, reason
	);
	h->sockfd = 0;

	h->raw_req.cap = 0;
	h->raw_req.len = 0;
	pr_debug(
		VERBOSE,
		"raw_req.raw_bytes will be freed: %p\n",
		h->raw_res.raw_bytes
	);
	free(h->raw_req.raw_bytes);

	h->raw_res.cap = 0;
	h->raw_res.len = 0;
	pr_debug(
		VERBOSE,
		"raw_res.raw_bytes will be freed: %p\n",
		h->raw_res.raw_bytes
	);
	free(h->raw_res.raw_bytes);
	free(h->req_queue.req);
	memset(&h->req_queue, 0, sizeof(struct http_req_queue));

	occupied_pool--;
}

static char *find_method(const char *buf)
{
	const char *http_methods[] = {
		"GET", "POST", "HEAD", "PATCH", "PUT",
		"DELETE", "OPTIONS", "CONNECT", "TRACE", NULL
	};
	const char **ptr = http_methods;
	char *method_ptr = NULL;
	while (*ptr) {
		method_ptr = strstr(buf, *ptr);
		if (method_ptr != NULL)
			break;
		ptr++;
	}

	return method_ptr;
}

static int concat_buf(const void *src, struct concated_buf *buf, size_t len)
{
	size_t *append_pos = &buf->len;
	size_t incoming_len = *append_pos + len;
	char **b = &buf->raw_bytes;

	if (incoming_len <= buf->cap) {
		memcpy(*b + *append_pos, src, len);
		*append_pos += len;
	} else {
		/* we don't have enough space in the memory, let's resize it */
		void *tmp = realloc(*b, buf->cap + incoming_len);
		if (tmp == NULL) {
			return -1;
		}
		*b = tmp;
		memcpy(*b + *append_pos, src, len);
		*append_pos += len;
		buf->cap += incoming_len;
		pr_debug(
			VERBOSE,
			"new address is allocated for concated buffer: %p\n",
			buf->raw_bytes
		);
	}

	return 0;
}

static void strtolower(char *str)
{
	for (char *p = str; *p; p++)
		*p = tolower(*p);
}

static int parse_hdr(struct http_hdr *header)
{
	/* iterate over the http header */
	header->next_line = strstr(header->line, "\r\n");
	if (header->next_line == NULL)
		return -1;

	*header->next_line = '\0';
	header->next_line += 2;

	header->key = header->line;
	header->value = strchr(header->line, ':');
	if (header->value == NULL)
		return -1;
	*header->value = '\0';
	header->value += 1;

	/* ignore any leading space */
	while (*header->value == ' ')
		header->value++;

	/* ignore any trailing space */
	char *trailing = header->next_line - 3;
	while (*trailing == ' ')
		trailing--;

	strtolower(header->key);
	header->line = header->next_line;

	return 0;
}

static int parse_res_line(struct http_hdr *hdr, http_res_raw *r, struct http_req *req)
{
	char *space = strchr(r->raw_bytes, ' ');
	if (space == NULL && r->len >= MAX_HTTP_VER_LEN + 1)
		space = strchr(r->raw_bytes, '\0');

	/*
	* try to wait for more buffer, but if we still didn't find
	* the space after a certain length, we decide to drop
	* the connection from the pool
	*/
	if (r->len < MAX_HTTP_VER_LEN + 1)
		return -EAGAIN;
	if (space == NULL)
		return -EINVAL;
	*space = '\0';

	char *status_code = space + 1;

	/* make sure it's a HTTP response */
	req->begin_res = strstr(r->raw_bytes, "HTTP/1.");
	if (req->begin_res == NULL)
		return -EINVAL;

	if (r->len < MAX_HTTP_VER_LEN + 4)
		return -EAGAIN;

	strncpy(req->response_code, status_code, 3);

	/* some bytes haven't arrived yet, wait until it completed */
	req->end_of_hdr_res = strstr(status_code, "\r\n\r\n");
	if (req->end_of_hdr_res == NULL)
		return -EAGAIN;
	req->end_of_hdr_res += 4;

	/* TODO:
	* even though the above already test the http version/http method and
	* crlf crlf, but malformed HTTP request and response is still possible
	* in between the string, figure out how to handle it
	*/
	char *end_resline = strstr(status_code, "\r\n");
	char *res_header = end_resline + 2;
	hdr->line = res_header;

	return 0;
}

static int process_res_hdr(struct http_ctx *h, struct http_hdr *hdr, struct http_req *req)
{
	if (hdr->line + 2 == req->end_of_hdr_res) {
		advance(&h->raw_res, req->end_of_hdr_res - req->begin_res);
		if (h->is_chunked || h->content_length > 0)
			h->state = HTTP_RES_BODY;
		else
			h->state = HTTP_RES_LINE;

		write_log(h, req);
		pr_debug(VERBOSE, "dequeue request...\n");
		dequeue(&h->req_queue);
		return 0;
	}

	/* assume it's malformed HTTP header if we can't parse it */
	if (parse_hdr(hdr) < 0) {
		return -EINVAL;
	}

	pr_debug(
		VERBOSE,
		"parsing response header: %s: %s\n",
		hdr->key, hdr->value
	);

	if (strcmp(hdr->key, "content-length") == 0) {
		/*
		* if it have content-length but also chunked,
		* it's malformed HTTP response
		*/
		if (h->is_chunked)
			return -EINVAL;
		h->content_length = atoll(hdr->value);
	} else if (strcmp(hdr->key, "transfer-encoding") == 0) {
		/*
		* if it's chunked and have content-length,
		* it's malformed HTTP response
		*/
		if (h->content_length > 0)
			return -EINVAL;
		if (strstr(hdr->value, "chunked") != NULL)
			h->is_chunked = true;
	}

	return -EAGAIN;
}

static int parse_req_line(struct http_hdr *hdr, http_req_raw *r, struct http_req *req)
{
	char *space = strchr(r->raw_bytes, ' ');
	if (space == NULL && r->len >= MAX_HTTP_METHOD_LEN)
		space = strchr(r->raw_bytes, '\0');

	/*
	* try to wait for more buffer, but if we still didn't find
	* the space after a certain length, we decide to drop
	* the connection from the pool
	*/
	if (r->len < MAX_HTTP_METHOD_LEN)
		return -EAGAIN;
	if (space == NULL)
		return -EINVAL;
	*space = '\0';

	/* make sure it's a HTTP request */
	req->begin_req = find_method(r->raw_bytes);
	if (req->begin_req == NULL)
		return -EINVAL;

	strcpy(req->method, req->begin_req);

	char *uri = NULL;
	uri = space + 1;
	if (r->len < MAX_HTTP_METHOD_LEN + 2)
		return -EAGAIN;

	if (uri == NULL)
		return -EINVAL;

	/* malformed URI if it doesn't start with slash character */
	if (*uri != '/') {
		return -EINVAL;
	}

	if (req->end_of_hdr_req == NULL) {
		/* some bytes haven't departed yet, wait until it completed */
		req->end_of_hdr_req = strstr(uri, "\r\n\r\n");
		if (req->end_of_hdr_req == NULL)
			return -EAGAIN;
		req->end_of_hdr_req += 4;
	}

	char *end_uri = strstr(space + 1, " HTTP/1.");
	if (end_uri == NULL) {
		return -EINVAL;
	}
	*end_uri = '\0';
	end_uri += 1;

	size_t uri_len = end_uri - uri;
	if (uri_len > MAX_INSANE_URI_LENGTH) {
		return -EINVAL;
	}

	req->uri = malloc(uri_len);
	/*
	* abort the subsequent operation when we fail to allocate
	* dynamic memory for uri
	*/
	if (req->uri == NULL) {
		return -EINVAL;
	}
	memcpy(req->uri, uri, uri_len);

	char *end_reqline = strstr(end_uri, "\r\n");
	char *req_header = end_reqline + 2;
	hdr->line = req_header;

	return 0;
}

static int process_req_hdr(struct http_ctx *h, struct http_hdr *hdr, struct http_req *req)
{
	if (hdr->line + 2 == req->end_of_hdr_req) {
		pr_debug(VERBOSE, "push processed data to the queue\n");
		if (enqueue(&h->req_queue, *req) < 0)
			pr_debug(VERBOSE, "warning: failed to push data to queue\n");
		advance(&h->raw_req, req->end_of_hdr_req - req->begin_req);
		if (h->is_chunked || h->content_length > 0)
			h->state = HTTP_REQ_BODY;
		else
			h->state = HTTP_REQ_LINE;
		req->begin_req = NULL;
		req->end_of_hdr_req = NULL;
		return 0;
	}

	/* assume it's malformed HTTP header if we can't parse it */
	if (parse_hdr(hdr) < 0) {
		return -EINVAL;
	}

	pr_debug(
		VERBOSE,
		"parsing request header: %s: %s\n",
		hdr->key, hdr->value
	);

	if (strcmp(hdr->key, "host") == 0) {
		strcpy(req->host, hdr->value);
	} else if (strcmp(hdr->key, "content-length") == 0) {
		/*
		* if it have content-length but also chunked,
		* it's malformed HTTP request
		*/
		if (h->is_chunked)
			return -EINVAL;
		h->content_length = atoll(hdr->value);
	} else if (strcmp(hdr->key, "transfer-encoding") == 0) {
		/*
		* if it's chunked and have content-length,
		* it's malformed HTTP request
		*/
		if (h->content_length > 0)
			return -EINVAL;
		if (strstr(hdr->value, "chunked") != NULL) {
			h->is_chunked = true;
		}
	}

	return -EAGAIN;
}

static int process_body(struct http_ctx *h, struct concated_buf *r, parser_state s)
{
	if (h->is_chunked) {
		char *separator = strstr(r->raw_bytes, "\r\n");
		/*
		* some bytes haven't departed/arrived yet, short-send?
		* wait until it completed
		* or maybe it's a malformed http request
		*/
		if (separator == NULL)
			return -EINVAL;
		*separator = '\0';
		int ascii_hex_len = strlen(r->raw_bytes);
		size_t chunk_sz = strtoull(r->raw_bytes, NULL, 16);
		
		if (chunk_sz == 0) {
			advance(r, ascii_hex_len + 2 + chunk_sz + 2);
			h->state = s;
			h->is_chunked = false;
			return 0;
		}

		/* some bytes haven't departed/arrived yet. */
		if (r->len - (ascii_hex_len + 4) < chunk_sz)
			return -EINVAL;

		/*
		* shift the buffer and check for the next chunk
		* in the newly shifted buffer if any.
		*/
		advance(r, ascii_hex_len + 2 + chunk_sz + 2);
		return -EAGAIN;
	} else {
		/* some bytes haven't departed/arrived yet */
		if (r->len < h->content_length)
			return -EINVAL;
		advance(r, h->content_length);

		/*
		* completed body.
		* after fully receive body content,
		* try to lookup for another header if any.
		* 
		* handle scenario like HTTP pipeline or
		* keep-alive that re-using existing socket
		* to send multiple HTTP request
		*/
		h->state = s;
		h->content_length = 0;
		return 0;
	}
}

static void handle_parse_localbuf(struct http_ctx *h, const void *buf, int buf_len)
{
	int ret;
	http_req_raw *r = &h->raw_req;
	struct http_req *req = NULL;
	struct http_hdr hdr = {0};

	if (concat_buf(buf, r, buf_len) < 0) {
		unwatch_sockfd(h, "after concat req buf");
		return;
	}

next:
	req = back(&h->req_queue);
	if (h->state == HTTP_REQ_LINE) {
		ret = parse_req_line(&hdr, r, req);
		if (ret == -EINVAL) {
			unwatch_sockfd(h, "after parse_req_line");
			return;
		} else if (ret == -EAGAIN)
			return;
		h->state = HTTP_REQ_HDR;
	}

	pr_debug(DEBUG, "parsing HTTP request on sockfd %d\n", h->sockfd);
	pr_debug(
		DEBUG,
		"buffer address: %p\nlength: %ld\ncapacity: %ld\nstate: %d\n",
		r->raw_bytes, r->len, r->cap, h->state
	);

	while (true) {
		switch (h->state) {
		case HTTP_REQ_HDR:
			ret = process_req_hdr(h, &hdr, req);
			if (ret == -EINVAL) {
				unwatch_sockfd(h, "after process_req_hdr");
				return;
			} else if (ret == -EAGAIN)
				continue;
			goto exit_loop;
		case HTTP_REQ_BODY:
			pr_debug(VERBOSE, "parsing request body\n");
			ret = process_body(h, r, HTTP_REQ_LINE);
			if (ret == -EINVAL)
				return;
			else if (ret == -EAGAIN)
				continue;
			goto exit_loop;
		default:
			return;
		}
	}

exit_loop:
	if (r->len > 0)
		goto next;

	/* move to the next state, receiving server respond */
	h->state = HTTP_RES_LINE;
}

static struct http_ctx *find_http_ctx(int sockfd)
{
	/*
	* do not perform lookup if the fd is stdin or stdout
	* prevent false-positive when dealing with program like nc
	* save some cpu cycle by stop executing subsequent instruction
	* and early exit
	*/
	if (sockfd == STDIN_FILENO || sockfd == STDOUT_FILENO)
		return NULL;

	/*
	* we are not allowed to assume ctx_pool to always be valid
	* one of the concrete example is when find_http_ctx is called
	* from close() and the init is not called yet
	*/
	if (ctx_pool == NULL)
		return NULL;

	struct http_ctx *h = NULL;
	for (size_t i = 0; i < current_pool_sz; i++)
	{
		if (ctx_pool[i].sockfd != sockfd)
			continue;

		h = &ctx_pool[i];
		break;
	}
	
	return h;
}

static void handle_parse_remotebuf(struct http_ctx *h, const void *buf, int buf_len)
{
	int ret;
	struct http_req *req = front(&h->req_queue);
	struct http_hdr hdr = {0};

	if (req == NULL) {
		pr_debug(VERBOSE, "failed to get request, queue is empty.\n");
		unwatch_sockfd(h, "after front()");
		return;
	}

	if (buf_len == 0) {
		/*
		* built-in php web server
		* the server send an EOF, we can assume the connection
		* will be closed and data will no longer be sent, stop parsing.
		*/
		return;
	}

	if (concat_buf(buf, &h->raw_res, buf_len) < 0) {
		unwatch_sockfd(h, "after concat res buf");
		return;
	}

next:
	if (h->state == HTTP_RES_LINE) {
		ret = parse_res_line(&hdr, &h->raw_res, req);
		if (ret == -EINVAL) {
			unwatch_sockfd(h, "after parse_res_line");
			return;
		} else if (ret == -EAGAIN)
			return;

		h->state = HTTP_RES_HDR;
	}

	pr_debug(DEBUG, "parsing HTTP response on sockfd %d\n", h->sockfd);
	pr_debug(
		DEBUG,
		"buffer address: %p\nlength: %ld\ncapacity: %ld\nstate: %d\n",
		h->raw_res.raw_bytes, h->raw_res.len, h->raw_res.cap, h->state
	);

	while (true) {
		switch (h->state) {
		case HTTP_RES_HDR:
			ret = process_res_hdr(h, &hdr, req);
			if (ret == -EINVAL) {
				unwatch_sockfd(h, "after process_res_hdr");
				return;
			} else if (ret == -EAGAIN)
				continue;
			goto exit_loop;
		case HTTP_RES_BODY:
			pr_debug(VERBOSE, "parsing response body\n");
			ret = process_body(h, &h->raw_res, HTTP_RES_LINE);
			if (ret == -EINVAL)
				return;
			else if (ret == -EAGAIN)
				continue;
			goto exit_loop;
		default:
			return;
		}
	}

exit_loop:
	if (h->req_queue.occupied > 0 && h->raw_res.len > 0)
		goto next;
}

static void fill_address(struct http_ctx *h, const struct sockaddr *addr)
{
	struct sockaddr_in *in = (void *)addr;
	struct sockaddr_in6 *in6 = (void *)addr;

	switch (addr->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &in->sin_addr, h->ip_addr, INET_ADDRSTRLEN);
		h->port_addr = ntohs(in->sin_port);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &in6->sin6_addr, h->ip_addr, INET6_ADDRSTRLEN);
		h->port_addr = ntohs(in6->sin6_port);
		break;
	}

	pr_debug(
		DEBUG,
		"sockfd %d with domain %d is connected to %s:%d\n",
		h->sockfd,
		(int)addr->sa_family,
		h->ip_addr,
		h->port_addr
	);
}

int socket(int domain, int type, int protocol)
{
	int ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket),	/* %rax */
		  "D" (domain),		/* %rdi */
		  "S" (type),		/* %rsi */
		  "d" (protocol)	/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	if (domain != AF_INET && domain != AF_INET6)
		return ret;

	if (!(type & SOCK_STREAM))
		return ret;

	if (ctx_pool == NULL && init() == 0)
		push_sockfd(ret);
	else
		pr_debug(
			VERBOSE,
			"failed to push sockfd %d with domain %d\n",
			ret, domain
		);

	return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_connect),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (addr),		/* %rsi */
		  "d" (addrlen)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	if (ctx_pool == NULL)
		return ret;

	struct http_ctx *h = find_http_ctx(sockfd);
	if (h == NULL)
		return ret;

	fill_address(h, addr);

	return ret;
}

ssize_t recvfrom(
	int sockfd, void *buf, size_t size, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
{
	register int _f asm("r10") = flags;
	register struct sockaddr *_s asm("r8") = src_addr;
	register socklen_t *_a asm("r9") = addrlen;
	ssize_t ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (1),		/* %rdx */
		  "r" (_f),		/* %r10 */
		  "r" (_s),		/* %r8 */
		  "r" (_a)		/* %r9 */
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	struct http_ctx *h = find_http_ctx(sockfd);
	if (h == NULL)
		return ret;

	handle_parse_remotebuf(h, buf, ret);

	return ret;
}

ssize_t sendto(
	int sockfd, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t addrlen)
{
	register int _f asm("r10") = flags;
	register const struct sockaddr *_d asm("r8") = dst_addr;
	register socklen_t _a asm("r9") = addrlen;
	ssize_t ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (1),		/* %rdx */
		  "r" (_f),		/* %r10 */
		  "r" (_d),		/* %r8 */
		  "r" (_a)		/* %r9 */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	struct http_ctx *h = find_http_ctx(sockfd);
	if (h == NULL)
		return ret;
	
	handle_parse_localbuf(h, buf, ret);

	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t size, int flags)
{
	return recvfrom(sockfd, buf, size, flags, NULL, NULL);
}

ssize_t send(int sockfd, const void *buf, size_t size, int flags)
{
	return sendto(sockfd, buf, size, flags, NULL, 0);
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_read),	/* %rax */
		  "D" (fd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (count)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}
	
	struct http_ctx *h = find_http_ctx(fd);
	if (h == NULL)
		return ret;

	handle_parse_remotebuf(h, buf, ret);

	return ret;
}

/* TODO: fix broken pipe error
* bash -c 'for i in {1..800}; do
  rand=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
  printf "POST /%s HTTP/1.1\r\nHost: test.local\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n" "$rand"
done' > /tmp/req_many.txt
* throw an error: tr: write error: Broken pipe
* this only occurs when this shared library is set on LD_PRELOAD
*/
ssize_t write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_write),	/* %rax */
		  "D" (fd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (count)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	struct http_ctx *h = find_http_ctx(fd);
	if (h == NULL)
		return ret;

	handle_parse_localbuf(h, buf, ret);

	return ret;
}

int close(int fd)
{
	int ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_close),	/* %rax */
		  "D" (fd)		/* %rdi */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	struct http_ctx *h = find_http_ctx(fd);
	if (h != NULL)
		unwatch_sockfd(h, "after closing the sockfd");

	return ret;
}
