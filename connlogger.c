#include <arpa/inet.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
	char *uri;
};

struct concated_buf {
	char *raw_bytes;
	size_t len;
	size_t cap;
};

typedef struct concated_buf http_req_raw;
typedef struct concated_buf http_res_raw;

struct http_ctx {
	int sockfd;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port_addr;
	struct http_req_queue req_queue;
	http_req_raw raw_req;
	http_res_raw raw_res;
};

static size_t current_pool_sz = DEFAULT_POOL_SZ;
static size_t occupied_pool = 0;
static struct http_ctx *ctx_pool = NULL;
static FILE *file_log = NULL;

static void init_queue(struct http_req_queue *q)
{
	q->capacity = DEFAULT_REQ_QUEUE_SZ;
	/* TODO:
	* handle malloc failure.
	* what to do when we fail to init queue?
	* unregister the sockfd from the pool?
	*/
	q->req = malloc(DEFAULT_REQ_QUEUE_SZ * sizeof(struct http_req));
}

static int queue_grow(struct http_req_queue *q, size_t new_cap)
{
	void *tmp = realloc(q->req, new_cap);
	if (tmp == NULL)
	 	return -1;
	
	q->req = tmp;
	q->capacity = new_cap;
	return 0;
}

static struct http_req *front(struct http_req_queue *q)
{
	/* make sure the queue is not empty */
	if (q->occupied == 0)
		return NULL;

	struct http_req *req = &q->req[q->head];
	q->head = (q->head + 1) % q->capacity;
	q->occupied--;

	return req;
}

/* TODO:
* figure out how to handle a scenario where for some reason enqueue failed
* this failure can affect the pairing mechanism between
* HTTP request and response
*/
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

static void push_sockfd(int sockfd)
{
	struct http_ctx *c = ctx_pool;
	if (occupied_pool == current_pool_sz) {
		void *tmp = realloc(c, current_pool_sz * 2);
		if (tmp == NULL)
			return;
		
		ctx_pool = tmp;
		pr_debug(
			VERBOSE,
			"new address is allocated for context pool: %p\n",
			ctx_pool
		);
	}

	for (size_t i = 0; i < current_pool_sz; i++) {
		if (c[i].sockfd == 0) {
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

			pr_debug(
				DEBUG,
				"new socket file descriptor is registered to the pool: %d\n",
				sockfd
			);
			c[i].sockfd = sockfd;
			c[i].raw_req.cap = DEFAULT_RAW_CAP;
			c[i].raw_res.cap = DEFAULT_RAW_CAP;
			init_queue(&c[i].req_queue);
			pr_debug(
				VERBOSE,
				"init queue for socket file descriptor %d\n",
				sockfd
			);

			occupied_pool++;
			break;
		}
	}
}

static char *find_method(const char *buf)
{
	const char *http_methods[] = {
		"GET /", "POST /", "HEAD /", "PATCH /", "PUT /",
		"DELETE /", "OPTIONS /", "CONNECT /", "TRACE /", NULL
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
			/* TODO:
			* should we free b? if we decided to free b we need to
			* figure out what to do on the next concat,
			* so far raw_bytes only allocated from socket creation
			*/
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

static int parse_res_hdr(http_res_raw *r, struct http_req *res)
{
	pr_debug(VERBOSE, "begin parsing response header\n");
	pr_debug(
		VERBOSE,
		"buffer address: %p\nlength: %ld\ncapacity: %ld\n",
		r->raw_bytes, r->len, r->cap
	);

	char *http_ver = strstr(r->raw_bytes, "HTTP/1.1");
	if (http_ver == NULL)
		return -1;

	char *end_of_hdr = strstr(r->raw_bytes, "\r\n\r\n");
	if (end_of_hdr == NULL)
		return -1;
	
	/* for testing-only */
	char code_status[] = "200";
	strcpy(res->response_code, code_status);

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

static void strtolower(char *str)
{
	for (char *p = str; *p; p++)
		*p = tolower(*p);
}

static int parse_req_hdr(struct http_hdr *req_header)
{
	/* iterate over the http header */
	req_header->next_line = strstr(req_header->line, "\r\n");
	if (req_header->next_line == NULL)
		return -1;
	req_header->key = req_header->line;
	req_header->value = strchr(req_header->line, ':');
	if (req_header->value == NULL)
		return -1;
	*req_header->value = '\0';
	req_header->value += 1;

	*req_header->next_line = '\0';
	req_header->next_line += 2;
	req_header->line = req_header->next_line;

	/* ignore any leading space */
	while (*req_header->value == ' ')
		req_header->value++;

	strtolower(req_header->key);
	return 0;
}

static void handle_parse_localbuf(struct http_ctx *h, const void *buf, int buf_len)
{
	http_req_raw *r = &h->raw_req;
	/* TODO:
	* what to do when we failed to concat? stop parsing completely?
	* for now, just make sure the concat operation success before proceed-
	* executing subsequent instruction
	*/
	if (concat_buf(buf, r, buf_len) < 0)
		return;

	struct http_req req;
next:
	/* TODO:
	* how to make sure we can handle malformed HTTP request that
	* did not follow the protocol standard?
	* it is still possible that the find_method return false-positive?
	*/
	char *method = find_method(r->raw_bytes);
	if (method == NULL)
		return;

	char *end_of_hdr = strstr(r->raw_bytes, "\r\n\r\n");
	if (end_of_hdr == NULL)
		return;
	end_of_hdr += 4;

	pr_debug(VERBOSE, "begin parsing HTTP request\n");
	pr_debug(
		VERBOSE,
		"buffer address: %p\nlength: %ld\ncapacity: %ld\n",
		r->raw_bytes, r->len, r->cap
	);
	
	char *uri = strchr(r->raw_bytes, ' ');
	*uri = '\0';
	strcpy(req.method, method);
	uri += 1;

	char *end_uri = strstr(uri, " HTTP/1.") ;
	*end_uri = '\0';
	end_uri += 1;

	size_t uri_len = strlen(uri);
	if (uri_len > MAX_INSANE_URI_LENGTH)
		return;

	req.uri = malloc(uri_len);
	/*
	* abort the subsequent operation when we fail to allocate
	* dynamic memory for uri
	*/
	if (req.uri == NULL)
		return;
	strcpy(req.uri, uri);
	char *end_reqline = strstr(end_uri, "\r\n");
	char *req_header = end_reqline + 2;

	struct http_hdr hdr = {0};
	hdr.line = req_header;
	while (1) {
		if (parse_req_hdr(&hdr) < 0)
			return;

		if (strcmp(hdr.key, "host") == 0) {
			strcpy(req.host, hdr.value);
		}

		if (hdr.line + 2 == end_of_hdr)
			break;
	}

	pr_debug(VERBOSE, "push processed data to the queue\n");
	enqueue(&h->req_queue, req);
	advance(r, end_of_hdr - method);
	if (r->len > 0)
		goto next;
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

static void unwatch_sockfd(struct http_ctx *h)
{
	pr_debug(
		DEBUG,
		"socket file descriptor is unregistered from the pool: %d\n",
		h->sockfd
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

	occupied_pool--;
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

	int ret = fprintf(file_log, "[%s]|%s:%d|Host: %s|Method: %s|URI %s|Status: %s\n",
		human_readable_time,
		h->ip_addr, h->port_addr,
		req->host,
		req->method,
		req->uri,
		req->response_code
	);
	pr_debug(VERBOSE, "URI will be freed: %p\n", req->uri);
	free(req->uri);

	if (ret < 0) {
		pr_debug(VERBOSE, "failed to write parsed data to the file\n");
	} else {
		pr_debug(VERBOSE, "parsed data successfully written to the file\n");
	}
}

static void handle_parse_remotebuf(struct http_ctx *h, const void *buf, int buf_len)
{
	/* TODO:
	* what to do when we failed to concat? stop parsing completely?
	* for now, just make sure the concat operation success before proceed-
	* executing subsequent instruction
	*/
	if (concat_buf(buf, &h->raw_res, buf_len) < 0)
		return;

	pr_debug(VERBOSE, "dequeue request...\n");
	struct http_req *req = front(&h->req_queue);
	if (req == NULL) {
		pr_debug(VERBOSE, "failed to dequeue request\n");
		return;
	}

	if (parse_res_hdr(&h->raw_res, req) < 0)
		return;

	write_log(h, req);
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
		VERBOSE,
		"socket file descriptor %d is connected to %s:%d\n",
		h->sockfd,
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
		  "d" (size),		/* %rdx */
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
		  "d" (size),		/* %rdx */
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
		unwatch_sockfd(h);

	return ret;
}
