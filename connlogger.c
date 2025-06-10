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
#define FOCUS 1
#define DEFAULT_REQ_QUEUE_SZ 11000
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
	struct http_hdr req_hdr;
	struct http_hdr res_hdr;
	bool is_chunked_res;
	bool is_chunked_req;
	size_t content_length_req;
	size_t content_length_res;
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
	parser_state req_state;
	parser_state res_state;
};

static size_t current_pool_sz = DEFAULT_POOL_SZ;
static size_t occupied_pool = 0;
static struct http_ctx *ctx_pool = NULL;
static FILE *file_log = NULL;

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
	if (log_file == NULL) {
		pr_debug(DEBUG, "no file path provided in GWLOG_PATH env\n");
		return -1;
	}

	file_log = fopen(log_file, "a");
	if (file_log == NULL) {
		pr_debug(DEBUG, "failed to open file %s\n", log_file);
		return -1;
	}

	setvbuf(file_log, NULL, _IOLBF, 0);
	ctx_pool = calloc(DEFAULT_POOL_SZ, sizeof(struct http_ctx));
	if (ctx_pool == NULL) {
		pr_debug(DEBUG, "fail to allocate dynamic memory\n");
		return -1;
	}

	pr_debug(
		DEBUG,
		"init the pool context and file handle for the first time\n"
	);
	pr_debug(VERBOSE, "allocated address of context pool: %p\n", ctx_pool);
	return 0;
}

static void advance(struct concated_buf *ptr, size_t len)
{
	size_t overall_len = ptr->len;
	if (len > ptr->len)
		ptr->len = 0;
	else
		ptr->len -= len;

	if (ptr->len > 0) {
		memmove(ptr->raw_bytes, ptr->raw_bytes + len, ptr->len);
		ptr->raw_bytes[ptr->len] = '\0';
	} else
		memset(ptr->raw_bytes, 0, overall_len);
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

		c[i].raw_req.raw_bytes = calloc(1, DEFAULT_RAW_CAP + 1);
		c[i].raw_res.raw_bytes = calloc(1, DEFAULT_RAW_CAP + 1);
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
		FOCUS,
		"sockfd %d (%s) is unregistered from the pool: %s\n",
		h->sockfd, h->ip_addr, reason
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
	while (h->req_queue.occupied > 0) {
		struct http_req *req = front(&h->req_queue);
		if (req->uri)
			free(req->uri);
		dequeue(&h->req_queue);
	}
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
	size_t incoming_len = *append_pos + len + 1;
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
	(*b)[buf->len] = '\0';

	return 0;
}

static void strtolower(char *str)
{
	for (char *p = str; *p; p++)
		*p = tolower(*p);
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

static void handle_parse_localbuf(int fd, const void *buf, int buf_len)
{
	struct http_ctx *h = find_http_ctx(fd);
	if (h == NULL)
		return;
}

static void handle_parse_remotebuf(int fd, const void *buf, int buf_len)
{
	struct http_ctx *h = find_http_ctx(fd);
	if (h == NULL)
		return;
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

	if (init() == 0)
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

	handle_parse_remotebuf(sockfd, buf, ret);

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

	handle_parse_localbuf(sockfd, buf, ret);

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

	handle_parse_remotebuf(fd, buf, ret);

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

	handle_parse_localbuf(fd, buf, ret);

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
