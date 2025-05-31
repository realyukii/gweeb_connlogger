#include <arpa/inet.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define DEFAULT_POOL_SZ 100
#define DEFAULT_RAW_CAP 1024

struct http_req {
	char *raw_bytes;
	size_t len;
	size_t cap;
};

struct http_res {
};

struct http_ctx {
	int sockfd;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port_addr;
	struct http_req req;
	struct http_res res;
};

static size_t current_pool_sz = DEFAULT_POOL_SZ;
static struct http_ctx *ctx_pool = NULL;
static FILE *file_log = NULL;

static int init(void)
{
	/* already initialised, skip duplicate init, exit. */
	if (file_log != NULL && ctx_pool != NULL)
		return -1;

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
	
	return 0;
}

static void push_sockfd(int sockfd)
{
	/* TODO:
	* find out how the pool will be resized when the current pool size is full
	*/
	struct http_ctx *c = ctx_pool;
	for (size_t i = 0; i < current_pool_sz; i++) {
		if (c[i].sockfd == 0) {
			c[i].req.raw_bytes = malloc(DEFAULT_RAW_CAP);
			/*
			* do not push current connection to the pool
			* if we fail to allocate some memory
			*/
			if (c[i].req.raw_bytes != NULL) {
				c[i].sockfd = sockfd;
				c[i].req.cap = DEFAULT_RAW_CAP;
			}
			break;
		}
	}
}

static void concat_buf(const void *src, struct http_ctx *h, size_t len)
{
	size_t *append_pos = &h->req.len;
	size_t incoming_len = *append_pos + len;
	void *b = h->req.raw_bytes;

	if (incoming_len <= h->req.cap) {
		memcpy(b + *append_pos, src, len);
		*append_pos += len;
	} else {
		/* we don't have enough space in the memory, let's resize it */
		void *tmp = realloc(b, h->req.cap + incoming_len);
		if (tmp == NULL) {
			// TODO: should we free b?
			return;
		}
		b = tmp;
		memcpy(b + *append_pos, src, len);
		*append_pos += len;
		h->req.cap += incoming_len;
	}
}

static void handle_parse_localbuf(struct http_ctx *h, const void *buf, int buf_len)
{
	/* TODO:
	* what to do when we failed to concat? stop parsing completely?
	*/
	concat_buf(buf, h, buf_len);
}

static void handle_parse_remotebuf(void)
{
}

static struct http_ctx *find_http_ctx(int sockfd)
{
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
	h->sockfd = 0;
	h->req.cap = DEFAULT_RAW_CAP;
	h->req.len = 0;
	free(h->req.raw_bytes);
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

static void write_log(struct http_ctx *h)
{
	char human_readable_time[26] = {0};
	generate_current_time(human_readable_time);

	fprintf(file_log, "[%s] %s:%d\n", human_readable_time, h->ip_addr, h->port_addr);
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
	}

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
	}

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
	}

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

	/* exclude stdin file descriptor, just in case... */
	if (fd != 0) {
		struct http_ctx *h = find_http_ctx(fd);
		if (h != NULL)
			unwatch_sockfd(h);
	}

	return ret;
}
