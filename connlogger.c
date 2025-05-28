#define _GNU_SOURCE // for strcasestr
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HTTP_VER_LEN 10
#define RAW_BUFF_SZ 1024 * 1024
#define POOL_SZ 100
#define REQ_QUEUE_SZ 32
#define LINEBREAK_LEN 4
static FILE *log_file = NULL;

struct http_req {
	char http_method[8 + 1];
	char http_path[8000 + 1];
	char http_host_hdr[63 + 253 + 1];
};

struct http_req_queue {
	int head;
	int tail;
	struct http_req array[REQ_QUEUE_SZ];
};

struct http_ctx {
	int sockfd;
	char remote_addr[INET6_ADDRSTRLEN];
	uint16_t remote_port;
	struct http_req_queue http_req_queue;
	char *raw_http_req_hdr;
	char *raw_http_res_hdr;
	char *ptr_raw_http_req_hdr;
	char *ptr_raw_http_res_hdr;
	char http_code_status[3 + 1];
};

static struct http_ctx network_state[POOL_SZ] = {
	[0 ... POOL_SZ-1] = { .sockfd = -1 }
};

struct http_ctx *find_ctx(int sockfd)
{
	struct http_ctx *ctx = NULL;
	for (size_t i = 0; i < POOL_SZ; i++) {
		if (network_state[i].sockfd == sockfd) {
			ctx = &network_state[i];
			break;
		}
	}

	return ctx;
}

void enqueue(struct http_req_queue *q, struct http_req http_req)
{
	/* make sure the queue is not full */
	if (q->tail == REQ_QUEUE_SZ)
		return;

	q->array[q->tail] = http_req;
	q->tail++;
}

/* return front item and dequeue */
struct http_req *front(struct http_req_queue *q)
{
	/* make sure the queue is not empty */
	if (q->head == q->tail)
		return NULL;

	struct http_req *req = &q->array[q->head];

	q->head++;
	return req;
}

static void init_log(void)
{
	const char *log_path;
	if (log_file)
		return;

	log_path = getenv("GWLOG_PATH");
	if (!log_path)
		log_path = "/dev/null";

	log_file = fopen(log_path, "a");
	setvbuf(log_file, NULL, _IOLBF, 0);
}

char *validate_method(const char raw_bytes[])
{
	const char *http_methods[] = {
		"GET", "POST", "HEAD", "PATCH", "PUT",
		"DELETE", "OPTIONS", "CONNECT", "TRACE", NULL
	};
	const char **ptr = http_methods;
	char *method_ptr = NULL;
	while (*ptr) {
		method_ptr = strstr(raw_bytes, *ptr);
		if (method_ptr != NULL)
			break;
		ptr++;
	}

	return method_ptr;
}

char *validate_http_ver(const char raw_bytes[])
{
	/* for now only support logging for HTTP/1.1 */
	const char *http_ver_list[] = {"HTTP/1.1 ", NULL};
	const char **ptr = http_ver_list;
	char *http_ver_ptr = NULL;
	while (*ptr) {
		http_ver_ptr = strstr(raw_bytes, *ptr);
		if (http_ver_ptr != NULL)
			break;
		ptr++;
	}

	return http_ver_ptr;
}

void unwatch_connection(struct http_ctx *ctx)
{
	/*
	* weird, free cause segfault on google chrome browser
	* even though it's already guaranteed to be malloc'ed as
	* the ctx is only available through socket() call which call calloc
	*/
	// free(ctx->raw_http_res_hdr);
	// free(ctx->raw_http_req_hdr);
	memset(ctx, 0, sizeof(struct http_ctx));
	ctx->sockfd = -1;
}

void handle_parsing_localbuf(int sockfd, const void *buf, int buf_len)
{
	struct http_ctx *find_ctx = find_ctx(sockfd);
	if (ctx != NULL) {
		/*
		* handle partial send by concat HTTP request header
		* until \r\n\r\n
		*/
		strncat(ctx->ptr_raw_http_req_hdr, buf, buf_len);

		char end_header[] = "\r\n\r\n";
		char *possible_http = validate_method(ctx->ptr_raw_http_req_hdr);
		if (possible_http == NULL)
			return;
		ctx->ptr_raw_http_req_hdr = possible_http;
		char *start = ctx->ptr_raw_http_req_hdr;
		char *pos;

		/*
		* enqueue more than one times if the buffer have
		* multiple request (either HTTP pipeline or HTTP keep-alive).
		*
		* when we have validated method and get crlf crlf,
		* data ready to be parsed.
		*/
		while ((pos = strstr(start, end_header)) != NULL) {
			*pos = '\0';
			int str_len = strlen(start);
			char tmpstr[str_len];
			char *saveptr_tmpstr = NULL;
			strcpy(tmpstr, start);
			const char keyword[] = "Host:";
			const char *method = strtok_r(tmpstr, " ", &saveptr_tmpstr);
			const char *path = strtok_r(NULL, " ", &saveptr_tmpstr);

			char anothertmpstr[str_len];
			char *svptr = NULL;
			strcpy(anothertmpstr, start);
			char *http_host_hdr = strcasestr(anothertmpstr, keyword);
			strtok_r(http_host_hdr, "\r\n", &svptr);

			struct http_req req;
			strcpy(req.http_method, method);
			strcpy(req.http_path, path);
			strcpy(req.http_host_hdr, http_host_hdr);

			enqueue(&ctx->http_req_queue, req);

			memset(ctx->ptr_raw_http_req_hdr, 0, str_len);
			start = pos + LINEBREAK_LEN;
		}
	}
}

void handle_parsing_networkbuf(int sockfd, const void *buf, int buf_len)
{
	struct http_ctx *ctx = find_ctx(sockfd);

	if (ctx != NULL) {
		/*
		* handle partial recv by concat HTTP response header
		* until \r\n\r\n
		*/
		strncat(ctx->ptr_raw_http_res_hdr, buf, buf_len);

		char *possible_http = validate_http_ver(ctx->ptr_raw_http_res_hdr);
		if (possible_http == NULL)
			return;
		ctx->ptr_raw_http_res_hdr = possible_http;

		char end_header[] = "\r\n\r\n";
		char end_of_header = 0;
		char *eof_ptr = strstr(ctx->ptr_raw_http_res_hdr, end_header);
		if (eof_ptr != NULL)
			end_of_header = 1;

		/* data ready to be parsed */
		if (end_of_header == 1) {
			*eof_ptr = '\0';
			
			struct http_req *req = front(&ctx->http_req_queue);
			if (req != NULL) {
				char tmpbuf[strlen(ctx->ptr_raw_http_res_hdr)];
				char *svptr = NULL;
				char *response_code;
				strcpy(tmpbuf, ctx->ptr_raw_http_res_hdr);
				strtok_r(tmpbuf, " ", &svptr);
				response_code = strtok_r(NULL, " ", &svptr);
				strcpy(ctx->http_code_status, response_code);

				time_t rawtime;
				struct tm *timeinfo;
				time(&rawtime);
				timeinfo = localtime(&rawtime);
				char formatted_time[32];
				strcpy(formatted_time, asctime(timeinfo));
				formatted_time[strlen(formatted_time) - 1] = '\0';

				init_log();
				fprintf(
					log_file,
					"[%s]|address %s:%d|HTTP Ver: HTTP/1.1|Method: %s|Path: %s|%s|HTTP Response: %s\n",
					formatted_time, ctx->remote_addr, ctx->remote_port, req->http_method, req->http_path, req->http_host_hdr, ctx->http_code_status
				);
				char *next_ptr = eof_ptr+LINEBREAK_LEN;
				ctx->ptr_raw_http_res_hdr = next_ptr;
			}
		}
	}
}

int socket(int domain, int type, int protocol)
{
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket),		/* %rax */
		  "D" (domain),			/* %rdi */
		  "S" (type),			/* %rsi */
		  "d" (protocol)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else if (domain == AF_INET || domain == AF_INET6) {
		for (size_t i = 0; i < POOL_SZ; i++) {
			if (network_state[i].sockfd == -1) {
				network_state[i].sockfd = ret;
				network_state[i].raw_http_req_hdr = calloc(1, RAW_BUFF_SZ);
				network_state[i].raw_http_res_hdr = calloc(1, RAW_BUFF_SZ);
				network_state[i].ptr_raw_http_req_hdr = network_state[i].raw_http_req_hdr;
				network_state[i].ptr_raw_http_res_hdr = network_state[i].raw_http_res_hdr;
				break;
			}
		}
	}

	return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	asm volatile (
		"syscall"
		:"=a" (ret)
		:"a" (__NR_connect),		/* %rax */
		 "D" (sockfd),			/* %rdi */
		 "S" (addr),			/* %rsi */
		 "d" (addrlen)			/* %rdx */
		:"memory", "rcx", "r11", "cc"
	);

	if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
		struct http_ctx *ctx = find_ctx(sockfd);

		if (ctx != NULL) {
			const struct sockaddr_in *in = (void *)addr;
			const struct sockaddr_in6 *in6 = (void *)addr;

			switch (addr->sa_family) {
			case AF_INET:
				inet_ntop(AF_INET, &in->sin_addr, ctx->remote_addr, INET_ADDRSTRLEN);
				ctx->remote_port = ntohs(in->sin_port);
				break;
			case AF_INET6:
				inet_ntop(AF_INET6, &in6->sin6_addr, ctx->remote_addr, INET6_ADDRSTRLEN);
				ctx->remote_port = ntohs(in6->sin6_port);
				break;
			}
		}
	}

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
	register int _flags asm("r10") = flags;
	register const struct sockaddr *_dest_addr asm("r8") = dst_addr;
	register socklen_t _dest_len asm("r9") = addrlen;
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto),		/* %rax */
		  "D" (sockfd),			/* %rdi */
		  "S" (buf),			/* %rsi */
		  "d" (size),			/* %rdx */
		  "r" (_flags),			/* %r10 */
		  "r" (_dest_addr),		/* %r8 */
		  "r" (_dest_len)		/* %r9 */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		handle_parsing_localbuf(sockfd, buf, ret);
	}

	return ret;
}

ssize_t recvfrom(
	int sockfd, void *buf, size_t size, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
{
	register int _flags asm("r10") = flags;
	register struct sockaddr *_dest_addr asm("r8") = src_addr;
	register socklen_t *_dest_len asm("r9") = addrlen;
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom),		/* %rax */
		  "D" (sockfd),			/* %rdi */
		  "S" (buf),			/* %rsi */
		  "d" (size),			/* %rdx */
		  "r" (_flags),			/* %r10 */
		  "r" (_dest_addr),		/* %r8 */
		  "r" (_dest_len)		/* %r9 */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		handle_parsing_networkbuf(sockfd, buf, ret);
	}

	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_read),		/* %rax */
		  "D" (fd),			/* %rdi */
		  "S" (buf),			/* %rsi */
		  "d" (count)			/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		handle_parsing_networkbuf(fd, buf, count);
	}

	return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_write),		/* %rax */
		  "D" (fd),			/* %rdi */
		  "S" (buf),			/* %rsi */
		  "d" (count)			/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		handle_parsing_localbuf(fd, buf, ret);
	}

	return ret;
}

ssize_t send(int sockfd, const void *buf, size_t size, int flags)
{
	return sendto(sockfd, buf, size, flags, NULL, 0);
}

ssize_t recv(int sockfd, void *buf, size_t size, int flags)
{
	return recvfrom(sockfd, buf, size, flags, NULL, NULL);
}

int close(int fd)
{
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_close),		/* %rax */
		  "D" (fd)			/* %rdi */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		struct http_ctx *ctx = find_ctx(sockfd);

		if (ctx != NULL)
			unwatch_connection(ctx);
	}

	return ret;
}
