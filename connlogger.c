#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define POOL_SZ 100

static FILE *log_file = NULL;
struct http_ctx {
	int sockfd;
	int incr_send;
	int incr_recv;
	char remote_addr[INET6_ADDRSTRLEN];
	uint16_t remote_port;
	char *raw_http_req_hdr;
	char *raw_http_res_hdr;
	char http_method[8 + 1];
	char http_path[8000 + 1];
	char http_host_hdr[63 + 253 + 1];
	char http_code_status[3 + 1];
};
static struct http_ctx network_state[POOL_SZ] = {
	[0 ... POOL_SZ-1] = { .sockfd = -1 }
};

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

char validate_method(const char method[])
{
	const char *http_methods[] = {"GET", "POST", "HEAD", "PATCH", "PUT", "DELETE", "OPTIONS", "CONNECT", "TRACE", NULL};
	char valid = 0;
	const char **ptr = http_methods;
	while (*ptr) {
		const char *http_method = *ptr;
		const char *first_bytes = method;
		while (*http_method) {
			if (*first_bytes != *http_method)
				valid = 0;
			else
				valid = 1;
			first_bytes++;
			http_method++;
		}
		if (valid)
			break;
		ptr++;
	}

	return valid;
}

char validate_http_ver(const char bytes[])
{
	/* for now only support logging for HTTP/1.1 */
	const char *http_ver_list[] = {"HTTP/1.1", NULL};
	char valid = 0;
	const char **ptr = http_ver_list;
	while (*ptr) {
		const char *http_ver = *ptr;
		const char *first_bytes = bytes;
		while (*http_ver) {
			if (*first_bytes != *http_ver)
				valid = 0;
			else
				valid = 1;
			first_bytes++;
			http_ver++;
		}
		if (valid)
			break;
		ptr++;
	}

	return valid;
}

void unwatch_connection(struct http_ctx *ctx)
{
	ctx->sockfd = -1;
	ctx->incr_recv = 0;
	ctx->incr_send = 0;
	free(ctx->raw_http_req_hdr);
	free(ctx->raw_http_res_hdr);
}

int socket(int domain, int type, int protocol)
{
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket),	/* %rax */
		  "D" (domain),			/* %rdi */
		  "S" (type),			/* %rsi */
		  "d" (protocol)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		for (size_t i = 0; i < POOL_SZ; i++) {
			if (network_state[i].sockfd == -1 && (domain == AF_INET || domain == AF_INET6)) {
				network_state[i].sockfd = ret;
				network_state[i].raw_http_req_hdr = calloc(1, 1024 * 1024);
				network_state[i].raw_http_res_hdr = calloc(1, 1024 * 1024);
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
		:"a" (__NR_connect),	/* %rax */
		 "D" (sockfd),			/* %rdi */
		 "S" (addr),			/* %rsi */
		 "d" (addrlen)			/* %rdx */
		:"memory", "rcx", "r11", "cc"
	);
	
	if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {		
		struct http_ctx *ctx = NULL;
		for (size_t i = 0; i < POOL_SZ; i++) {
			if (network_state[i].sockfd == sockfd) {
				ctx = &network_state[i];
				break;
			}
		}

		if (ctx != NULL) {
			switch (addr->sa_family) {
			case AF_INET:
					inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), ctx->remote_addr, INET_ADDRSTRLEN);
					ctx->remote_port = ntohs(((struct sockaddr_in *)addr)->sin_port);
				break;
			case AF_INET6:
					inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr), ctx->remote_addr, INET6_ADDRSTRLEN);
					ctx->remote_port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
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

ssize_t sendto(int sockfd, const void *buf, size_t size, int flags, const struct sockaddr *dst_addr, socklen_t addrlen)
{
	register int _flags asm("r10") = flags;
	register const struct sockaddr *_dest_addr asm("r8") = dst_addr;
	register socklen_t _dest_len asm("r9") = addrlen;
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto),	/* %rax */
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
		struct http_ctx *ctx = NULL;
		for (size_t i = 0; i < POOL_SZ; i++) {
			if (network_state[i].sockfd == sockfd) {
				ctx = &network_state[i];
				break;
			}
		}

		if (ctx != NULL) {
			/* increment amount of sendto call */
			ctx->incr_send += 1;
			if (ctx->incr_send == 1 && !validate_method(buf)) {
				unwatch_connection(ctx);
				return ret;
			}

			/* concat HTTP request header until \r\n\r\n */
			strncat(ctx->raw_http_req_hdr, buf, ret);

			/* check for line break */
			char end_header[] = "\r\n\r\n";
			char end_of_header = 0;
			if (strstr(buf, end_header) != NULL)
				end_of_header = 1;

			/* data ready to be parsed */
			if (end_of_header == 1) {
				int str_len = strlen(ctx->raw_http_req_hdr);
				char tmpstr[str_len];
				strcpy(tmpstr, ctx->raw_http_req_hdr);
				const char keyword[] = "Host:";
				const char *method = strtok(tmpstr, " ");
				const char *path = strtok(NULL, " ");

				char *http_host_hdr = strcasestr(ctx->raw_http_req_hdr, keyword);
				strtok(http_host_hdr, "\r\n");
				strcpy(ctx->http_method, method);
				strcpy(ctx->http_path, path);
				strcpy(ctx->http_host_hdr, http_host_hdr);
			}
		}
	}

	return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t size, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	register int _flags asm("r10") = flags;
	register struct sockaddr *_dest_addr asm("r8") = src_addr;
	register socklen_t *_dest_len asm("r9") = addrlen;
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom),	/* %rax */
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
		struct http_ctx *ctx = NULL;
		for (size_t i = 0; i < POOL_SZ; i++) {
			if (network_state[i].sockfd == sockfd) {
				ctx = &network_state[i];
				break;
			}
		}

		if (ctx != NULL) {
			/* increment amount of recvfrom call, for now it's unused */
			ctx->incr_recv += 1;
			if (strlen(ctx->raw_http_res_hdr) >= 9 && !validate_http_ver(ctx->raw_http_res_hdr)) {
				unwatch_connection(ctx);
				return ret;
			}

			/* concat HTTP response header until \r\n\r\n */
			strncat(ctx->raw_http_res_hdr, buf, ret);
			char end_header[] = "\r\n\r\n";
			char end_of_header = 0;
			if (strstr(ctx->raw_http_res_hdr, end_header) != NULL)
				end_of_header = 1;

			/* data ready to be parsed */
			if (end_of_header == 1) {
				char tmpbuf[strlen(ctx->raw_http_res_hdr)];
				char *response_code;
				strcpy(tmpbuf, ctx->raw_http_res_hdr);
				strtok(tmpbuf, " ");
				response_code = strtok(NULL, " ");
				strcpy(ctx->http_code_status, response_code);

				time_t rawtime;
				struct tm *timeinfo;
				time(&rawtime);
				timeinfo = localtime(&rawtime);
				char formatted_time[255];
				strcpy(formatted_time, asctime(timeinfo));
				formatted_time[strlen(formatted_time) - 1] = '\0';

				char formatted_log[1024] = {0};
				sprintf(formatted_log, "[%s]|address %s:%d|HTTP Ver: HTTP/1.1|Method: %s|Path: %s|%s|HTTP Response: %s\n", formatted_time, ctx->remote_addr, ctx->remote_port, ctx->http_method, ctx->http_path, ctx->http_host_hdr, ctx->http_code_status);

				init_log();
				fwrite(formatted_log, strlen(formatted_log), 1, log_file);
				fflush(log_file);

				unwatch_connection(ctx);
			}
		}
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
		: "a" (__NR_close),	/* %rax */
		  "D" (fd)			/* %rdi */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		struct http_ctx *ctx = NULL;
		for (size_t i = 0; i < POOL_SZ; i++) {
			if (network_state[i].sockfd == fd) {
				ctx = &network_state[i];
				break;
			}
		}

		if (ctx != NULL) {
			unwatch_connection(ctx);
		}
	}

	return ret;
}
