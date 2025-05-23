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
	char remote_addr[INET6_ADDRSTRLEN];
	uint16_t remote_port;
	char is_http11;
	char *http_method;
	char *http_path;
	char *http_host_hdr;
	char *http_code_status;
};
static struct http_ctx network_state[POOL_SZ] = {0};

static void init_log(void)
{
	const char *log_path;
	if (log_file)
		return;

	log_path = getenv("GWLOG_PATH");
	if (!log_path)
		log_path = "/dev/null";

	log_file = fopen(log_path, "a");
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
			if (network_state[i].sockfd == 0) {
				network_state[i].sockfd = ret;
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

		// char str_sockfd[255] = {0};
		// sprintf(str_sockfd, "connected at socket file descriptor: %d\n", sockfd);
	
		// init_log();
		// fwrite(str_sockfd, strlen(str_sockfd), 1, log_file);

		// fwrite(formatted_log, strlen(formatted_log), 1, log_file);
		fflush(log_file);
	}

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

ssize_t send(int sockfd, const void *buf, size_t size, int flags)
{
	register int _flags asm("r10") = flags;
	register struct sockaddr *_dest_addr asm("r8") = NULL;
	register socklen_t _dest_len asm("r9") = 0;
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
			char tmpbuf[ret];
			strncpy(tmpbuf, buf, ret);
			char *method = strtok(tmpbuf, " ");
			char *path = strtok(0, " ");
			char *http_version = strtok(0, "\r\n");
			char *host = strtok(0, "\r\n");

			ctx->http_method = malloc(strlen(method));
			ctx->http_path = malloc(strlen(path));
			ctx->http_host_hdr = malloc(strlen(host));

			strcpy(ctx->http_method, method);
			strcpy(ctx->http_path, path);
			strcpy(ctx->http_host_hdr, host);
			
			// char str_sockfd[255] = {0};
			// sprintf(str_sockfd, "send from socket file descriptor: %d\n", sockfd);
			
			// init_log();
			// fwrite(str_sockfd, strlen(str_sockfd), 1, log_file);

			// fprintf(log_file, "HTTP Ver: %s|Method: %s|Path: %s|%s|", http_version, method, path, host);
			// fflush(log_file);
		}
	}
	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t size, int flags)
{
	register int _flags asm("r10") = flags;
	register struct sockaddr *_dest_addr asm("r8") = NULL;
	register socklen_t _dest_len asm("r9") = 0;
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
		for (size_t i = 0; i < POOL_SZ; i++)
		{
			if (network_state[i].sockfd == sockfd) {
				ctx = &network_state[i];
				break;
			}
		}

		if (ctx != NULL) {
			strtok(buf, " ");
			char *response_code = strtok(0, " ");
			init_log();

			ctx->http_code_status = malloc(strlen(response_code));
			strcpy(ctx->http_code_status, response_code);

			// char str_sockfd[255] = {0};
			// sprintf(str_sockfd, "receive from socket file descriptor: %d\n", sockfd);
			// fwrite(str_sockfd, strlen(str_sockfd), 1, log_file);

			// fprintf(log_file, "HTTP Response: %s\n", response_code);
		}
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

			/* cleanup */
			ctx->sockfd = -1;
			free(ctx->http_method);
			free(ctx->http_path);
			free(ctx->http_host_hdr);
			free(ctx->http_code_status);
		}
	}

	return ret;
}
