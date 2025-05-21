#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>

static FILE *log_file = NULL;

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

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	asm volatile(
		"syscall"
		:"=a" (ret)
		:"a" (__NR_connect),	/* %rax */
		 "D" (sockfd),		/* %rdi */
		 "S" (addr),		/* %rsi */
		 "d" (addrlen)		/* %rdx */
		:"memory", "rcx", "r11", "cc"
	);

	char formatted_log[1024] = {0};
	
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	char formatted_time[255];
	strcpy(formatted_time, asctime(timeinfo));
	formatted_time[strlen(formatted_time) - 1] = '\0';

	char ip_str[INET6_ADDRSTRLEN] = {0};
	uint16_t port;
	switch (addr->sa_family) {
	case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), ip_str, INET_ADDRSTRLEN);
			port = ntohs(((struct sockaddr_in *)addr)->sin_port);
		break;
	case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr), ip_str, INET6_ADDRSTRLEN);
			port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
		break;
	}

	if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
		sprintf(formatted_log, "[%s]|address %s:%d|", formatted_time, ip_str, port);
		init_log();
		fwrite(formatted_log, strlen(formatted_log), 1, log_file);
		fflush(log_file);
	}

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}

ssize_t send(int sockfd, const void *buf, size_t size, int flags) {
	register int _flags asm("r10") = flags;
	register struct sockaddr *_dest_addr asm("r8") = NULL;
	register socklen_t _dest_len asm("r9") = 0;
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (size),		/* %rdx */
		  "r" (_flags),		/* %r10 */
		  "r" (_dest_addr),	/* %r8 */
		  "r" (_dest_len)	/* %r9 */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		char tmpbuf[ret];
		strncpy(tmpbuf, buf, ret);
		char *method = strtok(tmpbuf, " ");
		char *path = strtok(0, " ");
		char *http_version = strtok(0, "\r\n");
		char *host = strtok(0, "\r\n");
		
		init_log();
		fprintf(log_file, "HTTP Ver: %s|Method: %s|Path: %s|%s|", http_version, method, path, host);
		fflush(log_file);
	}
	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t size, int flags) {
	register int _flags asm("r10") = flags;
	register struct sockaddr *_dest_addr asm("r8") = NULL;
	register socklen_t _dest_len asm("r9") = 0;
	int ret;
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (size),		/* %rdx */
		  "r" (_flags),		/* %r10 */
		  "r" (_dest_addr),	/* %r8 */
		  "r" (_dest_len)	/* %r9 */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	} else {
		strtok(buf, " ");
		char *response_code = strtok(0, " ");
		init_log();
		fprintf(log_file, "HTTP Response: %s\n", response_code);
	}
	return ret;
}
