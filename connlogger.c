#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

/* cheating for testing purposes :v */
#include <sys/syscall.h>
#include <unistd.h>

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
		 "D" (sockfd),	/* %rdi */
		 "S" (addr),	/* %rsi */
		 "d" (addrlen)	/* %rdx */
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

	sprintf(formatted_log, "[%s] address %s:%d, return: %d\n", formatted_time, ip_str, port, ret);
	init_log();
	fwrite(formatted_log, strlen(formatted_log), 1, log_file);

	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	return 0;
}

ssize_t send(int sockfd, const void *buf, size_t size, int flags) {
	init_log();
	const char testing[] = "test send\n";
	fwrite(testing, sizeof(testing) - 1, 1, log_file);
	
	return syscall(__NR_sendto, sockfd, buf, size, flags, NULL, 0);
}

ssize_t recv(int sockfd, void *buf, size_t size, int flags) {
	init_log();
	const char testing[] = "test recv\n";
	fwrite(testing, sizeof(testing) - 1, 1, log_file);
	
	return syscall(__NR_recvfrom, sockfd, buf, size, flags, NULL, 0);
}
