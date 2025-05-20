#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	int ret;
	asm volatile(
			"syscall"
		:	"=a" (ret)
		:	"a" (42),		/* %rax */
			"D" (sockfd),	/* %rdi */
			"S" (addr),		/* %rsi */
			"d" (addrlen)	/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	FILE *handle = fopen("./build/log", "a");
	char formatted_log[1024] = {0};
	
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	char formatted_time[255];
	strcpy(formatted_time, asctime(timeinfo));
	formatted_time[strlen(formatted_time) - 1] = '\0';
	char ip_str[INET6_ADDRSTRLEN] = {0};

	switch (addr->sa_family)
	{
	case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), ip_str, INET_ADDRSTRLEN);
		break;
	case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr), ip_str, INET6_ADDRSTRLEN);
		break;
	default:
		sprintf(ip_str, "Unknown AF");
		break;
	}
	sprintf(formatted_log, "[%s] address %s, return: %d\n", formatted_time, ip_str, ret);
	fwrite(formatted_log, strlen(formatted_log), 1, handle);

	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	return 0;
}
