#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

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

	printf("ret: %d\n", ret);
	if (ret < 0) {
		errno = -ret;
		puts("failed");
		perror("connect");
		return -1;
	}

	fprintf(stderr, "success\n");

	return 0;
}
