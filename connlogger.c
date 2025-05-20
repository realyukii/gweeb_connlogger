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
	);

	printf("ret: %d\n", ret);
	perror("connect");
	if (ret < 0) {
		puts("failed");
		errno = -ret;
		return -1;
	}

	puts("success");

	return 0;
}
