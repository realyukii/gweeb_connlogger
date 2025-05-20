## documentation
- `connect(2)`
- [osdev wiki](https://wiki.osdev.org/Inline_Assembly) - inline assembly
- [gcc documentation](https://gcc.gnu.org/onlinedocs/gcc/Constraints.html) - list of constraint letter
- [well-written example](gist.github.com/ammarfaizi2/1e1424f987cfbe3e3c3b571b6e590923) as references

### inline assembly
```
__asm__ volatile (
	"syscall"
	: "=a" (fd2)		/* %rax */
	: "a" (257),		/* %rax */
		"D" (fd),		/* %rdi */
		"S" (file),		/* %rsi */
		"d" (flags),	/* %rdx */
		"r" (__mode)	/* %r10 */
	: "memory", "rcx", "r11", "cc"
);
```

syntax inline-assembly terdiri dari:
```
__asm__ volatile (
	"assembly instruction"				(optional)
	: [label] "=constraint" (C bind)	(optional)
	: [label] "constraint" (C bind)		(optional)
	: clobbered register list
)
```

### Weird stuff
```
[reyuki@zero gweeb_connlogger]$  strace -e trace=connect /usr/bin/env LD_PRELOAD=/home/reyuki/software/my-code/gnuweeb/gweeb_connlogger/build/gwconnlogger.so curl -s http://google.com/ >/dev/null
connect: No such file or directory
connect(4, {sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2404:6800:4003:c05::8a", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)
connect: Operation now in progress
+++ exited with 0 +++
[reyuki@zero gweeb_connlogger]$ 
```
no such file or directory on connect syscall? printed by `perror`