## links and documentation
- `connect(2)`
- [osdev wiki](https://wiki.osdev.org/Inline_Assembly) - inline assembly
- [gcc documentation](https://gcc.gnu.org/onlinedocs/gcc/Constraints.html) - list of constraint letter
- [well-written example](gist.github.com/ammarfaizi2/1e1424f987cfbe3e3c3b571b6e590923) as references
- [ChatGPT](https://chatgpt.com/share/682c9388-e6dc-8002-a209-fe11def5a65e) - debugging a shared library
- [stackoverflow](https://stackoverflow.com/questions/15997759/constraining-r10-register-in-gcc-inline-x86-64-assembly) - r10 register is not available in constraint letter

### glibc
list of used glibc's function:
- `sprintf`
- `strlen`
- `localtime`
- `asctime`
- `fopen`
- `fwrite`
- `getenv`

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

### note
dikutip dari SystemV ABI:
> user-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.

calling convention untuk function user-level application dan linux kernel system call itu berbeda.

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

okay, it's a file? `run/systemd/resolve/io.system` (the AF_FAMILY is pointed to PF_LOCAL):
```
gef➤  p/d $rax
$1 = 42
gef➤  p $rsi
$2 = 0x7ffff6dfe040
gef➤  hexdump byte $rsi
0x00007ffff6dfe040     01 00 2f 72 75 6e 2f 73 79 73 74 65 6d 64 2f 72    ../run/systemd/r
0x00007ffff6dfe050     65 73 6f 6c 76 65 2f 69 6f 2e 73 79 73 74 65 6d    esolve/io.system
0x00007ffff6dfe060     64 2e 52 65 73 6f 6c 76 65 00 00 00 00 00 00 00    d.Resolve.......
0x00007ffff6dfe070     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
gef➤  
```