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


