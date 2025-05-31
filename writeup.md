## links and documentation
- `connect(2)`
- [osdev wiki](https://wiki.osdev.org/Inline_Assembly) - inline assembly
- [gcc documentation](https://gcc.gnu.org/onlinedocs/gcc/Constraints.html) - list of constraint letter
- [well-written example](gist.github.com/ammarfaizi2/1e1424f987cfbe3e3c3b571b6e590923) as references
- [ChatGPT](https://chatgpt.com/share/682c9388-e6dc-8002-a209-fe11def5a65e) - debugging a shared library
- [stackoverflow](https://stackoverflow.com/questions/15997759/constraining-r10-register-in-gcc-inline-x86-64-assembly) - r10 register is not available in constraint letter
- [telegram](https://t.me/GNUWeeb/1169097) - review and suggestion by sir Ammar
- [gist github](https://gist.github.com/htp/fbce19069187ec1cc486b594104f01d0) - test websocket connection with curl

### glibc
list of used glibc's function:
from string:
- `strcpy`
from time:
- `time`
- `localtime`
- `asctime_r`
from stdio:
- `fopen`
- `fprintf`
from arpa/inet:
- `ntohs`
- `inet_ntop`
from stdlib:
- `getenv`
- `calloc`

list of used glibc's defined constant and custom data type:
from stdio:
- typedef FILE
from sys/syscall
- system call number
from arpa/inet:
- struct sockaddr
- AF_INET, AF_INET6
- SOCK_STREAM
- INET6_ADDRSTRLEN
from errno:
- errno
from time:
- struct tm
- typedef time_t

### alur program
alur programnya saat ini:
- Jika domain nya `AF_INET` or `AF_INET6` maka register `sockfd` setiap kali fungsi `socket` dipanggil untuk di-watch dan di-log.
- jika first bytes `buffer` pada first call `send` tidak identik dengan HTTP protocol, un-watch `sockfd` nya
- parameter `buffer` data pada `send`, `recv`, `read` dan `write` yang terkait dengan `sockfd` yang di-watch akan ditampung untuk nantinya di-parse
- setiap berhasil melakukan parsing pada buffer send/write masukkan hasil parse kedalam queue untuk nantinya di-dequeue
- setiap berasil melakukan parsing pada buffer recv/read, cocokkan dengan buffer yang ada pada send/write dengan melakukan dequeue dan tulis log yang sudah terformat kedalam file

karena kita tidak dapat mengendalikan atau menebak berapa bytes buffer yang akan kita proses, maka hal yang pertama dilakukan adalah menampungnya terlebih dahulu

dan sembari menampung, kita mencoba me-locate atau menentukan awal dan akhir data header HTTP:
- untuk mengetahui awal-nya dapat diidentifikasi melalui HTTP method
- sementara untuk mengetahui akhirnya dapat diidentifikasi melalui double linebreak (\r\n\r\n atau CRLF CRLF)

jika sudah dapat ditentukan awal dan akhir nya, maka lanjut ke proses parsing
setelah parsing selesai dilakukan dan dipastikan tidak ada masalah, baru tulis kedalam log
lalu gantikan tampungannya dengan data yang baru

skenario tertentu yang saat ini dapat ditangani:
- fitur HTTP pipeline
- re-use existing socket, HTTP keep-alive (?)
- short recv dan partial send
- transfer encoding chunked
- websocket switch protocol

additional note:
- `recvfrom` dan `sendto` digunakan untuk jaga-jaga jika ada program yang langsung call ke situ dan gak ke-catch di `send` ataupun `recv`
- intercept `read` dan `write` juga karena program seperti `nc` menggunakan syscall tersebut untuk mengirim dan menerima paket 


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
---

queue abstract data type is used to support re-use existing socket for multiple HTTP request
---

to support HTTP pipeline, I need to instruct the program to looking for possible additional HTTP request by scan the entire sendto/write buffer
---

from MDN page https://developer.mozilla.org/en-US/docs/Glossary/Head_of_line_blocking:
> In HTTP/1.1, HOL blocking can occur when a client sends multiple requests to a server without waiting for the responses. The server processes the requests in order, but if the response to the first request is delayed, the responses to subsequent requests are also delayed. HTTP/2 addresses this issue through request multiplexing, eliminating HOL blocking in the application layer, but it still exists at the transport (TCP) layer.

HTTP pipeline feature is improved in HTTP/2 (?)

see also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Connection_management_in_HTTP_1.x
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

---
some 'unwanted' socket file descriptor still accidently registered on context, so we need to unwatch it if any
my gdb session shows it only perform socket() -> close() sequence
