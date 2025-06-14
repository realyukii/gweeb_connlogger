#include <arpa/inet.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 0
#endif
#define VERBOSE 3
#define DEBUG 2
#define FOCUS 1
#define DEFAULT_REQ_QUEUE_SZ 11000
#define DEFAULT_POOL_SZ 100
#define DEFAULT_RAW_CAP 1024
#define MAX_HTTP_METHOD_LEN 8
#define MAX_HTTP_VER_LEN 8
#define MAX_HOST_LEN 512
#define MAX_INSANE_URI_LENGTH 300000

#define pr_debug(lvl, fmt, ...)				\
do {							\
	if (DEBUG_LEVEL >= (lvl)) {			\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	}						\
} while (0)

struct http_req_queue {
	struct http_req *head;
	struct http_req *tail;
};

typedef enum {
	HTTP_REQ_INIT = 0,
	HTTP_REQ_LINE,
	HTTP_REQ_HDR,
	HTTP_REQ_HDR_DONE,
	HTTP_REQ_BODY,
	HTTP_RES_LINE = 0,
	HTTP_RES_HDR,
	HTTP_RES_HDR_DONE,
	HTTP_RES_BODY,
} parser_state;

enum chunk_state {
	CHK_BEGIN,
	CHK_CONTENT
};

struct http_body {
	/* indicate the trafer-encoding is chunked */
	bool is_chunked;
	/* a body's content length */
	size_t content_length;
	size_t chk_sz;
	enum chunk_state s;
};

struct http_hdr {
	char *key;
	char *value;
};

struct http_hdrs {
	struct http_hdr *hdr;
	size_t nr_hdr;
};

struct http_res {
	/* response status code */
	char status_code[4];
	/* parsing context of response header */
	struct http_hdrs hdr_list;
	struct http_body body;
};

enum HTTP_METHODS {
	HTTP_GET,
	HTTP_POST,
	HTTP_HEAD,
	HTTP_PATCH,
	HTTP_PUT,
	HTTP_DELETE,
	HTTP_OPTIONS,
	HTTP_CONNECT,
	HTTP_TRACE,
	HTTP_UNKNOWN
};

struct http_method {
	const char *name;
	size_t len;
	enum HTTP_METHODS id;
};

static const struct http_method methods[] = {
	{ "GET",	3,	HTTP_GET },
	{ "POST",	4,	HTTP_POST },
	{ "HEAD",	4,	HTTP_HEAD },
	{ "PATCH",	5,	HTTP_PATCH },
	{ "PUT",	3,	HTTP_PUT },
	{ "DELETE",	6,	HTTP_DELETE},
	{ "OPTIONS",	7,	HTTP_OPTIONS },
	{ "CONNECT",	7,	HTTP_CONNECT },
	{ "TRACE",	5,	HTTP_TRACE }
};

struct http_req {
	/* http method */
	enum HTTP_METHODS method;
	/* host name */
	char host[MAX_HOST_LEN];
	/* a pointer to the malloc'ed buffer */
	char *uri;
	/* parsing context of request header */
	struct http_hdrs hdr_list;
	struct http_body body;
	/* corresponding response  */
	struct http_res res;
	/* a pointer to next http_req on the list */
	struct http_req *next;
};

struct concated_buf {
	/* concated buffer */
	char *raw_bytes;
	/* current length of buffer*/
	size_t len;
	/* offset of processed buffer */
	size_t off;
	/* the capacity it can hold */
	size_t cap;
};

typedef struct concated_buf http_req_raw;
typedef struct concated_buf http_res_raw;

struct http_ctx {
	int sockfd;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port_addr;
	struct http_req_queue req_queue;
	http_req_raw raw_req;
	http_res_raw raw_res;
	parser_state req_state;
	parser_state res_state;
};

static size_t current_pool_sz = DEFAULT_POOL_SZ;
static size_t occupied_pool = 0;
static struct http_ctx *ctx_pool = NULL;
static FILE *file_log = NULL;
static const char http_ver[] = "HTTP/1.";

static struct http_req *allocate_req(void)
{
	struct http_req *r = calloc(1, sizeof(*r));

	return r;
}

static void enqueue(struct http_req_queue *q, struct http_req *r)
{
	if (!q->head)
		/* initialize empty queue */
		q->tail = q->head = r;
	else {
		/* grow the queue */
		q->tail->next = r;
		q->tail = r;
	}
}

static void dequeue(struct http_req_queue *q)
{
	struct http_req *r = q->head;
	
	/* queue is empty */
	if (!r)
		return;

	q->head = q->head->next;
	if (!q->head)
		q->tail = NULL;

	if (r->uri) {
		pr_debug(VERBOSE, "URI will be freed: %p\n", r->uri);
		free(r->uri);
	}

	for (size_t i = 0; i < r->hdr_list.nr_hdr; i++) {
		struct http_hdr *h = &r->hdr_list.hdr[i];
		free(h->key);
		free(h->value);
	}
	free(r->hdr_list.hdr);

	for (size_t i = 0; i < r->res.hdr_list.nr_hdr; i++) {
		struct http_hdr *h = &r->res.hdr_list.hdr[i];
		free(h->key);
		free(h->value);
	}
	free(r->res.hdr_list.hdr);

	free(r);
}

static void generate_current_time(char *buf)
{
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	/*
	* the manual says atleast 26 bytes of buf is provided
	* 24 ascii character + newline + null terminated bytes
	*/
	asctime_r(timeinfo, buf);
	buf[26 - 2] = '\0';
}

static void write_log(struct http_ctx *h, struct http_req *req)
{
	char human_readable_time[26] = {0};
	generate_current_time(human_readable_time);

	int ret = fprintf(
		file_log,
		"[%s]|%s:%d|Host: %s|Method: %s|URI %s|Status: %s\n",
		human_readable_time,
		h->ip_addr, h->port_addr,
		req->host, methods[req->method].name, req->uri, req->res.status_code
	);

	if (ret < 0) {
		pr_debug(DEBUG, "failed to write parsed data to the file\n");
	} else {
		pr_debug(DEBUG, "parsed data successfully written to the file\n");
	}
}

static int init(void)
{
	/* already initialised, skip duplicate init, exit. */
	if (file_log != NULL && ctx_pool != NULL)
		return 0;

	const char *log_file = getenv("GWLOG_PATH");

	/* do not init if there's no destination for parsed data to write */
	if (log_file == NULL) {
		pr_debug(DEBUG, "no file path provided in GWLOG_PATH env\n");
		return -1;
	}

	file_log = fopen(log_file, "a");
	if (file_log == NULL) {
		pr_debug(DEBUG, "failed to open file %s\n", log_file);
		return -1;
	}

	setvbuf(file_log, NULL, _IOLBF, 0);
	ctx_pool = calloc(DEFAULT_POOL_SZ, sizeof(struct http_ctx));
	if (ctx_pool == NULL) {
		pr_debug(DEBUG, "fail to allocate dynamic memory\n");
		return -1;
	}

	pr_debug(
		DEBUG,
		"init the pool context and file handle for the first time\n"
	);
	pr_debug(VERBOSE, "allocated address of context pool: %p\n", ctx_pool);
	return 0;
}

static void advance(struct concated_buf *ptr, size_t len)
{
	size_t overall_len = ptr->len;
	if (len > ptr->len)
		ptr->len = 0;
	else
		ptr->len -= len;

	if (ptr->len > 0) {
		memmove(ptr->raw_bytes, ptr->raw_bytes + len, ptr->len);
		ptr->raw_bytes[ptr->len] = '\0';
	} else
		memset(ptr->raw_bytes, 0, overall_len);
}

static void push_sockfd(int sockfd)
{
	struct http_ctx **_c = &ctx_pool;
	struct http_ctx *c = *_c;
	if (occupied_pool == current_pool_sz) {
		void *tmp = realloc(c, current_pool_sz * 2);
		if (tmp == NULL)
			return;
		
		*_c = tmp;
		pr_debug(
			VERBOSE,
			"new address is allocated for context pool: %p\n",
			ctx_pool
		);
	}

	for (size_t i = 0; i < current_pool_sz; i++) {
		if (c[i].sockfd != 0)
			continue;

		c[i].raw_req.raw_bytes = calloc(1, DEFAULT_RAW_CAP + 1);
		c[i].raw_res.raw_bytes = calloc(1, DEFAULT_RAW_CAP + 1);
		/*
		* do not push current connection to the pool
		* if we fail to allocate some memory
		*/
		if (c[i].raw_req.raw_bytes == NULL || c[i].raw_res.raw_bytes == NULL) {
			void *to_free = (c[i].raw_req.raw_bytes != NULL)
				? c[i].raw_req.raw_bytes
				: c[i].raw_res.raw_bytes;

			/* if both null, it is still safe to call free */
			free(to_free);
			break;
		}

		pr_debug(
			VERBOSE,
			"init queue for sockfd %d\n",
			sockfd
		);

		pr_debug(
			DEBUG,
			"new sockfd %d is registered to the pool\n",
			sockfd
		);
		c[i].sockfd = sockfd;
		c[i].raw_req.cap = DEFAULT_RAW_CAP;
		c[i].raw_res.cap = DEFAULT_RAW_CAP;

		occupied_pool++;
		break;
	}
}

static void unwatch_sockfd(struct http_ctx *h, char *reason)
{
	pr_debug(
		FOCUS,
		"sockfd %d (%s) is unregistered from the pool: %s\n",
		h->sockfd, h->ip_addr, reason
	);
	h->sockfd = 0;

	pr_debug(
		VERBOSE,
		"raw_req.raw_bytes will be freed: %p\n",
		h->raw_res.raw_bytes
	);
	free(h->raw_req.raw_bytes);

	pr_debug(
		VERBOSE,
		"raw_res.raw_bytes will be freed: %p\n",
		h->raw_res.raw_bytes
	);
	free(h->raw_res.raw_bytes);
	while (h->req_queue.head)
		dequeue(&h->req_queue);

	occupied_pool--;
}

static int concat_buf(const void *src, struct concated_buf *buf, size_t len)
{
	size_t *append_pos = &buf->len;
	size_t incoming_len = *append_pos + len + 1;
	char **b = &buf->raw_bytes;

	if (incoming_len <= buf->cap) {
		memcpy(*b + *append_pos, src, len);
		*append_pos += len;
	} else {
		/* we don't have enough space in the memory, let's resize it */
		void *tmp = realloc(*b, buf->cap + incoming_len);
		if (tmp == NULL) {
			return -1;
		}
		*b = tmp;
		memcpy(*b + *append_pos, src, len);
		*append_pos += len;
		buf->cap += incoming_len;
		pr_debug(
			VERBOSE,
			"new address is allocated for concated buffer: %p\n",
			buf->raw_bytes
		);
	}
	(*b)[buf->len] = '\0';

	return 0;
}

static size_t low_len(size_t a, size_t b)
{
	return a < b ? a : b;
}

/*
* read more on what is considered as white space defined by RFC in stackoverflow:
* https://stackoverflow.com/q/50179659/22382954
*/
static bool is_whitespace(char c)
{
	return c == ' ' || c == '\t';
}

/*
* read more on what are visible ascii character defined by RFC in stackoverflow:
* https://stackoverflow.com/q/52336695/22382954
*/
static bool is_vchar(char c)
{
	return c >= 0x21 && c <= 0x7E;
}

static struct http_ctx *find_http_ctx(int sockfd)
{
	/*
	* do not perform lookup if the fd is stdin or stdout
	* prevent false-positive when dealing with program like nc
	* save some cpu cycle by stop executing subsequent instruction
	* and early exit
	*/
	if (sockfd == STDIN_FILENO || sockfd == STDOUT_FILENO)
		return NULL;

	/*
	* we are not allowed to assume ctx_pool to always be valid
	* one of the concrete example is when find_http_ctx is called
	* from close() and the init is not called yet
	*/
	if (ctx_pool == NULL)
		return NULL;

	struct http_ctx *h = NULL;
	for (size_t i = 0; i < current_pool_sz; i++)
	{
		if (ctx_pool[i].sockfd != sockfd)
			continue;

		h = &ctx_pool[i];
		break;
	}
	
	return h;
}

/* the function only accept string with base 16 ascii-hex */
static size_t strntol(char *p, size_t len)
{
	size_t acc, off;

	off = acc = 0;
	while (off < len) {
		unsigned digit;
		char c = p[off];

		if (c >= '0' && c <= '9')
			digit = c - '0';
		else if (c >= 'a' && c <= 'f')
			digit = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			digit = c - 'A'  + 10;
		else break;

		acc = acc * 16 + digit;
		off++;
	}

	return acc;
}

static int parse_bdy_chk(struct http_body *b, struct concated_buf *raw_buf,
			size_t len)
{
	size_t off;
	char *buf, *p;
	off = 0;
	buf = &raw_buf->raw_bytes[raw_buf->off];
	while (true) {
		p = NULL;

		if (b->s == CHK_BEGIN)
			while (true) {
				if (off + 1 >= len) {
					return -EAGAIN;
				}

				if (buf[off] == ';')
					p = &buf[off];

				if (buf[off] == '\r' && buf[off + 1] == '\n') {
					size_t chk_len;
					if (!p)
						p = &buf[off];
					
					chk_len = p - buf;
					b->chk_sz = strntol(buf, chk_len);

					off += 2;
					raw_buf->off += off;
					buf = &raw_buf->raw_bytes[raw_buf->off];
					off = 0;
					b->s = CHK_CONTENT;
					break;
				}

				off++;
			}

		if (b->chk_sz == 0) {
			if (off + 1 >= len) {
				return -EAGAIN;
			}

			if (buf[off] == '\r' && buf[off + 1] == '\n') {
				off += 2;

				raw_buf->off += off;
				return 0;
			}

			pr_debug(FOCUS, "malformed chunked body\n");
			return -EINVAL;
		}

		while (true) {
			off += b->chk_sz;
			if (off + 1 >= len) {
				return -EAGAIN;
			}

			if (buf[off] == '\r' && buf[off + 1] == '\n') {
				off += 2;

				raw_buf->off += off;
				buf = &raw_buf->raw_bytes[raw_buf->off];
				off = 0;
				b->s = CHK_BEGIN;
				break;
			}

			pr_debug(FOCUS, "invalid chunk len\n");
			return -EINVAL;
		}
	}
}

static int parse_req_line(struct http_req *r, http_req_raw *raw_buf)
{
	enum HTTP_METHODS m;
	const char *uri, *buf = raw_buf->raw_bytes + raw_buf->off;
	size_t uri_len, len, nr_m, off;

	/* offset */
	off = 0;
	/* length of unparsed bytes */
	len = raw_buf->len - raw_buf->off;
	/* number of methods */
	nr_m = sizeof(methods) / sizeof(methods[0]);

	m = HTTP_UNKNOWN;
	for (size_t i = 0; i < nr_m; i++) {
		const struct http_method method = methods[i];
		size_t cmplen, mlen = method.len;

		cmplen = low_len(mlen, len);
		/* non-zero value indicate mismatch, cont to next method */
		if (memcmp(buf, method.name, cmplen))
			continue;

		/* need more bytes to confirm if it's actually HTTP method */
		if (cmplen < mlen)
			return -EAGAIN;

		/* now, the method is matched */
		m = method.id;
		off += mlen;
		break;
	}

	if (m == HTTP_UNKNOWN) {
		pr_debug(FOCUS, "Method Unknown\n");
		return -EINVAL;
	}
	r->method = m;

	/*
	* very rare scenario but still possible
	* where the buffer is shorted 1 byte
	*/
	if (off >= len)
		return -EAGAIN;

	if (!is_whitespace(buf[off])) {
		pr_debug(FOCUS, "Expect a whitespace char\n");
		return -EINVAL;
	}

	/* if the next char is not a slash or wildcard treat it as malformed */
	off += 1;
	
	/*
	* very rare scenario but still possible
	* where the buffer is shorted 1 byte
	*/
	if (off >= len)
		return -EAGAIN;

	if (m != HTTP_CONNECT && m != HTTP_OPTIONS) {
		if (buf[off] != '/') {
			pr_debug(FOCUS, "Expect a slash char\n");
			return -EINVAL;
		}
	} else {
		if (buf[off] != '*' || buf[off] != '/') {
			pr_debug(FOCUS, "Expect a wildcard or slash char\n");
			return -EINVAL;
		}
	}

	uri_len = 0;
	uri = &buf[off];
	while(true) {
		if (off >= len)
			return -EAGAIN;
		
		if (is_whitespace(buf[off])) {
			off += 1;
			break;
		}

		if (!is_vchar(buf[off])) {
			pr_debug(FOCUS, "Not a visible character\n");
			return -EINVAL;
		}
		off++;
		uri_len++;
	}

	if (!r->uri)
		r->uri = malloc(uri_len + 1);
	if (!r->uri) {
		pr_debug(FOCUS, "not enough memory\n");
		return -ENOMEM;
	}
	memcpy(r->uri, uri, uri_len);
	r->uri[uri_len] = '\0';

	if (off + 7 >= len)
		return -EAGAIN;

	if (memcmp(&buf[off], http_ver, 7)) {
		pr_debug(FOCUS, "Expect HTTP/1.x version\n");
		return -EINVAL;
	}

	off += 7;
	/* only support HTTP/1.1 and HTTP/1.0 */
	if (buf[off] != '0' && buf[off] != '1') {
		pr_debug(FOCUS, "Invalid HTTP version\n");
		return -EINVAL;
	}

	if (off + 2 >= len)
		return -EAGAIN;
	off += 1;

	if (memcmp(&buf[off], "\r\n", 2)) {
		pr_debug(FOCUS, "Expect a line break after req line");
		return -EINVAL;
	}

	off += 2;
	raw_buf->off += off;
	return 0;
}

static int add_hdr(struct http_hdrs *h, char *k, char *v, size_t kl, size_t vl)
{
	char *kp, *vp;
	struct http_hdr *hdr, *tmp_hdr;

	if (!h->hdr) {
		h->hdr = malloc(sizeof(*h->hdr) * 1);
		if (!h->hdr)
			return -ENOMEM;
	}

	if (h->nr_hdr > 0) {
		tmp_hdr = realloc(h->hdr, sizeof(*tmp_hdr) * (h->nr_hdr + 1));
		if (!tmp_hdr) {
			free(h->hdr);
			return -ENOMEM;
		}
		h->hdr = tmp_hdr;
	}

	hdr = &h->hdr[h->nr_hdr];

	kp = malloc(kl + 1);
	if (!kp)
		return -ENOMEM;
	
	vp = malloc(vl + 1);
	if (!vp)
		return -ENOMEM;

	memcpy(kp, k, kl);
	kp[kl] = '\0';

	memcpy(vp, v, vl);
	vp[vl] = '\0';

	hdr->key = kp;
	hdr->value = vp;
	h->nr_hdr++;
	
	return 0;
}

static int parse_hdr(struct http_hdrs *h, struct concated_buf *raw_buf)
{
	char *buf = &raw_buf->raw_bytes[raw_buf->off];
	size_t len, off;

	len = raw_buf->len - raw_buf->off;
	if (!len)
		return -EAGAIN;

	off = 0;
	while (true) {
		int ret;
		char *key, *value, *tmp;
		size_t key_len, val_len;

		key = &buf[off];
		key_len = 0;

		if (off + 1 >= len)
			return -EAGAIN;

		/* looking for end of header signal */
		if (memcmp(&buf[off], "\r\n", 2) == 0) {
			off += 2;
			raw_buf->off += off;
			break;
		}

		/* parsing key of http header */
		while (true) {
			if (off >= len)
				return -EAGAIN;

			if (buf[off] == ':') {
				off += 1;
				break;
			}
			
			off++;
			key_len++;
		}

		value = &buf[off];
		val_len = 0;
		/* parsing value of http header */
		while (true) {
			if (off >= len)
				return -EAGAIN;

			if (buf[off] == '\r' || buf[off] == '\n')
				break;

			val_len++;
			off++;
		}

		if (buf[off] == '\r') {
			if (++off >= len)
				return -EAGAIN;
		}

		if (buf[off] != '\n') {
			pr_debug(FOCUS, "missing LF after CR\n");
			return -EINVAL;
		}
		off += 1;

		while (is_whitespace(*key)) {
			key_len--;
			key++;
		}
		
		while (is_whitespace(*value)) {
			val_len--;
			value++;
		}
		
		tmp = &key[key_len - 1];
		while (is_whitespace(*tmp)) {
			key_len--;
			tmp--;
		}

		tmp = &value[val_len - 1];
		while (is_whitespace(*tmp)) {
			val_len--;
			tmp--;
		}

		/* add the parsed key-value pair to the list */
		ret = add_hdr(h, key, value, key_len, val_len);
		if (ret == -ENOMEM)
			pr_debug(FOCUS, "not enough memory\n");
		if (ret < 0)
			return -EINVAL;
	}

	return 0;
}

static int check_req_hdr(struct http_req *q)
{
	for (size_t i = 0; i < q->hdr_list.nr_hdr; i++) {
		struct http_hdr *h = &q->hdr_list.hdr[i];
		if (strcasecmp(h->key, "host") == 0) {
			strcpy(q->host, h->value);
		} else if (strcasecmp(h->key, "content-length") == 0) {
			if (q->body.is_chunked)
				return -EINVAL;

			q->body.content_length = atol(h->value);
		} else if (strcasecmp(h->key, "transfer-encoding") == 0) {
			if (q->body.content_length > 0)
				return -EINVAL;

			char *p = strstr(h->value, "chunked");
			if (p)
				q->body.is_chunked = true;
		}
	}

	return 0;
}

static int parse_bdy(struct http_body *b, struct concated_buf *raw_buf)
{
	size_t len;

	len = raw_buf->len - raw_buf->off;
	if (b->is_chunked) {
		int ret = parse_bdy_chk(b, raw_buf, len);
		if (ret < 0)
			return ret;
	} else {
		/*
		* TODO handle malformed request/response
		* what if content length exists but no body sent?
		* or the amount of body send is not
		* proportional with content_length?
		*/
		if (len < b->content_length)
			return -EAGAIN;

		raw_buf->off += b->content_length;
	}

	return 0;
}

static void handle_parse_localbuf(int fd, const void *buf, int buf_len)
{
	struct http_req *r;
	struct http_ctx *h;
	http_req_raw *raw;
	int ret;

	h = find_http_ctx(fd);
	if (h == NULL)
		return;
	raw = &h->raw_req;
	r = h->req_queue.tail;

	concat_buf(buf, raw, buf_len);

	while (raw->len) {
		if (h->req_state == HTTP_REQ_INIT) {
			r = allocate_req();
			if (!r) {
				pr_debug(
					FOCUS,
					"failed to allocate mem for req\n"
				);
				goto drop_sockfd;
			}

			enqueue(&h->req_queue, r);
			pr_debug(VERBOSE, "queue a new request\n");
			h->req_state = HTTP_REQ_LINE;
		}

		if (h->req_state == HTTP_REQ_LINE) {
			pr_debug(VERBOSE, "parsing request line\n");
			ret = parse_req_line(r, raw);
			if (ret == -EINVAL)
				goto drop_sockfd;
			else if (ret == -EAGAIN)
				return;
			h->req_state = HTTP_REQ_HDR;
		}

		if (h->req_state == HTTP_REQ_HDR) {
			pr_debug(VERBOSE, "parsing request header\n");
			ret = parse_hdr(&r->hdr_list, raw);
			if (ret == -EAGAIN)
				return;
			if (ret < 0)
				goto drop_sockfd;

			h->req_state = HTTP_REQ_HDR_DONE;
		}

		if (h->req_state == HTTP_REQ_HDR_DONE) {
			pr_debug(VERBOSE, "checking request header\n");
			ret = check_req_hdr(r);
			if (ret < 0)
				goto drop_sockfd;

			if (r->body.is_chunked || r->body.content_length > 0) {
				/*
				* don't be fooled,
				* ignore the body when these methods is used
				*/
				if (strcmp(methods[r->method].name, "GET")
				&& strcmp(methods[r->method].name, "HEAD"))
					h->req_state = HTTP_REQ_BODY;
			} else {
				advance(raw, raw->off);
				raw->off = 0;
				h->req_state = HTTP_REQ_INIT;
			}
		}

		if (h->req_state == HTTP_REQ_BODY) {
			pr_debug(VERBOSE, "parsing request body\n");
			ret = parse_bdy(&r->body, raw);
			if (ret == -EAGAIN)
				return;
			if (ret < 0)
				goto drop_sockfd;

			advance(raw, raw->off);
			raw->off = 0;
			h->req_state = HTTP_REQ_INIT;
		}
	}

	return;
drop_sockfd:
	unwatch_sockfd(h, "failed to parse local buffer");
}

static int parse_res_line(struct http_req *r, http_res_raw *raw_buf)
{
	char *buf;
	size_t off, len;

	len = raw_buf->len;
	off = 0;
	buf = raw_buf->raw_bytes;

	if (off + 7 >= len)
		return -EAGAIN;
	
	if (memcmp(buf, http_ver, 7)) {
		pr_debug(DEBUG, "probably not a HTTP packet\n");
		return -EINVAL;
	}
	off += 7;

	/* only support HTTP/1.1 and HTTP/1.0 */
	if (buf[off] != '0' && buf[off] != '1') {
		pr_debug(FOCUS, "Invalid HTTP version\n");
		return -EINVAL;
	}
	off++;

	if (off + 5 >= len)
		return -EAGAIN;

	off += 1;
	memcpy(r->res.status_code, &buf[off], 3);
	off += 3 + 1;

	while (true) {
		if (off + 1 >= len)
			return -EAGAIN;

		if (buf[off] == '\r')
			break;
		off++;
	}

	if (memcmp(&buf[off], "\r\n", 2)) {
		pr_debug(FOCUS, "Expect a line break after req line");
		return -EINVAL;
	}
	off += 2;

	raw_buf->off += off;	
	return 0;
}

static int check_res_hdr(struct http_res *r)
{
	for (size_t i = 0; i < r->hdr_list.nr_hdr; i++) {
		struct http_hdr *h = &r->hdr_list.hdr[i];
		if (strcasecmp(h->key, "content-length") == 0) {
			if (r->body.is_chunked)
				return -EINVAL;

			r->body.content_length = atol(h->value);
		} else if (strcasecmp(h->key, "transfer-encoding") == 0) {
			if (r->body.content_length > 0)
				return -EINVAL;

			char *p = strstr(h->value, "chunked");
			if (p)
				r->body.is_chunked = true;
		}
	}

	return 0;
}

static void handle_parse_remotebuf(int fd, const void *buf, int buf_len)
{
	struct http_req *r;
	struct http_ctx *h;
	http_res_raw *raw;
	int ret;

	h = find_http_ctx(fd);
	if (h == NULL)
		return;
	
	raw = &h->raw_res;

	concat_buf(buf, raw, buf_len);

	while (raw->len) {
		r = h->req_queue.head;
		if (!r) {
			pr_debug(FOCUS, "req queue is empty\n");
			goto drop_sockfd;
		}

		if (h->res_state == HTTP_RES_LINE) {
			pr_debug(VERBOSE, "parsing response line\n");
			ret = parse_res_line(r, raw);
			if (ret == -EAGAIN)
				return;
			if (ret < 0)
				goto drop_sockfd;

			h->res_state = HTTP_RES_HDR;
		}

		if (h->res_state == HTTP_RES_HDR) {
			pr_debug(VERBOSE, "parsing response header\n");
			ret = parse_hdr(&r->res.hdr_list, raw);
			if (ret == -EAGAIN)
				return;
			if (ret < 0)
				goto drop_sockfd;

			h->res_state = HTTP_RES_HDR_DONE;
		}

		if (h->res_state == HTTP_RES_HDR_DONE) {
			pr_debug(VERBOSE, "checking response header\n");
			ret = check_res_hdr(&r->res);
			if (ret < 0)
				goto drop_sockfd;

			if (r->res.body.is_chunked ||
				r->res.body.content_length > 0) {
				/*
				* don't be fooled,
				* ignore the body when HEAD method is used
				*/
				if (strcmp(methods[r->method].name, "HEAD"))
					h->res_state = HTTP_RES_BODY;
			} else {
				write_log(h, r);
				dequeue(&h->req_queue);
				pr_debug(VERBOSE, "dequeue request\n");
				advance(raw, raw->off);
				raw->off = 0;
				h->res_state = HTTP_RES_LINE;
			}
		}

		if (h->res_state == HTTP_RES_BODY) {
			pr_debug(VERBOSE, "parsing response body\n");
			ret = parse_bdy(&r->res.body, raw);
			if (ret == -EAGAIN)
				return;
			if (ret < 0)
				goto drop_sockfd;

			write_log(h, r);
			dequeue(&h->req_queue);
			pr_debug(VERBOSE, "dequeue request\n");
			advance(raw, raw->off);
			raw->off = 0;
			h->res_state = HTTP_RES_LINE;
		}

	}

	return;
drop_sockfd:
	unwatch_sockfd(h, "failed to parse remote buffer");
}

static void fill_address(struct http_ctx *h, const struct sockaddr *addr)
{
	struct sockaddr_in *in = (void *)addr;
	struct sockaddr_in6 *in6 = (void *)addr;

	switch (addr->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &in->sin_addr, h->ip_addr, INET_ADDRSTRLEN);
		h->port_addr = ntohs(in->sin_port);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &in6->sin6_addr, h->ip_addr, INET6_ADDRSTRLEN);
		h->port_addr = ntohs(in6->sin6_port);
		break;
	}

	pr_debug(
		DEBUG,
		"sockfd %d with domain %d is connected to %s:%d\n",
		h->sockfd,
		(int)addr->sa_family,
		h->ip_addr,
		h->port_addr
	);
}

int socket(int domain, int type, int protocol)
{
	int ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket),	/* %rax */
		  "D" (domain),		/* %rdi */
		  "S" (type),		/* %rsi */
		  "d" (protocol)	/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	if (domain != AF_INET && domain != AF_INET6)
		return ret;

	if (!(type & SOCK_STREAM))
		return ret;

	if (init() == 0)
		push_sockfd(ret);
	else
		pr_debug(
			VERBOSE,
			"failed to push sockfd %d with domain %d\n",
			ret, domain
		);

	return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_connect),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (addr),		/* %rsi */
		  "d" (addrlen)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	if (ctx_pool == NULL)
		return ret;

	struct http_ctx *h = find_http_ctx(sockfd);
	if (h == NULL)
		return ret;

	fill_address(h, addr);

	return ret;
}

ssize_t recvfrom(
	int sockfd, void *buf, size_t size, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
{
	register int _f asm("r10") = flags;
	register struct sockaddr *_s asm("r8") = src_addr;
	register socklen_t *_a asm("r9") = addrlen;
	ssize_t ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (size),		/* %rdx */
		  "r" (_f),		/* %r10 */
		  "r" (_s),		/* %r8 */
		  "r" (_a)		/* %r9 */
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	handle_parse_remotebuf(sockfd, buf, ret);

	return ret;
}

ssize_t sendto(
	int sockfd, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t addrlen)
{
	register int _f asm("r10") = flags;
	register const struct sockaddr *_d asm("r8") = dst_addr;
	register socklen_t _a asm("r9") = addrlen;
	ssize_t ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto),	/* %rax */
		  "D" (sockfd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (size),		/* %rdx */
		  "r" (_f),		/* %r10 */
		  "r" (_d),		/* %r8 */
		  "r" (_a)		/* %r9 */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	handle_parse_localbuf(sockfd, buf, ret);

	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t size, int flags)
{
	return recvfrom(sockfd, buf, size, flags, NULL, NULL);
}

ssize_t send(int sockfd, const void *buf, size_t size, int flags)
{
	return sendto(sockfd, buf, size, flags, NULL, 0);
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret;
	
	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_read),	/* %rax */
		  "D" (fd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (count)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	handle_parse_remotebuf(fd, buf, ret);

	return ret;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_write),	/* %rax */
		  "D" (fd),		/* %rdi */
		  "S" (buf),		/* %rsi */
		  "d" (count)		/* %rdx */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
		return ret;
	}

	handle_parse_localbuf(fd, buf, ret);

	return ret;
}

int close(int fd)
{
	int ret;

	asm volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_close),	/* %rax */
		  "D" (fd)		/* %rdi */
		: "memory", "rcx", "r11", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	struct http_ctx *h = find_http_ctx(fd);
	if (h != NULL)
		unwatch_sockfd(h, "after closing the sockfd");

	return ret;
}
