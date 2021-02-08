#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>

#define ABORT(ctx, expr, fmt, ...) \
do { \
	if (expr) { \
		ctx->errno = 1; \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
		exit(0); \
	} \
} while (0)

#define PAGE_SIZE 4096

enum pt_event_kind {
	PT_EVENT_NONE,
	PT_EVENT_CALL,
	PT_EVENT_RET,
	PT_EVENT_XBEGIN,
	PT_EVENT_XCOMMIT,
	PT_EVENT_XABORT,
};

struct pt_event {
	unsigned long addr:48;
	unsigned long kind:16;
};

#define MAGIC 0x51C0FFEE
#define VERSION 1

struct pt_logfile_header {
	unsigned int magic;
	unsigned int version;
};

enum pt_logitem_kind {
	PT_LOGITEM_BUFFER,
	PT_LOGITEM_PROCESS,
	PT_LOGITEM_THREAD,
	PT_LOGITEM_IMAGE,
	PT_LOGITEM_XPAGE,
	PT_LOGITEM_UNMAP,
	PT_LOGITEM_FORK,
	PT_LOGITEM_SECTION,
	PT_LOGITEM_THREAD_END,
};

struct pt_logitem_header {
	enum pt_logitem_kind kind;
	unsigned int size;
};

struct pt_logitem_buffer {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long pid;
	unsigned long sequence;
	unsigned long size;
};

struct pt_logitem_process {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long cmd_size;
};

struct pt_logitem_thread {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long pid;
};

struct pt_logitem_image {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
	unsigned int size;
	unsigned int timestamp;
	unsigned long image_name_length;
};

struct pt_logitem_xpage {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
	unsigned long size;
};

struct pt_logitem_unmap {
	struct pt_logitem_header header;
	unsigned long tgid;
	unsigned long base;
};

struct pt_logitem_fork {
	struct pt_logitem_header header;
	unsigned long parent_tgid;
	unsigned long parent_pid;
	unsigned long child_tgid;
	unsigned long child_pid;
};

#define PID_SPACE 0xffff
struct stack {
	void *top;
	struct pt_event *sp;
	struct pt_event *xbegin;
};

#define MIRROR_DISTANCE 0x010000000000
#define MIRROR(addr, level) (((addr) + (level) * MIRROR_DISTANCE) & 0x7fffffffffff)

#define PT_IP_TO_CODE(addr) MIRROR(addr, 1)
#define PT_IP_TO_BLOCK(addr) MIRROR((addr) & ~0x7, ((addr) & 0x7) + 2)

#define MAP_SIZE (1 << 16)
#define HASH_CONST 0xa5b35705

#define MAX_IMAGES 256
struct image_map {
	unsigned int id;
	unsigned long start_va;
	unsigned long end_va;
};

struct pt_recover_ctx {
	unsigned char errno;
	unsigned short pid;
	unsigned long prev_block_addr;
	struct stack stacks[PID_SPACE];
	unsigned char hashmap[MAP_SIZE];
	struct image_map images[MAX_IMAGES];
	char log_abspath[PATH_MAX];
};

typedef struct pt_recover_ctx *pt_recover_arg;

#define pt_on_call(addr, ctx) do { \
	*(ctx->stacks[ctx->pid].sp--) = (struct pt_event) {addr, PT_EVENT_CALL}; \
} while (0)

#define pt_on_icall(addr, ctx)

#define pt_on_mode(mode_payload, ctx)

#define pt_on_syscall(addr)

static inline void pt_on_ret(unsigned long addr, pt_recover_arg ctx)
{
	struct pt_event *sp;
	struct stack *stacks = ctx->stacks;
	unsigned short pid = ctx->pid;

	/* ignore sigreturn */
	if (*(unsigned long *)(PT_IP_TO_CODE(addr)) == 0x0f0000000fc0c748 &&
			*(unsigned char *)(PT_IP_TO_CODE(addr) + 8) == 0x05)
		return;

	for (sp = stacks[pid].sp + 1; ; sp++) {
		if (sp->kind != PT_EVENT_CALL) {
			*(sp - 1) = (struct pt_event) {addr, PT_EVENT_RET};
			stacks[pid].sp = sp - 2;
			return;
		}

		if (sp->addr == addr) {
			stacks[pid].sp = sp;
			return;
		}
	}
}

static inline void pt_on_xbegin(pt_recover_arg ctx)
{
	unsigned short pid = ctx->pid;
	struct stack *stacks = ctx->stacks;

	if (!stacks[pid].xbegin) {
		*(stacks[pid].sp--) = (struct pt_event) {0, PT_EVENT_XBEGIN};
		stacks[pid].xbegin = stacks[pid].sp + 1;
	}
}

static inline void pt_on_xcommit(pt_recover_arg ctx)
{
	struct pt_event *old_sp, *sp;
	unsigned short pid = ctx->pid;
	struct stack *stacks = ctx->stacks;

	if (!stacks[pid].xbegin)
		return;

	old_sp = stacks[pid].sp;
	stacks[pid].sp = stacks[pid].xbegin;

	for (sp = stacks[pid].xbegin - 1; sp > old_sp; sp--) {
		if (sp->kind == PT_EVENT_CALL)
			pt_on_call(sp->addr, ctx);
		else if (sp->kind == PT_EVENT_RET)
			pt_on_ret(sp->addr, ctx);
		else
			ABORT(ctx, 1, "unexpected event type (%d) while commit", sp->kind);
	}

	stacks[pid].xbegin = NULL;
}

static inline void pt_on_xabort(pt_recover_arg ctx)
{
	unsigned short pid = ctx->pid;
	struct stack *stacks = ctx->stacks;

	ABORT(ctx, !stacks[pid].xbegin, "abort outside a transaction");

	stacks[pid].sp = stacks[pid].xbegin;
	stacks[pid].xbegin = NULL;
}

inline unsigned long norm_addr(struct image_map *images, unsigned long addr)
{
	struct image_map *ptr = images;

	while (ptr->id) {
		if (addr >= ptr->start_va && addr < ptr->end_va)
			return addr - ptr->start_va;
		ptr += 1;
	}

	return 0; // no match
}

static inline void pt_on_block(unsigned long addr, pt_recover_arg ctx)
{
	addr = norm_addr(ctx->images, addr);
	ctx->hashmap[((ctx->prev_block_addr << 1) ^ addr) % MAP_SIZE] = 1;
	ctx->prev_block_addr = addr;
}

#define PT_USE_MIRROR

#include "pt.h"
#include "hash.h"

/* Return the number of bits in hashmap b that are not in a, while also updating a to superset b. */
unsigned long num_new_bits_and_update(unsigned char *a, unsigned char *b)
{
	unsigned long i, new_bits = 0;

	for (i = 0; i < MAP_SIZE; i++) {
		if (!a[i] && b[i]) {
			new_bits += 1;
			a[i] = 1;
		}
	}

	return new_bits;
}

void update_images(struct image_map *images, struct pt_logitem_image *image)
{
	int i;
	for (i = 0; i < MAX_IMAGES; i++) {
		if (!images[i].id) {
			images[i].start_va = image->base;
			images[i].end_va = image->base + image->size;
			images[i].id = hash32(image + 1, image->image_name_length, HASH_CONST);
			return;
		}
	}
}

void segfault_sigaction(int signal, siginfo_t *si, void *arg)
{
	fprintf(stderr, "Segfault while disassembling\n");
	fflush(stdout);
	fflush(stderr);
	exit(1);
}

/* Caller must munmap returned pointer */
struct pt_recover_ctx *process_log(char *logfile)
{
	gzFile log;
	size_t len;
	struct pt_logfile_header lhdr;
	struct pt_logitem_header header;
	struct pt_logitem_buffer *buffer;
	struct pt_logitem_process *process;
	struct pt_logitem_thread *thread;
	struct pt_logitem_image *image;
	struct pt_logitem_xpage *xpage;
	void *addr;
	struct pt_logitem_unmap *unmap;
	struct pt_logitem_fork *pt_fork;
	void *item;
	struct pt_event *sp;
	int i, pid, status;
	int num_images = 0;
	struct stack *stacks;
	struct pt_recover_ctx *recover_ctx;
	struct sigaction sa;

	/* we're going to fork because recovery is not thread-safe, make context shared memory */
	recover_ctx = (struct pt_recover_ctx *) mmap(NULL, sizeof(struct pt_recover_ctx),
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(recover_ctx, 0, sizeof(struct pt_recover_ctx));

	pid = fork();
	ABORT(recover_ctx, pid == -1, "failed to fork");

	if (pid == 0) { // child
		/* setup signal handler */
		memset(&sa, 0, sizeof(struct sigaction));
		sigemptyset(&sa.sa_mask);
		sa.sa_sigaction = segfault_sigaction;
		sa.sa_flags = SA_SIGINFO;
		sigaction(SIGSEGV, &sa, NULL);

		/* open logfile and check format */
		log = gzopen(logfile, "r");
		ABORT(recover_ctx, !log, "open %s failed", logfile);
		ABORT(recover_ctx, !realpath(logfile, recover_ctx->log_abspath),
				"failed to resolve absolute path of %s", logfile);

		len = gzfread(&lhdr, 1, sizeof(lhdr), log);
		ABORT(recover_ctx, len < sizeof(lhdr), "corrupted log");
		ABORT(recover_ctx, lhdr.magic != MAGIC, "unmatched magic");
		ABORT(recover_ctx, lhdr.version != VERSION, "unmatched version");

		stacks = recover_ctx->stacks;

		while ((len = gzfread(&header, 1, sizeof(header), log))) {
			/* undo the seek due to header read */
			gzseek(log, -sizeof(header), SEEK_CUR);

			/* allocate memory to store the whole item */
			item = malloc(header.size);
			ABORT(recover_ctx, !item, "malloc for item failed");

			/* read in */
			len = gzfread(item, 1, header.size, log);
			ABORT(recover_ctx, len != header.size, "unexpected log ending");

			switch (header.kind) {
			case PT_LOGITEM_IMAGE:
				ABORT(recover_ctx, num_images >= MAX_IMAGES, "exceeded max number of images");
				image = (struct pt_logitem_image *) item;
				update_images(recover_ctx->images, image);
				num_images += 1;
				break;
			case PT_LOGITEM_BUFFER:
				buffer = (struct pt_logitem_buffer *) item;
				recover_ctx->pid = buffer->pid;
				pt_recover((char *)(buffer + 1), buffer->size, recover_ctx);
				break;
			case PT_LOGITEM_THREAD:
				thread = (struct pt_logitem_thread *) item;
				if (stacks[thread->pid].top)
					break;
				stacks[thread->pid].top = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
				ABORT(recover_ctx, !stacks[thread->pid].top, "stack allocation failed");
				stacks[thread->pid].top += PAGE_SIZE;
				stacks[thread->pid].sp = ((struct pt_event *) stacks[thread->pid].top) - 1;
				stacks[thread->pid].xbegin = NULL;
				break;
			case PT_LOGITEM_XPAGE:
				xpage = (struct pt_logitem_xpage *) item;
				for (i = 1; i < 10; i++) {
					addr = mmap((void *) MIRROR(xpage->base, i), xpage->size,
							PROT_READ | PROT_WRITE, MAP_ANONYMOUS
							| MAP_PRIVATE | MAP_FIXED, -1, 0);
					ABORT(recover_ctx, (unsigned long) addr != MIRROR(xpage->base, i), "mirror failed");
				}
				memcpy((void *) PT_IP_TO_CODE(xpage->base), xpage + 1, xpage->size);
				break;
			case PT_LOGITEM_FORK:
				pt_fork = (struct pt_logitem_fork *) item;
				stacks[pt_fork->child_pid].top = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
				ABORT(recover_ctx, !stacks[pt_fork->child_pid].top, "stack allocation failed");
				stacks[pt_fork->child_pid].top += PAGE_SIZE;
				stacks[pt_fork->child_pid].sp = ((struct pt_event *) stacks[pt_fork->child_pid].top) - 1;
				stacks[pt_fork->child_pid].xbegin = stacks[pt_fork->parent_pid].xbegin;
				ABORT(recover_ctx, stacks[pt_fork->child_pid].xbegin, "fork in transaction?");
				/* duplicate call stack from parent thread */
				for (sp = stacks[pt_fork->parent_pid].top - 1; sp > stacks[pt_fork->parent_pid].sp; sp--)
					*(stacks[pt_fork->child_pid].sp--) = *sp;
				break;
			default:
				break;
			}

			free(item);
		}

		gzclose(log);
		exit(0);
	}

	/* parent */
	waitpid(pid, &status, WUNTRACED | WCONTINUED);
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		recover_ctx->errno = 2; // segfault while disassembling

	return recover_ctx;
}

void handle_recover_results(unsigned char *global_hashmap, struct pt_recover_ctx *ctx, int *res)
{
	unsigned long new_bits = 0;

	if (!ctx->errno) {
		new_bits = num_new_bits_and_update(global_hashmap, ctx->hashmap);
		printf("%08x  %5lu  %s\n", hash32(ctx->hashmap, MAP_SIZE, HASH_CONST), new_bits, ctx->log_abspath);
	} else {
		printf("ERROR            %s\n", ctx->log_abspath);
		*res = 1;
	}
}

int main(int argc, char *argv[])
{
	struct pt_recover_ctx **ctxs;
	unsigned char *global_hashmap;
	unsigned int i, jobs;
	int res = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: cmppath <log-files ...>\n");
		return 2;
	}

	global_hashmap = (unsigned char *) calloc(1, MAP_SIZE);
	jobs = argc - 1;
	ctxs = (struct pt_recover_ctx **) calloc(jobs, sizeof(struct pt_recover_ctx *));

	#pragma omp parallel for
	for (i = 0; i < jobs; i++)
		ctxs[i] = process_log(argv[i + 1]);

	for (i = 0; i < jobs; i++) {
		handle_recover_results(global_hashmap, ctxs[i], &res);
		munmap(ctxs[i], sizeof(struct pt_recover_ctx));
	}

	free(global_hashmap);
	return res;
}
