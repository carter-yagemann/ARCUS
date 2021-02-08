#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/mman.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <asm/fpu/internal.h>
#include <asm/msr.h>
#include <distorm/distorm.h>
#include <distorm/mnemonics.h>
#include <linux/pt.h>

//#define DEBUG

#define UNHANDLED(condition) BUG_ON(condition)
#define pt_print(fmt, ...) printk(KERN_INFO "pt: " fmt, ## __VA_ARGS__)

#ifdef DEBUG
#define pt_debug(fmt, ...) pt_print(fmt, ## __VA_ARGS__)
#define NEVER(condition) BUG_ON(condition)
#else
#define pt_debug(fmt, ...)
#define NEVER(condition)
#endif

#define PT_XSTATE_CTL 0
#define PT_XSTATE_OUTPUT_BASE 1
#define PT_XSTATE_OUTPUT_MASK 2
#define PT_XSTATE_STATUS 3

#define TOPA_ENTRY_SIZE_4K 0
#define TOPA_ENTRY_SIZE_8K 1
#define TOPA_ENTRY_SIZE_16K 2
#define TOPA_ENTRY_SIZE_32K 3
#define TOPA_ENTRY_SIZE_64K 4
#define TOPA_ENTRY_SIZE_128K 5
#define TOPA_ENTRY_SIZE_256K 6
#define TOPA_ENTRY_SIZE_512K 7
#define TOPA_ENTRY_SIZE_1M 8
#define TOPA_ENTRY_SIZE_2M 9
#define TOPA_ENTRY_SIZE_4M 10
#define TOPA_ENTRY_SIZE_8M 11
#define TOPA_ENTRY_SIZE_16M 12
#define TOPA_ENTRY_SIZE_32M 13
#define TOPA_ENTRY_SIZE_64M 14
#define TOPA_ENTRY_SIZE_128M 15
#define TOPA_ENTRY_SIZE_CHOICE TOPA_ENTRY_SIZE_2M
#define TOPA_BUFFER_SIZE (1 << (12 + TOPA_ENTRY_SIZE_CHOICE))

#define pt_resume() wrmsrl(MSR_IA32_RTIT_CTL, \
		native_read_msr(MSR_IA32_RTIT_CTL) | RTIT_CTL_TRACEEN)

#define pt_pause() wrmsrl(MSR_IA32_RTIT_CTL, \
		native_read_msr(MSR_IA32_RTIT_CTL) & ~RTIT_CTL_TRACEEN)

#define pt_topa_base() native_read_msr(MSR_IA32_RTIT_OUTPUT_BASE)

#define pt_topa_index() ((native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) \
			& 0xffffffff) >> 7)

#define pt_topa_offset() (native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) >> 32)

#define pt_status() (native_read_msr(MSR_IA32_RTIT_STATUS))

#define pt_state() pt_debug("[cpu:%d,pid:%d]" \
	" CTL: %llx," \
	" STATUS: %llx," \
	" OUTPUT_BASE: %llx," \
	" OUTPUT_MASK: %llx\n", \
	smp_processor_id(), current->pid, \
	native_read_msr(MSR_IA32_RTIT_CTL), \
	pt_status(), \
	pt_topa_base(), \
	native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) \
)

#define NUM_MIRROR_LAYER 10
#define MIRROR_DISTANCE 0x010000000000
#define MIRROR(addr, level) (((addr) + (level) * MIRROR_DISTANCE) & 0x7fffffffffff)
#define PT_IP_TO_BLOCK(addr) MIRROR((addr) & ~0x7, ((addr) & 0x7) + 1)
#define PT_IP_TO_INDEX(addr) MIRROR((addr) & ~0x1, ((addr) & 0x1) + 9)

#define POLICY_MATRIX 0x400000000000
#define POLICY_LENGTH 0x10000
#define POLICY_SIZE (u64)((u64)POLICY_LENGTH * (u64)POLICY_LENGTH)
#define POLICY_ADJUST 1
#define POLICY_RSVD ((u16)-POLICY_ADJUST)
#define POLICY_CHECK(src, dst) ((src == POLICY_RSVD) || (dst != POLICY_RSVD && \
	 test_bit(src * POLICY_LENGTH + dst, (const void *) POLICY_MATRIX)))

enum pt_block_kind {
	PT_BLOCK_DIRECT_CALL,
	PT_BLOCK_INDIRECT_CALL,
	PT_BLOCK_DIRECT_JMP,
	PT_BLOCK_INDIRECT_JMP,
	PT_BLOCK_COND_JMP,
	PT_BLOCK_RET,
	PT_BLOCK_SYSCALL,
	PT_BLOCK_TRAP,
};

struct pt_block {
	unsigned long fallthrough_addr;
	struct pt_block *fallthrough_block;
	unsigned long target_addr;
	struct pt_block *target_block;
	enum pt_block_kind kind;
	unsigned short src_index;
	unsigned short dst_index;
};

typedef long pt_event;
#define PT_EVENT_IS_CALL(e) ((e) > 0)
#define PT_EVENT_IS_RET(e) ((e) < 0)

struct topa_entry {
	u64 end:1;
	u64 rsvd0:1;
	u64 intr:1;
	u64 rsvd1:1;
	u64 stop:1;
	u64 rsvd2:1;
	u64 size:4;
	u64 rsvd3:2;
	u64 base:36;
	u64 rsvd4:16;
};

#define TOPA_ENTRY(_base, _size, _stop, _intr, _end) (struct topa_entry) { \
	.base = (_base) >> 12, \
	.size = (_size), \
	.stop = (_stop), \
	.intr = (_intr), \
	.end = (_end), \
}

struct topa {
	struct topa_entry entries[3];
	char *raw;
	struct task_struct *task;
	u64 sequence;
	u64 n_processed;
	struct list_head buffer_list;
	spinlock_t buffer_list_sl;
	bool failed;
	int index;
	pt_event stack[0];
};

#define STACK_PAGE_ORDER 1
#define STACK_MAX ((PAGE_SIZE << STACK_PAGE_ORDER) - sizeof(struct topa)) \
	/ sizeof(pt_event)

struct pt_buffer {
	struct work_struct work;
	struct tasklet_struct tasklet;
	struct list_head entry;
	struct topa *topa;
	struct topa *child_topa;
	struct completion *notifier;
	u64 sequence;
	char *raw;
	u32 size;
	int index;
	pt_event *stack;
};

#define pt_fail_topa(topa, fmt, ...) if (!test_and_set_bit(0, \
			(unsigned long *) &topa->failed)) \
	pt_print("[pid:%d] failed: " fmt "\n", \
			(topa)->task->pid, ## __VA_ARGS__)

static char pt_monitor[PATH_MAX];
static struct dentry *pt_monitor_dentry;

static struct kmem_cache *pt_buffer_cache = NULL;
static struct kmem_cache *pt_block_cache = NULL;
static struct kmem_cache *pt_trace_cache = NULL;

static struct workqueue_struct *pt_wq;

#define PT_NUM_WORKERS 6

static atomic64_t pt_flying_tasks = ATOMIC_INIT(0);

static struct dentry *pt_policy_dentry = NULL;

static struct file *pt_logfile = NULL;
static loff_t pt_logfile_off = 0;
static DEFINE_MUTEX(pt_logfile_mtx);

#define pt_close_logfile() do { \
	if (pt_logfile) { \
		filp_close(pt_logfile, NULL); \
		pt_logfile = NULL; \
		pt_logfile_off = 0; \
	} \
} while (0)

#define pt_log(buf, count) do { \
	ssize_t s; \
	NEVER(!pt_logfile); \
	s = kernel_write(pt_logfile, (char *) buf, count, pt_logfile_off); \
	UNHANDLED(s < 0); \
	pt_logfile_off += s; \
} while (0)



/** Ring Buffer storage of packets **/

// Need a circular linked list (a ring buffer) to manage all of the last N packets
#define RING_BUFFER_COUNT 6

// The data storage needs to be able to accommodate the largest amount of data possible
#define RING_ITEM_DATA_SIZE TOPA_BUFFER_SIZE + PAGE_SIZE

static struct kmem_cache *pt_ring_buffer_cache    = NULL;
static struct kmem_cache *pt_ring_item_cache      = NULL;
static struct kmem_cache *pt_ring_item_data_cache = NULL;

struct pt_ring_item {
	int index;
	ssize_t data_length;
	char * data;
	struct pt_ring_item * next;
	struct pt_ring_item * prev;
};

struct pt_ring_buffer {
	struct pt_ring_item * curr;
	struct pt_ring_item * head;
	void (* add_ring_item)(void *, ssize_t);
	void (* print_buffer)(unsigned int);
};

static struct pt_ring_buffer * ring_buffer;

void add_ring_item(void * data, ssize_t data_length) {
	pt_print("Adding buffer for #%d, size (%zd)\n", ring_buffer->curr->index, data_length);

	// If we haven't allocated the next ring buffer, then do so now
	if (unlikely(ring_buffer->curr->next == NULL)) {
		// If we're at the end of the ring, loop around
		if ((ring_buffer->curr->index + 1) % RING_BUFFER_COUNT == 0) {
			// Return to the beginning
			ring_buffer->curr->next = ring_buffer->head;
		} else {
			// Construct the next ring item
			ring_buffer->curr->next = kmem_cache_alloc(pt_ring_item_cache, GFP_KERNEL);
			memset(ring_buffer->curr->next, 0, sizeof(struct pt_ring_item));
			ring_buffer->curr->next->index = ring_buffer->curr->index + 1;
			ring_buffer->curr->next->data_length = 0; // Potentially redundant
		}

		// Allocate the current data
		ring_buffer->curr->data = kmem_cache_alloc(pt_ring_item_data_cache, GFP_KERNEL);

		// Set the next ring item's previous pointer to the current ring item
		ring_buffer->curr->next->prev = ring_buffer->curr;
	}

	// Verify that the data length does not exceed the cache block
	// For the short term, let's cap the data size to the ring item data size
	if (data_length > RING_ITEM_DATA_SIZE) {
		data_length = RING_ITEM_DATA_SIZE;
	}

	// Set the current data & length
	memcpy(ring_buffer->curr->data, data, data_length);
	ring_buffer->curr->data_length = data_length;

	// Now set the new current ring item
	ring_buffer->curr = ring_buffer->curr->next;
}

void print_buffer(unsigned int max_number_of_buffers) {
	// Set the minimum print index
	unsigned int minimum_print_index, current_print_index, first_index;

	// Impose limits on the max number of buffers - if we break them, just show all
	if (max_number_of_buffers <= 0 || max_number_of_buffers > RING_BUFFER_COUNT) {
		max_number_of_buffers = RING_BUFFER_COUNT;
	}

	// Validate that we have a buffer to print
	if (ring_buffer == NULL || ring_buffer->curr == NULL) {
		return;
	}

	pt_print("Current buffer is #%d, size (%zd)\n", ring_buffer->curr->index, ring_buffer->curr->data_length);

	// If we don't have a full ring buffer, start at the head
	if (ring_buffer->curr->next == NULL) {
		ring_buffer->curr = ring_buffer->head;
	}

	// Set the first index for a stopping criterion
	first_index = ring_buffer->curr->index;

	// Validate the starting criterion - that we have data to print
	if (ring_buffer->curr->data_length <= 0) {
		return;
	}

	// Set the minimum print index
	minimum_print_index = RING_BUFFER_COUNT - max_number_of_buffers;
	current_print_index = 0;

	// Print all of the buffers
	// Use do-while because we want to stop at the same index as the one we started with
	do {
		// Only print if we should
		if (current_print_index >= minimum_print_index) {
			pt_print("Printing buffer #%d to %d, size (%zd)\n", ring_buffer->curr->index, first_index, ring_buffer->curr->data_length);
			pt_log(ring_buffer->curr->data, ring_buffer->curr->data_length);
		}

		// Increment print index
		current_print_index++;

		// Move to the next ring item
		ring_buffer->curr = ring_buffer->curr->next;
	} while (
		ring_buffer->curr != NULL && 
		ring_buffer->curr->data_length > 0 &&
		ring_buffer->curr->index != first_index
	);
}

int initialize_ring_buffer(void) {
	// Devote space to the ring buffer, the items in the ring, and the data linked by the items
	pt_ring_buffer_cache = kmem_cache_create("pt_ring_buffer_cache", sizeof(struct pt_ring_buffer), 0, 0, NULL);
	if (!pt_ring_buffer_cache)
		goto destroy_ring_buffer_cache;

	pt_ring_item_cache = kmem_cache_create("pt_ring_item_cache", sizeof(struct pt_ring_item), 0, 0, NULL);
	if (!pt_ring_item_cache)
		goto destroy_ring_item_cache;

	pt_ring_item_data_cache = kmem_cache_create("pt_ring_item_data_cache", RING_ITEM_DATA_SIZE, 0, 0, NULL);
	if (!pt_ring_item_data_cache)
		goto destroy_ring_item_data_cache;

	// Initialize the ring buffer
	ring_buffer = kmem_cache_alloc(pt_ring_buffer_cache, GFP_KERNEL);
	memset(ring_buffer, 0, sizeof(struct pt_ring_buffer));

	// Now set the functions
	if (ring_buffer != NULL) {
		ring_buffer->add_ring_item = &add_ring_item;
		ring_buffer->print_buffer = &print_buffer;
	}

	// Construct the first ring item
	ring_buffer->head = kmem_cache_alloc(pt_ring_item_cache, GFP_KERNEL);
	ring_buffer->head->index = 0;
	ring_buffer->head->next = NULL;
	ring_buffer->head->prev = NULL;

	// And set the current ring item to it
	ring_buffer->curr = ring_buffer->head;

	return 0;

destroy_ring_item_data_cache:
	kmem_cache_destroy(pt_ring_item_data_cache);
destroy_ring_item_cache:
	kmem_cache_destroy(pt_ring_item_cache);
destroy_ring_buffer_cache:
	kmem_cache_destroy(pt_ring_buffer_cache);
	return -1;
}

/** End Ring Buffer logic **/


/** API Methods **/

// Flags
//static struct dentry *pt_trace_address_dentry;
static struct dentry *pt_trace_syscall_dentry;
static struct dentry *pt_trace_fwd_edge_dentry;
static struct dentry *pt_trace_shadow_stack_dentry;

// Turn on / off the various ways to print traces
//static bool _PT_TRACE_ADDR_RANGE = false;
static bool _PT_TRACE_SYSCALL      = false;
static bool _PT_TRACE_FWD_EDGE     = false;
static bool _PT_TRACE_SHADOW_STACK = false;
static bool _PT_TRACE_PROC_END     = false;

// Number of buffers before and after. No larger than {ring buffer max}/2.
static int _PT_TRACE_SYSCALL_WIDTH = 1;
static int _PT_TRACE_FWD_EDGE_WIDTH = 1;
static int _PT_TRACE_SHADOW_STACK_WIDTH = 1;

// For dumping traces within address ranges
// If these are ordered, we can search through them quickly
/*
static int pt_range_address_count       = 1;
static u64 pt_range_start_addresses[10] = {0x400c18,0,0,0,0,0,0,0,0,0};
static u64 pt_range_end_addresses[10]   = {0x400960,0,0,0,0,0,0,0,0,0};
static bool pt_range_open[10]           = {false,false,false,false,false,false,false,false,false,false};
*/

// Currently O(num addrs) timing - would like to reduce since this is called a LOT
/*
#define pt_trace_on_addr_range(last_addr, curr_addr) do { \
	if (_PT_TRACE_ADDR_RANGE) { \
		int pt_range_idx = 0; \
		for (pt_range_idx = 0; pt_range_idx < pt_range_address_count; pt_range_idx++) { \
			u64 pt_range_start_addr = pt_range_start_addresses[pt_range_idx]; \
			u64 pt_range_end_addr   = pt_range_end_addresses[pt_range_idx]; \
			if (!pt_range_open[pt_range_idx] && curr_addr <= pt_range_start_addr) { \
				pt_range_open[pt_range_idx] = true; \
				pt_print("  Starting Range: %llx to %llx compared to %llx\n", last_addr, curr_addr, pt_range_start_addr); \
			} \
			else if (pt_range_open[pt_range_idx] && curr_addr <= pt_range_end_addr) { \
				pt_range_open[pt_range_idx] = false; \
				_PT_TRACE_ADDR_RANGE = false; \
				pt_print("  Finished Range: %llx to %llx compared to %llx\n", last_addr, curr_addr, pt_range_end_addr); \
			} \
		} \
	} \
} while (0)
*/

// Keep track of when we need to dump a trace
static bool pt_trace_fwd_edge_trigger = false;
static bool pt_trace_shadow_stack_trigger = false;
static bool pt_trace_syscall_trigger = false;
static int pt_trace_syscall_trigger_rb_index = -1;

// For dumping traces on system calls
#define pt_trace_on_syscall() do { \
	if (_PT_TRACE_SYSCALL) { \
		pt_trace_syscall_trigger = true; \
		if (pt_trace_syscall_trigger_rb_index == -1) { \
			pt_trace_syscall_trigger_rb_index = ring_buffer->curr->index; \
		} \
		pt_print("  System call captured. Will print to log.\n"); \
	} \
} while (0)


// Files - used to trigger the APIs

/*
static ssize_t
pt_trace_address_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	// In progress
}

static const struct file_operations pt_trace_address_fops = {
	.write = pt_trace_address_write,
};
*/

static int pt_trace_address_setup(void)
{
	return 0;
/*
	pt_trace_address_dentry = debugfs_create_file("pt_trace_addresses",
			0600, NULL, NULL, &pt_trace_address_fops);
	if (!pt_trace_address_dentry) {
		pt_print("unable to create pt_trace_addresses\n");
		return -ENOMEM;
	}

	return 0;
*/
}

static void pt_trace_address_destroy(void)
{
/*
	if (pt_trace_address_dentry)
		debugfs_remove(pt_trace_address_dentry);
*/
}

static ssize_t
pt_trace_syscall_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	//char mode;
	char mode_to_int[2] = {"0\0"};
	int res = 0;

	if (*ppos != 0)
		return -EINVAL;
	if (count != 1)
		return -EINVAL;
	if (atomic64_read(&pt_flying_tasks))
		return -EBUSY;
	if (copy_from_user(&mode_to_int, buf, 1))
		return -EINVAL;

	// Pull the number
	//mode_to_int[0] = mode;
	_PT_TRACE_SYSCALL_WIDTH = kstrtoint((const char *)&mode_to_int,10,&res);

	pt_print("tracing system calls: %c -> %d\n", mode_to_int[0], _PT_TRACE_SYSCALL_WIDTH);

	// TESTING ONLY
	_PT_TRACE_SYSCALL_WIDTH = 1;

	// Validate and set
	if (_PT_TRACE_SYSCALL_WIDTH < 1 || _PT_TRACE_SYSCALL_WIDTH/2 > RING_BUFFER_COUNT) {
		pt_print("invalid Griffin syscall buffer width - must be between 1 and 3\n");
		_PT_TRACE_SYSCALL = false;
	} else {
		pt_print("tracing system calls: %c -> %d\n", mode_to_int[0], _PT_TRACE_SYSCALL_WIDTH);
		_PT_TRACE_SYSCALL = true;
	}

	return 1;
}

static const struct file_operations pt_trace_syscall_fops = {
	.write = pt_trace_syscall_write,
};

static int pt_trace_syscall_setup(void)
{
	pt_trace_syscall_dentry = debugfs_create_file("pt_trace_syscall",
			0600, NULL, NULL, &pt_trace_syscall_fops);
	if (!pt_trace_syscall_dentry) {
		pt_print("unable to create pt_trace_syscall\n");
		return -ENOMEM;
	}

	return 0;
}

static void pt_trace_syscall_destroy(void)
{
	if (pt_trace_syscall_dentry)
		debugfs_remove(pt_trace_syscall_dentry);
}

static ssize_t
pt_trace_fwd_edge_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char mode;

	if (*ppos != 0)
		return -EINVAL;
	if (count != 1)
		return -EINVAL;
	if (atomic64_read(&pt_flying_tasks))
		return -EBUSY;
	if (copy_from_user(&mode, buf, 1))
		return -EINVAL;

	pt_print("tracing forward edges\n");
	_PT_TRACE_FWD_EDGE = true;

	// Pull the number 
	/*
	int res = 0;
	_PT_TRACE_SYSCALL_WIDTH = kstrtoint(&mode,10,&res);

	pt_print("tracing system calls: %c -> %d\n", mode, _PT_TRACE_SYSCALL_WIDTH);

	// Validate and set
	if (_PT_TRACE_SYSCALL_WIDTH < 1 || _PT_TRACE_SYSCALL_WIDTH/2 > RING_BUFFER_COUNT) {
		pt_print("invalid Griffin fwd_edge buffer width - must be between 1 and 3\n");
		_PT_TRACE_SYSCALL = false;
	} else {
		pt_print("tracing system calls\n");
		_PT_TRACE_SYSCALL = true;
	}
	*/

	return 1;
}

static const struct file_operations pt_trace_fwd_edge_fops = {
	.write = pt_trace_fwd_edge_write,
};

static int pt_trace_fwd_edge_setup(void)
{
	pt_trace_fwd_edge_dentry = debugfs_create_file("pt_trace_fwd_edge",
			0600, NULL, NULL, &pt_trace_fwd_edge_fops);
	if (!pt_trace_fwd_edge_dentry) {
		pt_print("unable to create pt_trace_fwd_edge\n");
		return -ENOMEM;
	}

	return 0;
}

static void pt_trace_fwd_edge_destroy(void)
{
	if (pt_trace_fwd_edge_dentry)
		debugfs_remove(pt_trace_fwd_edge_dentry);
}

static ssize_t
pt_trace_shadow_stack_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char mode;

	if (*ppos != 0)
		return -EINVAL;
	if (count != 1)
		return -EINVAL;
	if (atomic64_read(&pt_flying_tasks))
		return -EBUSY;
	if (copy_from_user(&mode, buf, 1))
		return -EINVAL;

	pt_print("tracing shadow stack\n");
	_PT_TRACE_SHADOW_STACK = true;

	// Pull the number 
	/*
	int res = 0;
	_PT_TRACE_SYSCALL_WIDTH = kstrtoint(&mode,10,&res);

	pt_print("tracing system calls: %c -> %d\n", mode, _PT_TRACE_SYSCALL_WIDTH);

	// Validate and set
	if (_PT_TRACE_SYSCALL_WIDTH < 1 || _PT_TRACE_SYSCALL_WIDTH/2 > RING_BUFFER_COUNT) {
		pt_print("invalid Griffin shadow_stack buffer width - must be between 1 and 3\n");
		_PT_TRACE_SYSCALL = false;
	} else {
		pt_print("tracing system calls\n");
		_PT_TRACE_SYSCALL = true;
	}
	*/

	return 1;
}

static const struct file_operations pt_trace_shadow_stack_fops = {
	.write = pt_trace_shadow_stack_write,
};

static int pt_trace_shadow_stack_setup(void)
{
	pt_trace_shadow_stack_dentry = debugfs_create_file("pt_trace_shadow_stack",
			0600, NULL, NULL, &pt_trace_shadow_stack_fops);
	if (!pt_trace_shadow_stack_dentry) {
		pt_print("unable to create pt_trace_shadow_stack\n");
		return -ENOMEM;
	}

	return 0;
}

static void pt_trace_shadow_stack_destroy(void)
{
	if (pt_trace_shadow_stack_dentry)
		debugfs_remove(pt_trace_shadow_stack_dentry);
}

/** End API Methods **/


#pragma pack(push)

struct pt_logfile_header {
	u32 magic;
	u32 version;
};

#define PT_LOGFILE_MAGIC 0x51C0FFEE
#define PT_LOGFILE_VERSION 0x1
static void pt_log_header(void)
{
	struct pt_logfile_header h = {
		.magic = PT_LOGFILE_MAGIC,
		.version = PT_LOGFILE_VERSION,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&h, sizeof(h));
	mutex_unlock(&pt_logfile_mtx);
}

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
	u32 size;
};

struct pt_logitem_buffer {
	struct pt_logitem_header header;
	u64 tgid;
	u64 pid;
	u64 sequence;
	u64 size;
};

static void pt_log_buffer(struct pt_buffer *buf)
{
	struct pt_logitem_buffer item = {
		.header = {
			.kind = PT_LOGITEM_BUFFER,
			.size = sizeof(struct pt_logitem_buffer) + buf->size
		},
		.tgid = buf->topa->task->tgid,
		.pid = buf->topa->task->pid,
		.sequence = buf->sequence,
		.size = buf->size,
	};

	mutex_lock(&pt_logfile_mtx);
	ring_buffer->add_ring_item(&item, sizeof(item));
	ring_buffer->add_ring_item(buf->raw, buf->size);
	mutex_unlock(&pt_logfile_mtx);
}

struct pt_logitem_process {
	struct pt_logitem_header header;
	u64 tgid;
	u64 cmd_size;
};

struct pt_logitem_thread {
	struct pt_logitem_header header;
	u64 tgid;
	u64 pid;
};

static void pt_log_thread(struct task_struct *task)
{
	struct pt_logitem_thread item = {
		.header = {
			.kind = PT_LOGITEM_THREAD,
			.size = sizeof(struct pt_logitem_thread),
		},
		.tgid = task->tgid,
		.pid = task->pid,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, sizeof(item));
	mutex_unlock(&pt_logfile_mtx);
}

static void pt_log_process(struct task_struct *task)
{
	struct pt_logitem_process item = {
		.header = {
			.kind = PT_LOGITEM_PROCESS,
			.size = sizeof(struct pt_logitem_process)
				+ strlen(pt_monitor)
		},
		.tgid = task->tgid,
		.cmd_size = strlen(pt_monitor),
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, sizeof(item));
	pt_log(pt_monitor, item.cmd_size);
	mutex_unlock(&pt_logfile_mtx);

	pt_log_thread(task);
}

struct pt_logitem_image {
	struct pt_logitem_header header;
	u64 tgid;
	u64 base;
	u32 size;
	u32 timestamp;
	u64 image_name_length;
};

struct pt_logitem_xpage {
	struct pt_logitem_header header;
	u64 tgid;
	u64 base;
	u64 size;
};

static void pt_log_xpage(struct task_struct *task, u64 base,
		u64 real_size, u64 size)
{
	int ret, i, nr_pages, nr_real_pages;
	void *page = (void *) get_zeroed_page(GFP_KERNEL);
	struct pt_logitem_xpage item = {
		.header = {
			.kind = PT_LOGITEM_XPAGE,
			.size = sizeof(struct pt_logitem_xpage) + size
		},
		.tgid = task->tgid,
		.base = base,
		.size = size,
	};

	UNHANDLED(!page);

	if (!real_size)
		real_size = size;

	NEVER(real_size > size);
	NEVER(base & ~PAGE_MASK);
	NEVER(size & ~PAGE_MASK);

	nr_real_pages = PAGE_ALIGN(real_size) >> PAGE_SHIFT;
	nr_pages = size >> PAGE_SHIFT;

	mutex_lock(&pt_logfile_mtx);

	pt_log(&item, sizeof(item));

	for (i = 0; i < nr_real_pages; i++) {
		ret = access_process_vm(task, base + i * PAGE_SIZE,
				page, PAGE_SIZE, 0);
		UNHANDLED(ret != PAGE_SIZE);
		pt_log(page, PAGE_SIZE);
	}

	memset(page, 0, PAGE_SIZE);
	for (i = 0; i < nr_pages - nr_real_pages; i++)
		pt_log(page, PAGE_SIZE);

	mutex_unlock(&pt_logfile_mtx);

	free_page((unsigned long) page);
}

struct pt_logitem_unmap {
	struct pt_logitem_header header;
	u64 tgid;
	u64 base;
};

struct pt_logitem_fork {
	struct pt_logitem_header header;
	u64 parent_tgid;
	u64 parent_pid;
	u64 child_tgid;
	u64 child_pid;
};

static void pt_log_fork(struct task_struct *parent,
		struct task_struct *child)
{
	struct pt_logitem_fork item = {
		.header = {
			.kind = PT_LOGITEM_FORK,
			.size = sizeof(struct pt_logitem_fork),
		},
		.parent_tgid = parent->tgid,
		.parent_pid = parent->pid,
		.child_tgid = child->tgid,
		.child_pid = child->pid,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, item.header.size);
	mutex_unlock(&pt_logfile_mtx);
}

#pragma pack(pop)

static ssize_t
pt_monitor_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, pt_monitor,
			strlen(pt_monitor));
}

static ssize_t
pt_monitor_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	if (count >= PATH_MAX)
		return -ENOMEM;
	if (*ppos != 0)
		return -EINVAL;
	if (atomic64_read(&pt_flying_tasks))
		return -EBUSY;

	memset(pt_monitor, 0, PATH_MAX);
	if (copy_from_user(pt_monitor, buf, count))
		return -EINVAL;

	pt_close_logfile();
	pt_logfile = filp_open("/var/log/pt.log", O_WRONLY | O_TRUNC
			| O_CREAT | O_LARGEFILE, 0644);
	if (IS_ERR_OR_NULL(pt_logfile))
		return PTR_ERR(pt_logfile);
	pt_log_header();
	workqueue_set_max_active(pt_wq, 1);

	// Reset the PT watch triggers
	_PT_TRACE_FWD_EDGE = false;
	_PT_TRACE_SHADOW_STACK = false;
	_PT_TRACE_SYSCALL = false;
	pt_trace_fwd_edge_trigger = false;
	pt_trace_shadow_stack_trigger = false;
	pt_trace_syscall_trigger = false;
	pt_trace_syscall_trigger_rb_index = -1;

	// TODO: Clear out the PT Buffers here

	pt_print("offline: %s registered\n", pt_monitor);

	return count;
}

static const struct file_operations pt_monitor_fops = {
	.write = pt_monitor_write,
	.read = pt_monitor_read,
};

static int pt_monitor_setup(void)
{
	pt_monitor_dentry = debugfs_create_file("pt_monitor",
			0600, NULL, NULL, &pt_monitor_fops);
	if (!pt_monitor_dentry) {
		pt_print("unable to create pt_monitor\n");
		return -ENOMEM;
	}

	return 0;
}

static void pt_monitor_destroy(void)
{
	if (pt_monitor_dentry)
		debugfs_remove(pt_monitor_dentry);
}

static ssize_t
pt_policy_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	u32 total, bytes, nrows, ncols;
	u32 i, ret, offset = 0;
	char *row = NULL;
	struct {
		u64 addr;
		u32 is_target;
		u16 index;
		u16 padding;
	} mapping;

#define SAFE_READ(dest, n) \
do { \
	if (offset + (n) > count) \
		return -EINVAL; \
	if (copy_from_user((dest), buf + offset, (n))) \
		return -EINVAL; \
	offset += (n); \
} while (0)

#define ROW_SIZE (ncols / 8)

	if (!pt_enabled())
		return -EINVAL;
	if (*ppos != 0)
		return -EINVAL;

	SAFE_READ(&total, sizeof(total));
	if (!total) {
		pt_print("empty policy?\n");
		return -EINVAL;
	}

	for (i = 0; i < total; i++) {
		SAFE_READ(&mapping, sizeof(mapping));
		mapping.index += POLICY_ADJUST;
		ret = access_process_vm(current, PT_IP_TO_INDEX(mapping.addr),
				&mapping.index, sizeof(mapping.index), 1);
		if (ret != sizeof(mapping.index))
			return -EINVAL;
	}

	SAFE_READ(&nrows, sizeof(nrows));
	SAFE_READ(&ncols, sizeof(ncols));
	if (ncols & 0x7) {
		pt_print("ncols must be a multiply of eight\n");
		return -EINVAL;
	}

	row = (char *) kmalloc(ROW_SIZE, GFP_KERNEL);
	if (!row)
		return -ENOMEM;

	bytes = (nrows * ncols) / 8;

	for (i = 0; i < nrows; i++) {
		SAFE_READ(row, ROW_SIZE);
		ret = access_process_vm(current, POLICY_MATRIX + i * POLICY_LENGTH / 8,
				row, ROW_SIZE, 1);
		if (ret != ROW_SIZE)
			return -EINVAL;
	}

	return count;
}

static const struct file_operations pt_policy_fops = {
	.write = pt_policy_write,
};

static int pt_policy_setup(void)
{
	pt_policy_dentry = debugfs_create_file("pt_policy",
			0600, NULL, NULL, &pt_policy_fops);
	if (!pt_policy_dentry) {
		pt_print("unable to create pt_policy\n");
		return -ENOMEM;
	}

	return 0;
}

static void pt_policy_destroy(void)
{
	if (pt_policy_dentry)
		debugfs_remove(pt_policy_dentry);
}

static int pt_wq_setup(void)
{
	int err = -ENOMEM;
	struct workqueue_attrs *attrs;

	pt_wq = alloc_workqueue("pt_wq", WQ_UNBOUND | WQ_HIGHPRI, 1);
	if (!pt_wq)
		goto fail;

	attrs = alloc_workqueue_attrs(GFP_ATOMIC);
	if (!attrs)
		goto destroy_wq;

	/* worker may only run on physical core 1, 2, 3 */
	cpumask_clear_cpu(0, attrs->cpumask);
	cpumask_clear_cpu(4, attrs->cpumask);

	err = apply_workqueue_attrs(pt_wq, attrs);
	free_workqueue_attrs(attrs);
	if (err < 0)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(pt_wq);
fail:
	return err;
}

static void pt_wq_destroy(void)
{
	flush_workqueue(pt_wq);
	destroy_workqueue(pt_wq);
}

static void do_setup_topa(struct topa *topa, void *raw)
{
	/* checking virtual address is fine given 1:1 direct mapping */
#define DIRECT_MAPPING_END 0xffffc7ffffffffff
	NEVER((unsigned long) topa > DIRECT_MAPPING_END);
	NEVER((unsigned long) raw > DIRECT_MAPPING_END);
	NEVER((unsigned long) raw & (TOPA_BUFFER_SIZE - 1));

	/* setup topa entries */
	topa->entries[0] = TOPA_ENTRY(virt_to_phys(raw),
			TOPA_ENTRY_SIZE_CHOICE, 0, 1, 0);
	topa->entries[1] = TOPA_ENTRY(virt_to_phys(raw + TOPA_BUFFER_SIZE),
			TOPA_ENTRY_SIZE_4K, 0, 1, 0);
	topa->entries[2] = TOPA_ENTRY(virt_to_phys(topa), 0, 0, 0, 1);

	topa->raw = raw;
}

static void pt_setup_topa(struct topa *topa, void *raw, struct task_struct *task)
{
	topa->task = task;
	topa->sequence = 0;
	topa->n_processed = 0;
	INIT_LIST_HEAD(&topa->buffer_list);
	spin_lock_init(&topa->buffer_list_sl);
	topa->failed = false;
	topa->index = 0;

	do_setup_topa(topa, raw);
}

static void pt_setup_msr(struct topa *topa)
{
	NEVER(pt_enabled());

	wrmsrl(MSR_IA32_RTIT_STATUS, 0);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, virt_to_phys(topa));
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, 0);
	wrmsrl(MSR_IA32_RTIT_CTL, RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
			| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
			| ((TOPA_ENTRY_SIZE_64K + 1) << 24));
}

static void pt_setup_xsave(struct topa *topa, struct xregs_state *xsave)
{
	u64 *xregs = (u64 *) get_xsave_addr(xsave, XSTATE_INTEL_PT);
	NEVER(!xregs);

	xregs[PT_XSTATE_STATUS] = 0;
	xregs[PT_XSTATE_OUTPUT_BASE] = virt_to_phys(topa);
	xregs[PT_XSTATE_OUTPUT_MASK] = 0;
	xregs[PT_XSTATE_CTL] = RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
		| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
		| ((TOPA_ENTRY_SIZE_64K + 1) << 24);
}

enum pt_packet_kind {
	PT_PACKET_ERROR = -1,
	PT_PACKET_NONE,
	PT_PACKET_TNTSHORT,
	PT_PACKET_TNTLONG,
	PT_PACKET_TIP,
	PT_PACKET_TIPPGE,
	PT_PACKET_TIPPGD,
	PT_PACKET_FUP,
	PT_PACKET_PIP,
	PT_PACKET_MODE,
	PT_PACKET_TRACESTOP,
	PT_PACKET_CBR,
	PT_PACKET_TSC,
	PT_PACKET_MTC,
	PT_PACKET_TMA,
	PT_PACKET_CYC,
	PT_PACKET_VMCS,
	PT_PACKET_OVF,
	PT_PACKET_PSB,
	PT_PACKET_PSBEND,
	PT_PACKET_MNT,
	PT_PACKET_PAD,
};

static inline enum pt_packet_kind
pt_get_packet(unsigned char *buffer, u64 size, u64 *len)
{
	enum pt_packet_kind kind;
	unsigned char first_byte;
	unsigned char second_byte;
	unsigned long cyc_len;
	static unsigned long ipbytes_plus_one[8] = {1, 3, 5, 7, 7, 1, 9, 1};

#ifdef DEBUG
	if (!buffer || !size) {
		*len = 0;
		return PT_PACKET_NONE;
	}
#endif

	first_byte = *buffer;

	if ((first_byte & 0x1) == 0) { // ???????0
		if ((first_byte & 0x2) == 0) { // ??????00
			if (first_byte == 0) {
				kind = PT_PACKET_PAD;
				*len = 1;
			} else {
				kind = PT_PACKET_TNTSHORT;
				*len = 1;
			}
		} else { // ??????10
			if (first_byte != 0x2) {
				kind = PT_PACKET_TNTSHORT;
				*len = 1;
			} else {
#ifdef DEBUG
				if (size < 2) {
					kind = PT_PACKET_NONE;
					*len = 0;
				} else {
#endif
					second_byte = *(buffer + 1);
					if ((second_byte & 0x1) == 0) { // ???????0
						if ((second_byte & 0x2) == 0) { // ??????00
#ifdef DEBUG
							if (second_byte != 0xc8)
								return PT_PACKET_ERROR;
#endif
							kind = PT_PACKET_VMCS;
							*len = 7;
						} else { // ??????10
#ifdef DEBUG
							if (second_byte != 0x82)
								return PT_PACKET_ERROR;
#endif
							kind = PT_PACKET_PSB;
							*len = 16;
						}
					} else { // ???????1
						if ((second_byte & 0x10) == 0) { // ???0???1
							if ((second_byte & 0x20) == 0) { // ??00???1
								if ((second_byte & 0x40) == 0) { // ?000???1
									if ((second_byte & 0x80) == 0) { // 0000???1
#ifdef DEBUG
										if (second_byte != 0x3)
											return PT_PACKET_ERROR;
#endif
										kind = PT_PACKET_CBR;
										*len = 4;
									} else { // 1000???1
#ifdef DEBUG
										if (second_byte != 0x83)
											return PT_PACKET_ERROR;
#endif
										kind = PT_PACKET_TRACESTOP;
										*len = 2;
									}
								} else { // ??10???1
									if ((second_byte & 0x80) == 0) { // 0100???1
#ifdef DEBUG
										if (second_byte != 0x43)
											return PT_PACKET_ERROR;
#endif
										kind = PT_PACKET_PIP;
										*len = 8;
									} else { // 1100???1
#ifdef DEBUG
										if (second_byte != 0xc3)
											return PT_PACKET_ERROR;
#endif
										kind = PT_PACKET_MNT;
										*len = 11;
									}
								}
							} else { // ??10???1
								if ((second_byte & 0x80) == 0) { // 0?10???1
#ifdef DEBUG
									if (second_byte != 0x23)
										return PT_PACKET_ERROR;
#endif
									kind = PT_PACKET_PSBEND;
									*len = 2;
								} else { // 1?10???1
#ifdef DEBUG
									if (second_byte != 0xa3)
										return PT_PACKET_ERROR;
#endif
									kind = PT_PACKET_TNTLONG;
									*len = 8;
								}
							}
						} else { // ???1???1
							if ((second_byte & 0x80) == 0) { // 0??1???1
#ifdef DEBUG
								if (second_byte != 0x73)
									return PT_PACKET_ERROR;
#endif
								kind = PT_PACKET_TMA;
								*len = 7;
							} else { // 1??1???1
#ifdef DEBUG
								if (second_byte != 0xf3)
									return PT_PACKET_ERROR;
#endif
								kind = PT_PACKET_OVF;
								*len = 2;
							}
						}
					}
#ifdef DEBUG
				}
#endif
			}
		}
	} else { // ???????1
		if ((first_byte & 0x2) == 0) { // ??????01
			if ((first_byte & 0x4) == 0) { // ?????001
				if ((first_byte & 0x8) == 0) { // ????0001
					if ((first_byte & 0x10) == 0) { // ???00001
						kind = PT_PACKET_TIPPGD;
						*len = ipbytes_plus_one[first_byte>>5];
					} else { // ???10001
						kind = PT_PACKET_TIPPGE;
						*len = ipbytes_plus_one[first_byte>>5];
					}
				} else { // ????1001
					if ((first_byte & 0x40) == 0) { // ?0??1001
						if ((first_byte & 0x80) == 0) { // 00??1001
#ifdef DEBUG
							if (first_byte != 0x19)
								return PT_PACKET_ERROR;
#endif
							kind = PT_PACKET_TSC;
							*len = 8;
						} else { // 10??1001
#ifdef DEBUG
							if (first_byte != 0x99)
								return PT_PACKET_ERROR;
#endif
							kind = PT_PACKET_MODE;
							*len = 2;
						}
					} else { // ?1??1001
#ifdef DEBUG
						if (first_byte != 0x59)
							return PT_PACKET_ERROR;
#endif
						kind = PT_PACKET_MTC;
						*len = 2;
					}
				}
			} else { // ?????101
#ifdef DEBUG
				if ((first_byte & 0x8) == 0)
					return PT_PACKET_ERROR;
#endif
				if ((first_byte & 0x10) == 0) { // ???0?101
					kind = PT_PACKET_TIP;
					*len = ipbytes_plus_one[first_byte>>5];
				} else { // ???1?101
					kind = PT_PACKET_FUP;
					*len = ipbytes_plus_one[first_byte>>5];
				}
			}
		} else { // ??????11
			if ((first_byte & 0x4) == 0) {
				kind = PT_PACKET_CYC;
				*len = 1;
			} else {
				for (cyc_len = 2; cyc_len <= size; cyc_len ++) {
					if (buffer[cyc_len-1] & 0x1) {
						cyc_len ++;
					} else {
						break;
					}
				}
#ifdef DEBUG
				if (cyc_len > size) {
					kind = PT_PACKET_NONE;
					*len = 0;
				} else {
#endif
					kind = PT_PACKET_CYC;
					*len = cyc_len;
#ifdef DEBUG
				}
#endif
			}
		}
	}

	return kind;
}

static inline u64
pt_get_and_update_ip(unsigned char *packet, u32 len, u64 *last_ip)
{
	u64 ip;

	switch (len) {
	case 1:
		ip = 0; // do not change last_ip in this case
		break;
	case 3:
		ip = ((*last_ip) & 0xffffffffffff0000) | *(u16 *)(packet+1);
		*last_ip = ip;
		break;
	case 5:
		ip = ((*last_ip) & 0xffffffff00000000) | *(u32 *)(packet+1);
		*last_ip = ip;
		break;
	case 7:
		if (((*packet) & 0x80) == 0) { // extend
			*(u32 *)&ip = *(u32 *)(packet+1);
			*((s32 *)&ip+1) = (s32)*(s16 *)(packet+5);
		} else {
			*(u32 *)&ip = *(u32 *)(packet+1);
			*((u32 *)&ip+1) = ((u32)*((u16 *)last_ip+3) << 16 | (u32)*(u16 *)(packet+5));
		}
		*last_ip = ip;
		break;
	case 9:
		ip = *(u64 *)(packet+1);
		*last_ip = ip;
		break;
	default:
		ip = 0;
		*last_ip = 0;
		break;
	}

	return ip;
}

static struct pt_block *pt_disasm_block(u64 addr)
{
	unsigned int n;
	struct pt_block *block;
	_DInst inst;
	_DecodeResult r;
	_CodeInfo codeInfo = {
		.codeOffset = addr,
		.code = (char *) addr,
		.codeLen = 0x7fffffff,
		.dt = Decode64Bits,
		.features = DF_STOP_ON_FLOW_CONTROL | DF_RETURN_FC_ONLY,
	};

	block = kmem_cache_alloc(pt_block_cache, GFP_KERNEL);
	memset(block, 0, sizeof(struct pt_block));
retry:
	r = distorm_decompose(&codeInfo, &inst, 1, &n);
	NEVER(n != 1);

	switch (META_GET_FC(inst.meta)) {
	case FC_CALL:
		block->kind = inst.ops[0].type == O_PC? PT_BLOCK_DIRECT_CALL: PT_BLOCK_INDIRECT_CALL;
		block->fallthrough_addr = inst.addr + inst.size;
		if (block->kind == PT_BLOCK_DIRECT_CALL)
			block->target_addr = block->fallthrough_addr + inst.imm.sdword;
		break;
	case FC_RET:
		block->kind = PT_BLOCK_RET;
		block->fallthrough_addr = inst.addr + inst.size;
		break;
	case FC_SYS:
		block->kind = PT_BLOCK_SYSCALL;
		block->fallthrough_addr = inst.addr + inst.size;
		break;
	case FC_UNC_BRANCH:
		block->kind = inst.ops[0].type == O_PC? PT_BLOCK_DIRECT_JMP: PT_BLOCK_INDIRECT_JMP;
		block->fallthrough_addr = inst.addr + inst.size;
		if (block->kind == PT_BLOCK_DIRECT_JMP)
			block->target_addr = block->fallthrough_addr +
				(inst.ops[0].size == 32? inst.imm.sdword: inst.imm.sbyte);
		break;
	case FC_CND_BRANCH:
		block->kind = PT_BLOCK_COND_JMP;
		block->fallthrough_addr = inst.addr + inst.size;
		block->target_addr = block->fallthrough_addr +
			(inst.ops[0].size == 32? inst.imm.sdword: inst.imm.sbyte);
		break;
	case FC_INT:
		block->kind = PT_BLOCK_TRAP;
		block->fallthrough_addr = inst.addr + inst.size;
		break;
	case FC_CMOV:
		codeInfo.code = (char *) codeInfo.nextOffset;
		codeInfo.codeOffset = codeInfo.nextOffset;
		goto retry;
	default:
		BUG();
	}

	return block;
}

static inline struct pt_block *pt_get_block(unsigned long addr)
{
	atomic64_t *mirror_addr = (atomic64_t *) PT_IP_TO_BLOCK(addr);
	struct pt_block *block = (struct pt_block *) atomic64_read(mirror_addr);
	long new_block;

	if (unlikely(!block)) {
		block = pt_disasm_block(addr);
		block->src_index = (*(u16 *) PT_IP_TO_INDEX(block->fallthrough_addr)) - POLICY_ADJUST;
		block->dst_index = (*(u16 *) PT_IP_TO_INDEX(addr)) - POLICY_ADJUST;

		new_block = atomic64_cmpxchg(mirror_addr, 0, (long) block);
		if (new_block) {
			kmem_cache_free(pt_block_cache, block);
			block = (struct pt_block *) new_block;
		}
	}

	return block;
}

#define pt_in_block(a, b) (pt_get_block(a)->fallthrough_addr == (b)->fallthrough_addr)

#define pt_get_fallthrough_addr(b) (b)->fallthrough_addr

static inline struct pt_block *
pt_get_fallthrough_block(struct pt_block *block)
{
	if (unlikely(!block->fallthrough_block))
		block->fallthrough_block = pt_get_block(pt_get_fallthrough_addr(block));
	return block->fallthrough_block;
}

#define pt_get_target_addr(b) (b)->target_addr

static inline struct pt_block *
pt_get_target_block(struct pt_block *block)
{
	if (unlikely(!block->target_block))
		block->target_block = pt_get_block(pt_get_target_addr(block));
	return block->target_block;
}

#define pt_block_is_call(b) ((b)->kind == PT_BLOCK_DIRECT_CALL || (b)->kind == PT_BLOCK_INDIRECT_CALL)

#define pt_block_is_ret(b) ((b)->kind == PT_BLOCK_RET)

#define pt_block_is_direct(b) ((b)->kind == PT_BLOCK_DIRECT_CALL || (b)->kind == PT_BLOCK_DIRECT_JMP)

#define pt_block_is_cond(b) ((b)->kind == PT_BLOCK_COND_JMP)

#define pt_block_is_syscall(b) ((b)->kind == PT_BLOCK_SYSCALL)

static inline void
pt_push_raw(pt_event *stack, int *index, pt_event event)
{
	UNHANDLED(*index == STACK_MAX);
	stack[(*index)++] = event;
}

#define pt_push_call(stack, pindex, event) pt_push_raw(stack, pindex, event)

static inline void
pt_push_ret(pt_event *stack, int *index, pt_event event)
{
	int i;

	for (i = *index - 1; ; i--) {
		if (i < 0) {
			*index = 0;
			break;
		}

		if (!PT_EVENT_IS_CALL(stack[i])) {
			*index = i + 1;
			break;
		}

		if (stack[i] + event == 0) {
			*index = i;
			return;
		}
	}

	pt_push_raw(stack, index, event);
}

static inline void pt_process_buffer(struct pt_buffer *buf)
{
	int i;
	pt_event event;
	struct topa *topa = buf->topa;

	/* global shadow stack check! */
	for (i = 0; i < buf->index; i++) {
		event = buf->stack[i];
		if (PT_EVENT_IS_CALL(event)) {
			pt_push_call(topa->stack, &topa->index, event);
		} else {
			pt_push_ret(topa->stack, &topa->index, event);
			if (PT_EVENT_IS_RET(topa->stack[0])) {
				// Notify
				pt_fail_topa(topa, "unmatched return: %llx",
						(u64) -topa->stack[0]);

				if (_PT_TRACE_SHADOW_STACK) {
					pt_trace_shadow_stack_trigger = true;
				}

				return;
			}
		}
	}

	if (buf->child_topa) {
		NEVER(buf->child_topa->index);
		buf->child_topa->index = topa->index;
		memcpy(buf->child_topa->stack, topa->stack,
				topa->index * sizeof(pt_event));
	}
}

static void pt_submit_buffer(struct pt_buffer *buf)
{
	unsigned long flags;
	struct completion *notifier;
	struct pt_buffer *child_buf;
	struct topa *child_topa, *topa = buf->topa;
	u64 sequence = buf->sequence;

	spin_lock_irqsave(&topa->buffer_list_sl, flags);
	if (topa->n_processed == sequence) {
		do {
			list_del(&buf->entry);
			spin_unlock_irqrestore(&topa->buffer_list_sl, flags);
			pt_process_buffer(buf);
			if ((child_topa = buf->child_topa) && topa->failed)
				pt_fail_topa(child_topa, "parent failed");
			if (child_topa) {
				child_buf = kmem_cache_alloc(pt_buffer_cache, GFP_KERNEL);
				INIT_LIST_HEAD(&child_buf->entry);
				child_buf->topa = child_topa;
				child_buf->child_topa = NULL;
				child_buf->notifier = NULL;
				child_buf->sequence = sequence;
				child_buf->raw = NULL;
				child_buf->size = 0;
				child_buf->index = 0;
				child_buf->stack = NULL;
				pt_submit_buffer(child_buf);
			}
			topa->n_processed++;
			notifier = buf->notifier;
			free_pages((unsigned long) buf->stack, STACK_PAGE_ORDER);
			kmem_cache_free(pt_buffer_cache, buf);
			if (notifier) {
				complete(notifier);
				return;
			}
			/* find the next buffer */
			sequence++;
			spin_lock_irqsave(&topa->buffer_list_sl, flags);
			list_for_each_entry(buf, &topa->buffer_list, entry)
				if (buf->sequence == sequence)
					break;
		} while (&buf->entry != &topa->buffer_list);
	} else {
		list_add_tail(&buf->entry, &topa->buffer_list);
	}
	spin_unlock_irqrestore(&topa->buffer_list_sl, flags);
}

#define pt_tsx_begin(stack, pindex) pt_push_raw(stack, pindex, 0)

#define pt_tsx_abort(stack, pindex, xbegin) \
do { \
	NEVER(xbegin < 0); \
	*(pindex) = xbegin; \
} while (0)

static inline void
pt_tsx_commit(pt_event *stack, int *index, int xbegin)
{
	int i, old_index = *index;

	NEVER(xbegin < 0);
	*index = xbegin;

	for (i = xbegin + 1; i < old_index; i++) {
		if (PT_EVENT_IS_CALL(stack[i]))
			pt_push_call(stack, index, stack[i]);
		else
			pt_push_ret(stack, index, stack[i]);
	}
}

static void
pt_recover(char *buffer, u32 size, pt_event stack[], int *index)
{
	u64 bytes_remained;
	enum pt_packet_kind kind;
	unsigned char *packet;
	u64 packet_len;
	u64 last_ip = 0;
	u64 curr_addr = 0;
	u8 mask;
	u8 bit_selector;
	struct pt_block *curr_block = NULL;
#define RETC_STACK_SIZE 64
	struct pt_block *retc[RETC_STACK_SIZE] = {0};
	u32 retc_index = 0;
	u8 mode_payload;
	int si = *index;
	int xbegin = -1;
	unsigned short src_index = POLICY_RSVD;

#define PUSH_CALL(addr) pt_push_call(stack, &si, addr)
#define PUSH_RET(addr) \
do { \
	if (*(u64 *)(addr) != 0x0f0000000fc0c748 || *(u8 *)(addr + 8) != 0x05) \
		pt_push_ret(stack, &si, -addr); \
} while (0)

#define NEXT_PACKET() \
do { \
	bytes_remained -= packet_len; \
	packet += packet_len; \
	kind = pt_get_packet(packet, bytes_remained, &packet_len); \
} while (0)

#define FOLLOW_DIRECT_UNTIL(cond) \
do { \
	while (pt_block_is_direct(curr_block) && (!(cond))) { \
		if (pt_block_is_call(curr_block)) { \
			PUSH_CALL(pt_get_fallthrough_addr(curr_block)); \
			retc[retc_index] = curr_block; \
			retc_index = (retc_index + 1) % RETC_STACK_SIZE; \
		} \
		curr_block = pt_get_target_block(curr_block); \
	} \
} while(0)

#define FOLLOW_DIRECT() FOLLOW_DIRECT_UNTIL(false)

	packet = buffer;
	bytes_remained = size;

	while (bytes_remained > 0) {
		kind = pt_get_packet(packet, bytes_remained, &packet_len);
		NEVER(kind == PT_PACKET_ERROR);
		NEVER(packet_len == 0 || packet_len > bytes_remained);

		switch (kind) {
		case PT_PACKET_TNTSHORT:
			mask = (u8)*packet;
			bit_selector = 1 << (fls(mask) - 1);
			NEVER((mask & bit_selector) == 0);
			do {
				FOLLOW_DIRECT();
				if (mask & (bit_selector >>= 1)) {
					if (pt_block_is_ret(curr_block)) {
						retc_index = (retc_index + RETC_STACK_SIZE - 1) % RETC_STACK_SIZE;
						PUSH_RET(pt_get_fallthrough_addr(retc[retc_index]));
						curr_block = pt_get_fallthrough_block(retc[retc_index]);
					} else {
						curr_block = pt_get_target_block(curr_block);
					}
				} else {
					NEVER(pt_block_is_ret(curr_block));
					curr_block = pt_get_fallthrough_block(curr_block);
				}
			} while (bit_selector != 2);
			break;

		case PT_PACKET_TIP:
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			src_index = POLICY_RSVD;

			if (curr_block) {
				FOLLOW_DIRECT();
				NEVER(pt_block_is_cond(curr_block));

				if (pt_block_is_ret(curr_block)) {
					PUSH_RET(curr_addr);
				} else {
					src_index = curr_block->src_index;
					if (pt_block_is_call(curr_block)) {
						PUSH_CALL(pt_get_fallthrough_addr(curr_block));
						retc[retc_index] = curr_block;
						retc_index = (retc_index + 1) % RETC_STACK_SIZE;
					}
				}
			}

			curr_block = pt_get_block(curr_addr);

			if (!POLICY_CHECK(src_index, curr_block->dst_index)) {
				// Notify
				pt_print("forward-edge violation: %u -> %u (%llx)\n",
						src_index, curr_block->dst_index, curr_addr);

				if (_PT_TRACE_FWD_EDGE) {
					pt_trace_fwd_edge_trigger = true;
				}
			}
			break;

		case PT_PACKET_TIPPGE:
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			curr_block = pt_get_block(curr_addr);
			break;

		case PT_PACKET_TIPPGD:
			if (curr_block)
				FOLLOW_DIRECT();
			pt_get_and_update_ip(packet, packet_len, &last_ip);
			break;

		case PT_PACKET_FUP:
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			FOLLOW_DIRECT_UNTIL(pt_in_block(curr_addr, curr_block));
			curr_block = NULL;
			break;

		case PT_PACKET_PSB:
			last_ip = 0;
			do {
				NEXT_PACKET();
				if (kind == PT_PACKET_FUP)
					pt_get_and_update_ip(packet, packet_len, &last_ip);
			} while (kind != PT_PACKET_PSBEND && kind != PT_PACKET_OVF);
			break;

		case PT_PACKET_MODE:
			mode_payload = *(packet+1);
			switch ((mode_payload >> 5)) {
			case 0: /* MODE.Exec */
				UNHANDLED((mode_payload & (u8)0x3) != 1);
				break;
			case 1: /* MODE.TSX */
				do {
					NEXT_PACKET();
				} while (kind != PT_PACKET_FUP);
				curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
				FOLLOW_DIRECT_UNTIL(pt_in_block(curr_addr, curr_block));

				switch ((mode_payload & (u8)0x3)) {
				case 0:
					pt_tsx_commit(stack, &si, xbegin);
					xbegin = -1;
					break;
				case 1:
					NEVER(xbegin != -1);
					pt_tsx_begin(stack, &si);
					xbegin = si - 1;
					break;
				case 2:
					pt_tsx_abort(stack, &si, xbegin);
					xbegin = -1;
					curr_block = NULL;
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}
			break;

		case PT_PACKET_OVF:
			pt_print("OVF\n");
			do {
				NEXT_PACKET();
			} while (kind != PT_PACKET_FUP && kind != PT_PACKET_TIPPGE);
			curr_addr = pt_get_and_update_ip(packet, packet_len, &last_ip);
			curr_block = pt_get_block(curr_addr);
			break;

		default:
			break;
		}

		bytes_remained -= packet_len;
		packet += packet_len;
	}

	*index = si;
}

static void pt_work(struct work_struct *work)
{
	mm_segment_t oldfs;
	struct mm_struct *mm;
	struct pt_buffer *buf = (struct pt_buffer *) work;

	// Log the buffer first
	pt_log_buffer(buf);

	// Then go ahead and build the mirror pages
	oldfs = get_fs();
	mm = buf->topa->task->mm;
	set_fs(USER_DS);
	use_mm(mm);
	stac();

	if (!buf->topa->failed)
		pt_recover(buf->raw, buf->size, buf->stack, &buf->index);

	kmem_cache_free(pt_trace_cache, buf->raw);
	pt_submit_buffer(buf);

	clac();
	unuse_mm(mm);
	set_fs(oldfs);

	// Write any existing ring items - syscall
	if (pt_trace_syscall_trigger && pt_trace_syscall_trigger_rb_index > -1 &&
		(pt_trace_syscall_trigger_rb_index + _PT_TRACE_SYSCALL_WIDTH)%RING_BUFFER_COUNT >= (ring_buffer->curr->index)%RING_BUFFER_COUNT)
	{
		// Write the existing ring buffers
		pt_print("  Dumping trace from syscall trigger. Called on %d, dumped on %d, width is %d.", pt_trace_syscall_trigger_rb_index, ring_buffer->curr->index, _PT_TRACE_SYSCALL_WIDTH);
		ring_buffer->print_buffer(_PT_TRACE_SYSCALL_WIDTH * 2);

		// Unset the triggers
		pt_trace_syscall_trigger = false;
		pt_trace_syscall_trigger_rb_index = -1;
	}

	// Write any existing ring items - forward edge
	if (pt_trace_fwd_edge_trigger)
	{
		// Write the existing ring buffers
		pt_print("  Dumping trace from CFI forward edge trigger.");
		ring_buffer->print_buffer(_PT_TRACE_FWD_EDGE_WIDTH);

		// Unset the trigger
		pt_trace_fwd_edge_trigger = false;
	}

	// Write any existing ring items - shadow stack
	if (pt_trace_shadow_stack_trigger)
	{
		// Write the existing ring buffers
		pt_print("  Dumping trace from CFI shadow stack trigger.");
		ring_buffer->print_buffer(_PT_TRACE_SHADOW_STACK_WIDTH);

		// Unset the trigger
		pt_trace_shadow_stack_trigger = false;
	}
}

static void pt_tasklet(unsigned long data)
{
	struct pt_buffer *buf = (struct pt_buffer *) data;

	queue_work(pt_wq, &buf->work);
}

static int pt_move_trace_to_work(struct topa *topa, u32 size,
		struct topa *child_topa, bool waiting)
{
	struct pt_buffer *buf;
	DECLARE_COMPLETION(notifier);

	buf = kmem_cache_alloc(pt_buffer_cache, GFP_ATOMIC);
	if (!buf)
		goto fail;

	INIT_WORK(&buf->work, pt_work);
	tasklet_init(&buf->tasklet, pt_tasklet, (unsigned long) buf);
	INIT_LIST_HEAD(&buf->entry);
	buf->topa = topa;
	buf->child_topa = child_topa;
	buf->notifier = waiting? &notifier: NULL;
	buf->size = size;
	buf->index = 0;
	buf->raw = topa->raw;

	buf->stack = (pt_event *) __get_free_pages(GFP_ATOMIC,
			STACK_PAGE_ORDER);
	if (!buf->stack)
		goto free_buf;

	buf->sequence = topa->sequence++;

	tasklet_schedule(&buf->tasklet);

	if (waiting)
		wait_for_completion(&notifier);

	return 0;

free_buf:
	kmem_cache_free(pt_buffer_cache, buf);
fail:
	return -ENOMEM;
}

static void pt_flush_trace(struct topa *child_topa, bool waiting)
{
	u32 size;
	struct topa *topa;
	void *new_buffer;

	NEVER(pt_enabled());

	topa = phys_to_virt(pt_topa_base());
	if (topa->failed && !child_topa && !waiting)
		goto end;

	size = pt_topa_offset() + (pt_topa_index()? TOPA_BUFFER_SIZE: 0);

	new_buffer = (void *) kmem_cache_alloc(pt_trace_cache, GFP_ATOMIC);
	if (!new_buffer)
		goto failed;

	if (pt_move_trace_to_work(topa, size, child_topa, waiting) < 0)
		goto free_new_buffer;

	do_setup_topa(topa, new_buffer);

end:
	wrmsrl(MSR_IA32_RTIT_STATUS, 0);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, 0);
	return;

free_new_buffer:
	kmem_cache_free(pt_trace_cache, new_buffer);
failed:
	UNHANDLED(child_topa || waiting);
	pt_fail_topa(topa, "out of memory");
	goto end;
}

static struct topa *pt_alloc_topa(struct task_struct *task)
{
	struct topa *topa;
	void *raw;

	topa = (struct topa *) __get_free_pages(GFP_KERNEL, STACK_PAGE_ORDER);
	if (!topa)
		goto fail;

	raw = (void *) kmem_cache_alloc(pt_trace_cache, GFP_KERNEL);
	if (!raw)
		goto free_topa;

	pt_setup_topa(topa, raw, task);

	return topa;

free_topa:
	free_pages((unsigned long) topa, STACK_PAGE_ORDER);
fail:
	return NULL;
}

static bool pt_should_monitor(struct task_struct *task)
{
	char *path, *buf;
	size_t path_len, monitor_len;
	struct mm_struct *mm;
	bool monitored = false;

	monitor_len = strlen(pt_monitor);
	if (!monitor_len)
		return false;

	mm = task->mm;
	if (!mm)
		return false;

	down_read(&mm->mmap_sem);

	if (!mm->exe_file)
		goto up_read_sem;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		goto up_read_sem;

	path = d_path(&task->mm->exe_file->f_path, buf, PATH_MAX);
	path_len = strlen(path);

	if (monitor_len > path_len)
		goto free_buf;

	monitored = strncmp(path + (path_len - monitor_len),
			pt_monitor, monitor_len) == 0;

free_buf:
	kfree(buf);
up_read_sem:
	up_read(&mm->mmap_sem);
	return monitored;
}

static unsigned long pt_mirror_page(unsigned long addr, unsigned long len)
{
	int i;
	unsigned long ret, populate;

	for (i = 1; i <= NUM_MIRROR_LAYER; i++) {
		down_write(&current->mm->mmap_sem);
		ret = do_mmap_pgoff(NULL, MIRROR(addr, i), len, PROT_READ
				| PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS
				| MAP_FIXED, 0, &populate);
		up_write(&current->mm->mmap_sem);
		UNHANDLED(IS_ERR_VALUE(ret));
		NEVER(populate);
	}

	return ret;
}

void pt_pre_execve(void)
{
	if (!pt_enabled())
		return;

	pt_pause();
	pt_flush_trace(NULL, true);
	pt_resume();
}

static void pt_clear_rlimit(struct task_struct *task)
{
	task->signal->rlim[RLIMIT_MEMLOCK] = (struct rlimit) {
		RLIM64_INFINITY, RLIM64_INFINITY
	};

	task->signal->rlim[RLIMIT_AS] = (struct rlimit) {
		RLIM64_INFINITY, RLIM64_INFINITY
	};
}

static inline struct topa *pt_attach(struct task_struct *task)
{
	struct topa *topa = pt_alloc_topa(task);
	UNHANDLED(!topa);

	if (task == current)
		pt_setup_msr(topa);
	else
		pt_setup_xsave(topa, &task->thread.fpu.state.xsave);

	atomic64_inc(&pt_flying_tasks);

	return topa;
}

static inline void pt_detach(void)
{
	struct topa *topa;

	NEVER(!pt_enabled());
	pt_pause();

	topa = phys_to_virt(pt_topa_base());
	NEVER(topa->task != current);

	pt_move_trace_to_work(topa, pt_topa_offset(), NULL, true);

	free_pages((unsigned long) topa, STACK_PAGE_ORDER);

	atomic64_dec(&pt_flying_tasks);
}

void pt_on_execve(void)
{
	unsigned long len, ret, populate;
	struct vm_area_struct *vma;

	if (pt_enabled()) {
		/* execve()'ed from a task under tracing */
		pt_debug("[cpu:%d,pid:%d] execve: stop tracing...\n",
				smp_processor_id(), current->pid);
		pt_detach();
	}

	if (!pt_should_monitor(current))
		return;

	pt_debug("[cpu:%d,pid:%d] execve: %s\n", smp_processor_id(),
			current->pid, pt_monitor);

	pt_log_process(current);

	pt_clear_rlimit(current);

	/* fine without locking because we are in execve */
	for (vma = current->mm->mmap; vma; vma = vma->vm_next) {
		if (!(vma->vm_flags & VM_EXEC))
			continue;
		if (vma->vm_flags & VM_WRITE)
			continue;
		NEVER(!(vma->vm_flags & VM_READ));
		len = vma->vm_end - vma->vm_start;
		pt_log_xpage(current, vma->vm_start, 0, len);
		pt_mirror_page(vma->vm_start, len);
	}

	/* map the policy matrix */
	ret = do_mmap_pgoff(NULL, POLICY_MATRIX, POLICY_SIZE, PROT_READ
			| PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			0, &populate);
	UNHANDLED(IS_ERR_VALUE(ret));
	NEVER(populate);

	pt_attach(current);
}

void pt_on_exit(void)
{
	if (!pt_enabled())
		return;

	pt_debug("[cpu:%d,pid:%d] exit: %s\n", smp_processor_id(),
			current->pid, pt_monitor);
	pt_detach();

	// Exiting the program - dump the rest of the trace
	// Do this AFTER we detach, because the pt_detach function will wait
	// for the rest of the buffers to be written to disk before we print.
	if (_PT_TRACE_PROC_END) {
		ring_buffer->print_buffer(0); // Print all		
	}
}

int pt_on_interrupt(struct pt_regs *regs)
{
	int pt_on;
	u64 *xregs;

	if (!strlen(pt_monitor))
		return -ENOSYS;

	pt_on = pt_enabled();
	if (pt_on) /* off if triggered upon disabling PT */
		pt_pause();

	NEVER(pt_topa_index() == 0);
	pt_flush_trace(NULL, false);

#define is_xsaves(ip) ((*(unsigned int *)(ip) & 0xffffff) == 0x2fc70f)
	if (pt_on) {
		pt_resume();
	} else if (is_xsaves(regs->ip - 3)) {
		xregs = (u64 *) get_xsave_addr((struct xregs_state *) regs->di,
				XSTATE_INTEL_PT);
		xregs[PT_XSTATE_STATUS] = 0;
		xregs[PT_XSTATE_OUTPUT_MASK] = 0;
	}

	return 0;
}

void pt_on_clone(struct task_struct *child)
{
	struct topa *child_topa, *topa;

	if (!pt_enabled())
		return;

	child_topa = pt_attach(child);

	pt_debug("[cpu:%d,pid:%d] clone: %d (%llx)\n", smp_processor_id(),
			current->pid, child->pid, virt_to_phys(child_topa));

	if (child->tgid == child->pid) {
		NEVER(!pt_enabled());
		/* setup initial sequence numbers */
		topa = phys_to_virt(pt_topa_base());
		child_topa->sequence = topa->sequence + 1;
		child_topa->n_processed = topa->sequence;
		/* flush the parent's trace */
		pt_pause();
		pt_flush_trace(child_topa, true);
		pt_resume();
	}

	if (child->tgid == child->pid) {
		pt_log_fork(current, child);
		pt_log_process(child);
	} else {
		pt_log_thread(child);
	}

	pt_clear_rlimit(current);
	pt_clear_rlimit(child);
}

void pt_on_mmap(struct file *file, unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long pgoff)
{
	unsigned long actual_len;

	if (!pt_enabled())
		return;
	if (!(prot & PROT_EXEC))
		return;
	if (IS_ERR_VALUE(addr))
		return;
	if (prot & PROT_WRITE)
		return;

	actual_len = file? file->f_inode->i_size
		- (pgoff << PAGE_SHIFT): len;
	actual_len = len > actual_len? actual_len: len;
	pt_log_xpage(current, addr, actual_len, PAGE_ALIGN(len));
	pt_mirror_page(addr, len);
}

void pt_on_syscall(struct pt_regs *regs)
{
	if (!pt_enabled())
		return;

	switch (regs->orig_ax) {
	case __NR_mmap:
	case __NR_mprotect:
		if (!(regs->dx & PROT_EXEC))
			return;
		break;
	case __NR_sendmsg:
	case __NR_sendmmsg:
	case __NR_sendto:
		break;
	default:
		return;
	}

	pt_pause();
	pt_trace_on_syscall();
	pt_flush_trace(NULL, true);
	pt_resume();
}

static int __init pt_init(void)
{
	int pt_ring_buffer_success;
	int ret = -ENOMEM;

	if (!pt_avail())
		return -ENXIO;

	/* create a cache for buffers to enable dynamic (de)allocation */
	pt_buffer_cache = kmem_cache_create("pt_buffer_cache",
			sizeof(struct pt_buffer), 0, 0, NULL);
	if (!pt_buffer_cache)
		goto fail;

	/* create a cache for blocks */
	pt_block_cache = kmem_cache_create("pt_block_cache",
			sizeof(struct pt_block), 0, 0, NULL);
	if (!pt_block_cache)
		goto destroy_buffer_cache;

	/* create a cache for filled traces */
	pt_trace_cache = kmem_cache_create("pt_trace_cache",
			TOPA_BUFFER_SIZE + PAGE_SIZE, TOPA_BUFFER_SIZE,
			0, NULL);
	if (!pt_trace_cache)
		goto destroy_block_cache;

	/* Now allocate memory for the PT ring buffer */
	pt_ring_buffer_success = initialize_ring_buffer();
	if (pt_ring_buffer_success < 0)
		goto destroy_block_cache;

	/* setup the workqueue for async computation */
	ret = pt_wq_setup();
	if (ret < 0)
		goto destroy_trace_cache;

	/* create pt_monitor file */
	ret = pt_monitor_setup();
	if (ret < 0)
		goto destroy_wq;

	memset(pt_monitor, 0, PATH_MAX);

	/* create pt_policy file */
	ret = pt_policy_setup();
	if (ret < 0)
		goto destroy_monitor;
		//goto destroy_mode;

	/* create pt_trace_syscall file */
	ret = pt_trace_syscall_setup();
	if (ret < 0)
		goto destroy_policy;

	/* create pt_trace_fwd_edge file */
	ret = pt_trace_fwd_edge_setup();
	if (ret < 0)
		goto destroy_trace_syscall;

	/* create pt_trace_shadow_stack file */
	ret = pt_trace_shadow_stack_setup();
	if (ret < 0)
		goto destroy_trace_fwd_edge;

	pt_print("initialized (distorm version: %x)\n", distorm_version());

	return ret;

destroy_trace_fwd_edge:
	pt_trace_fwd_edge_destroy();
destroy_trace_syscall:
	pt_trace_syscall_destroy();
destroy_policy:
	pt_policy_destroy();
destroy_monitor:
	pt_monitor_destroy();
destroy_wq:
	pt_wq_destroy();
destroy_trace_cache:
	kmem_cache_destroy(pt_trace_cache);
destroy_block_cache:
	kmem_cache_destroy(pt_block_cache);
destroy_buffer_cache:
	kmem_cache_destroy(pt_buffer_cache);
fail:
	return ret;
}

static void __exit pt_exit(void)
{
	NEVER(pt_enabled());

	pt_close_logfile();
	pt_trace_shadow_stack_destroy();
	pt_trace_fwd_edge_destroy();
	pt_trace_syscall_destroy();
	pt_policy_destroy();
	pt_monitor_destroy();
	pt_wq_destroy();
	kmem_cache_destroy(pt_trace_cache);
	kmem_cache_destroy(pt_block_cache);
	kmem_cache_destroy(pt_buffer_cache);
}

module_init(pt_init);
module_exit(pt_exit);
MODULE_LICENSE("GPL");
