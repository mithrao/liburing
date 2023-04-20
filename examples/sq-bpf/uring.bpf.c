#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "uring.h"

static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    __u64 offset)
{
	sqe->opcode = op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->__pad2[0] = sqe->__pad2[1] = sqe->__pad2[2] = 0;
}

static inline void io_uring_prep_nop(struct io_uring_sqe *sqe)
{
	io_uring_prep_rw(IORING_OP_NOP, sqe, -1, 0, 0, 0);
}

static long (*bpf_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167;
static long (*sqring_queue_sqe) (void *ctx, struct io_uring_sqe *sqe, u32) = (void *) 168;
static long (*sqring_sqe_entries) (void *ctx) = (void *) 169;
static long (*sqring_do_iopoll) (void *ctx, unsigned int to_submit) = (void *) 170;
static long (*sqring_reap_sqe) (void *ctx, struct io_uring_sqe *sqe, u32) = (void *) 171;
static long (*sqring_submit_sqe) (void *ctx, struct io_uring_sqe *sqe, u32) = (void *) 172;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, unsigned long);
} arr SEC(".maps");

#define ARR_SLOT 0
#define REENTER_SLOT 10

static void writev(u32 kv, unsigned long v)
{
	unsigned long *val = bpf_map_lookup_elem(&arr, &kv);

	if (val)
		*val = v;
}

static unsigned long readv(u32 kv)
{
	unsigned long *val = bpf_map_lookup_elem(&arr, &kv);

	return val ? *val : -1UL;
}

/*
 * just a set of use examples for features
 */
SEC("sqring")
int test(struct sqring_bpf_ctx *ctx)
{
	unsigned int to_submit = 0, nr_events;
	int i, ret = 0;
	struct io_uring_sqe sqe = {};

	/* make sure we don't repeat it twice */
	if (readv(REENTER_SLOT))
		return 0;
	writev(REENTER_SLOT, 1);

	// just write some value
	writev(ARR_SLOT, 11);
	to_submit = sqring_sqe_entries(ctx);
	// to_submit == 0 and always 0!!!
	writev(ARR_SLOT + 1, to_submit);
	nr_events = sqring_do_iopoll(ctx, to_submit);
	writev(ARR_SLOT + 2, nr_events);
	writev(ARR_SLOT + 3, 13);

	// for (i = 0; i < 2; i++) {
	// 	ret = sqring_reap_sqe(ctx, &sqe, sizeof(sqe));
	// 	if (ret < 0) {
	// 		ret = -i;
	// 		break;
	// 	}
	// 	writev(ARR_SLOT + 4 + i, sqe.user_data);
	// 	ret = sqring_submit_sqe(ctx, &sqe, sizeof(sqe));
	// 	if (ret <= 0) {
	// 		break;
	// 	}
	// }

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
