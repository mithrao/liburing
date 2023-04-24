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

static long (*cqring_queue_sqe)(void *ctx, struct io_uring_sqe *sqe, u32) = (void *) 164;
static long (*cqring_emit_cqe)(void *ctx, u32 cq, u64 data, u32 res, u32 flags) = (void *) 165;
static long (*cqring_reap_cqe)(void *ctx, u32 cq, struct io_uring_cqe *cqe, u32) = (void *) 166;
static long (*bpf_copy_to_user)(void *user_ptr, const void *src, __u32 size) = (void *) 167;

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
SEC("cqring")
int test(struct cqring_bpf_ctx *ctx)
{
	struct io_uring_sqe sqe;
	struct io_uring_cqe cqe = {};
	u32 key = 0;
	long *val;
	int ret, cq_idx = 1;
	unsigned long secret, f1;
	__u32 vvv;
	u64 *uptr;

	/* make sure we don't repeat it twice */
	if (readv(REENTER_SLOT))
		return 0;
	writev(REENTER_SLOT, 1);

	// just write some value
	writev(ARR_SLOT, 10);

	ret = cqring_reap_cqe(ctx, 0, &cqe, sizeof(cqe));
	writev(ARR_SLOT + 1, ret ? ret : cqe.user_data);

	// emit CQE to the main CQ
	cqring_emit_cqe(ctx, 0, 3, 13, 0);

	// submit nop SQE
	io_uring_prep_nop(&sqe);
	sqe.user_data = 2;
	sqe.flags = 0;
	ret = cqring_queue_sqe(ctx, &sqe, sizeof(sqe));
	writev(ARR_SLOT + 2, ret < 0 ? ret : 21);

	// write back user_data
	writev(ARR_SLOT + 3, sqe.user_data);

	// demo for reading from userspace
	uptr = (u64 *)(unsigned long)ctx->user_data;
	bpf_copy_from_user(&secret, sizeof(secret), uptr);
	writev(ARR_SLOT + 4, secret);

	// copy to userspace
	secret = 31;
	bpf_copy_to_user(uptr, &secret, sizeof(secret));

	ctx->wait_idx = 0;
	ctx->wait_nr = 1;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";