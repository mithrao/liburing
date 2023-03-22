#include "liburing_bpf.h"
#include "uring.h"

#define MAIN_CQ                 0
#define IOSQE_FIXED_FILE        (1U << IOSQE_FIXED_FILE_BIT)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, unsigned long);
} arr SEC(".maps");

struct bpf_ctx {
	struct __kernel_timespec ts;
};

#define ARR_SLOT        0
#define REENTER_SLOT    10

static void writev(u32 kv, unsigned long v)
{
    unsigned long *val = bpf_map_lookup_elem(&arr, &kv);
    if (val) *val = v;
}

static unsigned long readv(u32 kv)
{
    unsigned long *val = bpf_map_lookup_elem(&arr, &kv);
    return val ? *val : -1UL;
}

SEC("iouring")
int test(struct io_uring_bpf_ctx *ctx)
{
    struct io_uring_sqe sqe;
    struct io_uring_cqe cqe;
    u32 key = 0;
    long *val;
    int ret, cq_idx = 1;
    unsigned long secret, f1;
    __u32 vvv;
    u64 *uptr;

    /* will be called twice, see CQ waiting at the end */
    if (readv(REENTER_SLOT))
        return IORING_BPF_OK;
    writev(REENTER_SLOT, 1);

    /* just write some values to a BPF array */
    writev(ARR_SLOT, 11);

    /* emit CQE to the main CQ */
    iouring_emit_cqe(bpf_ctx, 0, 3, 13, 0);

    /* emit 2 CQEs to a second CQ and reap them */
    iouring_emit_cqe(bpf_ctx, cq_idx, 4, 17, 0);
    iouring_emit_cqe(bpf_ctx, cq_idx, 5, 19, 0);

    /* reap just submitted CQEs */
    ret = iouring_reap_cqe(bpf_ctx, cq_idx, &cqe, sizeof(cqe));
    writev(ARR_SLOT + 1, ret ? ret : cqe.user_data);
    ret = iouring_reap_cqe(bpf_ctx, cq_idx, &cqe, sizeof(cqe));
    writev(ARR_SLOT + 2, ret ? ret : cqe.user_data);

    /* submit a nop request */
    io_uring_prep_nop(&sqe);
    sqe.user_data = 2;
    sqe.flags = 0;
    ret = bpf_io_uring_submit(bpf_ctx, &sqe, sizeof(sqe));
    writev(ARR_SLOT + 3, ret < 0 ? ret : 21);

    /* make sure we can read ctx->user_data */
    writev(ARR_SLOT + 4, ctx->user_data);

    /* read userspace memory */
    uptr = (u64 *)(unsigned long) ctx->user_data;
    bpf_copy_from_user(&secret, sizeof(secret), uptr);
    writev(ARR_SLOT + 5, secret);

    /* copy to userspace */
    secret = 31;
    bpf_copy_to_user(uptr, &secret, sizeof(secret));

    ctx->wait_idx = 0;
    ctx->wait_nr = 1;

    return IORING_BPF_WAIT;
}

SEC("iouring")
int counting(struct io_uring_bpf_ctx *ctx)
{
    struct counting_ctx *uctx = (void *)(unsigned long)ctx->user_data;
    struct io_uring_sqe sqe;
    struct io_uring_cqe cqe;
    unsigned long v = readv(0);
    unsigned int cq_idx = 1;

    if (v > 10)
        return IORING_BPF_OK;
    writev(0, v + 1);

    if (v != 0) {
        int ret = bpf_io_uring_reap_cqe(ctx, cq_idx, &cqe, sizeof(cqe));
        writev(1, ret ? ret : cqe.user_data);
    }

    io_uring_prep_timeout(&sqe, &uctx->ts, 0, 0);
    sqe.user_data = 5;
    sqe.cq_idx = cq_idx;
    bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));

    ctx->wait_idx = cq_idx;
    ctx->wait_nr = 1;
    return IORING_BPF_WAIT;
}

SEC("iouring")
int pingpong(struct io_uring_bpf_ctx *ctx)
{
    struct ping_ctx *uctx = (void *)(unsigned long)ctx->user_data;
    struct io_uring_sqe sqe;
    struct io_uring_cqe cqe;
    unsigned long v;
    int idx, ret, iter;
    int cq_idx2;

    bpf_copy_from_user(&idx, sizeof(idx), &uctx->idx);
    if (!readv(idx)) {
        writev(idx, 1);
wait:
        ctx->wait_idx = idx + 1;
        ctx->wait_nr = 1;
        return IORING_BPF_WAIT;
    }
    ret = bpf_io_uring_reap_cqe(ctx, idx + 1, &cqe, sizeof(cqe));
    iter = cqe.user_data;
    cq_idx2 = (idx ^ 1) + 1;
    bpf_io_uring_emit_cqe(ctx, cq_idx2, iter + 1, 0, 0);

    if (iter < 20)
        goto wait;
    writev(idx + 5, iter);
    return IORING_BPF_OK;
}

SEC("iouring")
int write_file(struct io_uring_bpf_ctx *ctx)
{
    const int off_idx = 1, infl_idx = 0;
    struct io_uring_sqe sqe;
    struct io_uring_cqe cqe;
    void *buf = (void *)(unsigned long)ctx->user_data;
    u64 ret, i, inflight = readv(infl_idx);
    u64 cur_off = readv(off_idx);

    for (i = 0; i < FILL_QD; i++) {
        if (inflight) {
            ret = bpf_io_uring_reap_cqe(ctx, 1, &cqe, sizeof(cqe));
            inflight--;
        }
    }
    for (i = 0; i < FILL_QD; i++) {
        if (inflight >= FILL_QD || cur_off >= FILL_BLOCKS)
            break;
        io_uring_prep_write(&sqe, 0, buf, FILL_BLOCK_SIZE, 
                            cur_off * FILL_BLOCK_SIZE);
        sqe.flags = IOSQE_FIXED_FILE;
        sqe.cq_idx = 1;
        ret = bpf_io_uring_submit(ctx, &sqe, sizeof(sqe));
        inflight++;
        cur_off++;
    }
    
    writev(off_idx, cur_off);
    writev(infl_idx, inflight);
	if (!inflight)
		return IORING_BPF_OK;
    ctx->wait_idx = 1;
    ctx->wait_nr = inflight;
    return IORING_BPF_WAIT;
}

char LICENSE[] SEC("license") = "GPL";