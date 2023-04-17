#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "uring.h"

static long (*iouring_register_restrictions) (void *ctx, struct io_uring_restriction * res, u32 nr_res) = (void *) 168;
static long (*iouring_register_enable_rings) (void *ctx) = (void *) 169;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, unsigned long);
} arr SEC(".maps");

/*
 * BPF register restrictions
 */
SEC("iouring")
int register_restrictions(struct io_uring_bpf_ctx *ctx)
{
	struct io_uring_restriction res[2];
    int ret;

	res[0].opcode = IORING_RESTRICTION_SQE_OP;
	res[0].sqe_op = IORING_OP_WRITEV;

	res[1].opcode = IORING_RESTRICTION_SQE_OP;
	res[1].sqe_op = IORING_OP_WRITE;

    /*
     * io_uring_register_restrictions(3) - setup the operation whitelist
     * @struct io_uring *ring
     * @struct io_uring_restriction *res
     * @unsigned int nr_res
     */
    ret = iouring_register_restrictions(ctx, res, 2);
	if (ret < 0)
		return 0;
	ret = iouring_register_enable_rings(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
