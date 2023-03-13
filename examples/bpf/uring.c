// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <assert.h>
// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
#include "../../../linux/tools/lib/bpf/bpf.h"
#include "../../../linux/tools/lib/bpf/libbpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "liburing.h"
#include "../../src/syscall.h"
#include "uring.skel.h"

#define NSEC_PER_SEC		1000000000ULL

int main(int argc, char const *argv[])
{
    struct io_uring_params param;
    struct io_uring ring;
    struct io_uring_cqe *cqe;
    struct io_uring_sqe *sqe;
    struct uring_bpf *obj;
    int ret, prog_fd;
    __u32 cq_sizes = 128;
    unsigned long secret = 29;

    /* 1 additional CQ, 2 in total */
    memset(&param, 0, sizeof(param));
    param.nr_cq = 1;
    param.cq_sizes = (__u64) (unsigned long) &cq_sizes;
    ret = io_uring_queue_init_params(8, &ring, &param);
    if (ret) {
        fprintf(stderr, "ring setup fialed: %d\n", ret);
        return 1;
    }

    obj = uring_bpf_open();
    if (!obj) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        return 1;
    }

    ret = uring_bpf_load(obj);
    if (ret) {
        fprintf(stderr, "fialed to load BPF object: %d\n", ret);
        return 1;
    }

    prog_fd = bpf_program__fd(obj->progs.test);
    ret = __sys_io_uring_register(ring.irng_fd, IORING_REGISTER_BPF,
                                    &prog_fd, 1);
    assert(ret >= 0);

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_nop(sqe);
    sqe->off = 0;
    sqe->opcode = IORING_OP_BPF;
    sqe->user_data = (__u64)(unsigned long) &secret;
    sqe->flags = 0;

    ret = io_uring_submit(&ring);
    assert(ret == 1);

    sleep(1);
    io_uring_wait_cqe(&ring, &cqe);
    while (1) {
        ret = io_uring_peek_cqe(&ring, &cqe);
        if (ret == -EAGAIN)
            break;
        assert(ret == 0);
        fprintf(stderr, "CQE user_data %lu, res %i flags %u\n",
                (unsigned long) cqe->user_data,
                (int) cqe->res, (unsigned) cqe->flags);
        io_uring_cqe_seen(&ring, cqe);
    }

    int map_fd = bpf_map__fd(obj->maps.arr);
    for (int i = 0; i < 10; i++) {
        unsigned long cnt;
        __u32 key = i;
        assert(bpf_map_lookup_elem(map_fd, &key, &cnt) == 0);
        fprintf(stderr, "%lu ", cnt);
    }
    fprintf(stderr, "\nnew secret %lu\n", secret);
    
    uring_bpf__destroy(obj);

    return 0;
}
