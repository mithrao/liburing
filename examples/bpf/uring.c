// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "liburing.h"
#include "../../src/syscall.h"
#include "uring.skel.h"
#include "uring.h"

static inline void io_uring_prep_bpf(struct io_uring_sqe *sqe, unsigned idx)
{
    io_uring_prep_nop(sqe);
    sqe->off = idx;
    sqe->opcode = IORING_OP_BPF;
}

static void ring_prep(struct io_uring *ring, struct uring_bpf **pobj)
{
    struct uring_bpf *payload;
    struct io_uring_params param;
    __u32 cq_sizes[2] = {128, 128};
    int prog_fds[4];
    int ret;

    /* 1 additional CQ, 2 in total */
    memset(&param, 0, sizeof(param));
    param.nr_cq = ARRAY_SIZE(cq_sizes);
    param.cq_sizes = (__u64) (unsigned long) cq_sizes;
    ret = io_uring_queue_init_params(8, ring, &param);
    if (ret) {
        fprintf(stderr, "ring setup fialed: %d\n", ret);
        exit(1);
    }

    payload = uring_bpf__open_and_load();
    if (!payload) {
        fprintf(stderr, "failed to open and load BPF payloadect\n");
        exit(1);
    }

    prog_fds[0] = bpf_program__fd(payload->progs.test);
    prog_fds[1] = bpf_program__fd(payload->progs.counting);
    prog_fds[2] = bpf_program__fd(payload->progs.pingpong);
    prog_fds[3] = bpf_program__fd(payload->progs.write_file);
    ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_BPF,
                                    prog_fds, ARRAY_SIZE(prog_fds));

    
    if (ret < 0) {
        fprintf(stderr, "bpf prog register failed %i\n", ret);
		exit(1);
    }
    *pobj = payload;
}

static void print_map(int map_fd, int limit)
{
    int i;
    for (i = 0; i < limit; i++) {
        unsigned long cnt;
        __u32 key = i;
        assert(bpf_map_lookup_elem(map_fd, &key, &cnt) == 0);
        fprintf(stderr, "%lu ", cnt);
    }
	fprintf(stderr, "\n");
}

/** example 1
 * bpf writing to userspace: `copy_to_user`
 * bpf reading from userspace: `copy_from_user` 
 * bpf waiting on CQ: `io_uring_wait_cqe`
 */
static int test1(void)
{
    struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct uring_bpf *obj;
	int ret;
	unsigned long secret = 29;

    ring_prep(&ring, &obj);

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_bpf(sqe, 0);
    sqe->user_data = (__u64)(unsigned long) &secret;

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

    print_map(bpf_map__fd(obj->maps.arr), 10);
    fprintf(stderr, "new secret %lu\n", secret);
    uring_bpf__destroy(obj);
    io_uring_queue_exit(&ring);
    return 0;
}

/** example 2
 * wait for N timeout requests 
 */
static int test2(void)
{
    struct counting_ctx b = {
        .ts = { 
            .tv_nsec = 200000000, 
        }
    };
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct uring_bpf *obj;
    int ret;

    ring_prep(&ring, &obj);

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_bpf(sqe, 1);
    sqe->user_data = (__u64)(unsigned long) &b;
    ret = io_uring_submit(&ring);
    assert(ret == 1);

    ret = io_uring_wait_cqe(&ring, &cqe);
    assert(!ret);
    fprintf(stderr, "ret %i, udata %lu\n", cqe->res, (unsigned long) cqe->user_data);
    io_uring_cqe_seen(&ring, cqe);

    print_map(bpf_map__fd(obj->maps.arr), 10);
    uring_bpf__destroy(obj);
    io_uring_queue_exit(&ring);
    
    return 0;
}

/** example 3
 * ping pong CQEs b/w 2 BPF requests 
 */
static int test3(void)
{
    struct ping_ctx uctx[2];
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct uring_bpf *obj;
    int i, ret;

    ring_prep(&ring, &obj);
    uctx[0].idx = 0;
    uctx[1].idx = 1;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_bpf(sqe, 2);
    sqe->user_data = (__u64)(unsigned long) &uctx[0];

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_bpf(sqe, 2);
    sqe->user_data = (__u64)(unsigned long) &uctx[1];

    /* kick off the first bpf */
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_nop(sqe);
    sqe->user_data = 0; /* start from 0 */
    sqe->cq_idx = 1;

    ret = io_uring_submit(&ring);
    assert(ret == 3);

    /* wait for bpf's CQE */
    for (i = 0; i < 2; i++) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        assert(!ret);
        fprintf(stderr, "ret %i, udata %lu\n", cqe->res, (unsigned long)cqe->user_data);
        io_uring_cqe_seen(&ring, cqe);
    }

    print_map(bpf_map__fd(obj->maps.arr), 10);
    uring_bpf__destroy(obj);
    io_uring_queue_exit(&ring);
    return 0;
}

static char verify_buf[FILL_BLOCK_SIZE];
/** example 4
 * bpf writing to file with QD > 1 
 */
static int test4(void)
{
    struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct uring_bpf *obj;
	int i, j, ret, fd;
    char filename[] = "./.tmp/bpf_file_XXXXXX";
	char pattern = 0xae;
    void *mem;

    ret = posix_memalign(&mem, 4096, FILL_FSIZE);
    assert(!ret);
    memset(mem, pattern, FILL_FSIZE);

    fd = mkstemp(filename);
    if (fd < 0) {
        fprintf(stderr, "mkstemp failed\n");
        return 1;
    }
    unlink(filename);

    ring_prep(&ring, &obj);
    ret = io_uring_register_files(&ring, &fd, 1);
    assert(!ret);

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_bpf(sqe, 3);
    sqe->user_data = (__u64)(unsigned long) mem;
    ret = io_uring_submit(&ring);
    assert(ret == 1);

    ret = io_uring_wait_cqe(&ring, &cqe);
    assert(!ret);
    fprintf(stderr, "ret %i, udata %lu\n", cqe->res, (unsigned long) cqe->user_data);
    io_uring_cqe_seen(&ring, cqe);

    print_map(bpf_map__fd(obj->maps.arr), 10);
    uring_bpf__destroy(obj);
    io_uring_queue_exit(&ring);
    free(mem);

    for (i = 0; i < FILL_BLOCKS; i++) {
        ret = read(fd, verify_buf, FILL_BLOCK_SIZE);
        assert(ret == FILL_BLOCK_SIZE);
        for (j = 0; j < FILL_BLOCK_SIZE; j++) {
            assert(verify_buf[j] == pattern);
        }
    }
    return 0;
}

int main(int argc, char const *argv[])
{
    fprintf(stderr, "test1()============\n");
    test1();
    fprintf(stderr, "test2()============\n");
    test2();
    fprintf(stderr, "test3()============\n");
    test3();
    fprintf(stderr, "test4()============\n");
    test4();
    return 0;
}
