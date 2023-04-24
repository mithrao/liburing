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

static inline void io_uring_prep_cq_bpf(struct io_uring_sqe *sqe, unsigned idx)
{
	io_uring_prep_nop(sqe);
	sqe->off = idx;
	sqe->opcode = IORING_OP_CQ_BPF;
}

static void ring_prep(struct io_uring *ring, struct uring_bpf **pobj)
{
	struct uring_bpf *obj;
	struct io_uring_params param;
	__u32 cq_sizes[2] = {128, 128};
	int ret, prog_fds[1];

	memset(&param, 0, sizeof(param));
	param.nr_cq = ARRAY_SIZE(cq_sizes);
	param.cq_sizes = (__u64)(unsigned long)cq_sizes;
	ret = io_uring_queue_init_params(8, ring, &param);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		exit(1);
	}

	obj = uring_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		exit(1);
	}
	ret = uring_bpf__load(obj);
	if (ret) {
		fprintf(stderr, "failed to load BPF object: %d\n", ret);
		exit(1);
	}

	prog_fds[0] = bpf_program__fd(obj->progs.test);
	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_CQ_BPF,
					prog_fds, ARRAY_SIZE(prog_fds));
	if (ret < 0) {
		fprintf(stderr, "bpf prog register failed %i\n", ret);
		exit(1);
	}
	*pobj = obj;
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

static int test1(void)
{
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct uring_bpf *obj;
	int ret;
	unsigned long secret = 29;

	ring_prep(&ring, &obj);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_cq_bpf(sqe, 0);
	sqe->user_data = (__u64)(unsigned long)&secret;

	ret = io_uring_submit(&ring);
	assert(ret == 1);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_nop(sqe);
	sqe->user_data = 4;
	ret = io_uring_submit(&ring);
	assert(ret == 1);

	sleep(1);
	// io_uring_wait_cqe(&ring, &cqe);
	// while (1) {
	// 	ret = io_uring_peek_cqe(&ring, &cqe);
	// 	if (ret == -EAGAIN)
	// 		break;

	// 	assert(ret == 0);
	// 	fprintf(stderr, "CQE user_data %lu, res %i flags %u\n",
	// 		(unsigned long)cqe->user_data,
	// 		(int)cqe->res, (unsigned)cqe->flags);
	// 	io_uring_cqe_seen(&ring, cqe);
	// }

	print_map(bpf_map__fd(obj->maps.arr), 10);
	fprintf(stderr, "new secret %lu\n", secret);
	uring_bpf__destroy(obj);
	io_uring_queue_exit(&ring);
	return 0;
}

int main(int arg, char **argv)
{
	fprintf(stderr, "test1() ============\n");
	test1();

	return 0;
}
