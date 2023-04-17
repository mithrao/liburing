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
	struct uring_bpf *obj;
	int ret, prog_fds[1];

	ret = io_uring_queue_init(8, ring, IORING_SETUP_R_DISABLED);
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

	prog_fds[0] = bpf_program__fd(obj->progs.register_restrictions);
	ret = __sys_io_uring_register(ring->ring_fd, IORING_REGISTER_BPF,
					prog_fds, ARRAY_SIZE(prog_fds));
	if (ret < 0) {
		fprintf(stderr, "bpf prog register failed %i\n", ret);
		exit(1);
	}
	*pobj = obj;
}

static int test5(void)
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct io_uring ring;
	struct uring_bpf *obj;
    int ret, pipe1[2];

    uint64_t ptr;
    struct iovec vec = {
        .iov_base = &ptr,
        .iov_len  = sizeof(ptr),
    };

    if (pipe(pipe1) != 0) {
        perror("pipe");
        return 1;
    }

    ring_prep(&ring, &obj);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_writev(sqe, pipe1[1], &vec, 1, 0);
	sqe->user_data = 1;

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_readv(sqe, pipe1[0], &vec, 1, 0);
	sqe->user_data = 2;

	ret = io_uring_submit(&ring);
	if (ret != 2) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}

    for (int i = 0; i < 2; i++) {
		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret) {
			fprintf(stderr, "wait: %d\n", ret);
			return 1;
		}

		switch (cqe->user_data) {
		case 1: /* writev */
			if (cqe->res != sizeof(ptr)) {
				fprintf(stderr, "write res: %d\n", cqe->res);
				return 1;
			}

			break;
		case 2: /* readv should be denied */
			if (cqe->res != -EACCES) {
				fprintf(stderr, "read res: %d\n", cqe->res);
				return 1;
			}
			break;
		}
		io_uring_cqe_seen(&ring, cqe);
	}

    uring_bpf__destroy(obj);
    io_uring_queue_exit(&ring);
    return 0;
}

int main(int arg, char **argv)
{
    fprintf(stderr, "\ntest5() ============\n");
	test5();

	return 0;
}
