prefix ?= /usr
datadir ?= $(prefix)/share

INSTALL=install
INCLUDES := -I../../src/include/ -I/usr/include/ -I.

CFLAGS ?= -g -O2
XCFLAGS =
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare\
	-D_GNU_SOURCE -D__SANE_USERSPACE_TYPES__ -L../../src/ \
	$(INCLUDES)

all_targets += register-restrictions

include ../../Makefile.quiet

all: $(all_targets)

%: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $< -luring $(XCFLAGS)

test_srcs := register-restrictions.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

install: $(all_targets) runtests.sh runtests-loop.sh
	$(INSTALL) -D -d -m 755 $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 $(all_targets) $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests.sh  $(datadir)/liburing-test/
	$(INSTALL) -D -m 755 runtests-loop.sh  $(datadir)/liburing-test/
clean:
	@rm -f $(all_targets) $(test_objs)
