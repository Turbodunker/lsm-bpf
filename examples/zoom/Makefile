CLANG ?= clang-19
LLVM_STRIP ?= llvm-strip-19
ARCH := x86
INCLUDES := -I/usr/include -I/usr/include/x86_64-linux-gnu
LIBS_DIR := -L/usr/lib/lib64 -L/usr/lib/x86_64-linux-gnu
LIBS := -lbpf -lelf

.PHONY: all clean run

all: zoom.skel.h zoom.bpf.o zoom

run: all
	sudo ./zoom denylist.txt

clean:
	rm -f *.o
	rm -f zoom.skel.h

#
# BPF is kernel code. We need to pass -D__KERNEL__ to refer to fields present
# in the kernel version of pt_regs struct. uAPI version of pt_regs (from ptrace)
# has different field naming.
# See: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fd56e0058412fb542db0e9556f425747cf3f8366
#
zoom.bpf.o: zoom.bpf.c
	$(CLANG) -g -O2 -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@ # Removes debug information

zoom.skel.h: zoom.bpf.o
	sudo bpftool gen skeleton $< > $@

zoom: zoom.c zoom.skel.h
	$(CC) -g -Wall -c $< -o $@.o
	$(CC) -g -o $@ $(LIBS_DIR) $@.o $(LIBS)

updater: updater.c 
	$(CC) -g -Wall -c $< -o $@.o
	$(CC) -g -o $@ $(LIBS_DIR) $@.o $(LIBS)
.DELETE_ON_ERROR:
