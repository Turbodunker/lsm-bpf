#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define X86_64_SPLICE_SYSCALL 275
#define SPLICE_SYSCALL X86_64_SPLICE_SYSCALL

#define X86_64_WRITE_SYSCALL 1
#define WRITE_SYSCALL X86_64_WRITE_SYSCALL

#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define MAX_ENTRIES 10240

#define NR_OPEN_DEFAULT 64

typedef long long int __kernel_loff_t;
typedef long long int ssize_t;
typedef unsigned short umode_t;


struct pt_regs {
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int cx;
	long unsigned int r8;
	long unsigned int r9;
	long unsigned int orig_ax;
} __attribute__((preserve_access_index));


struct task_struct {
    unsigned int flags;
    struct pipe_inode_info *splice_pipe;
    struct files_struct *files;
} __attribute__((preserve_access_index));


struct inode {
	unsigned long i_ino;
	umode_t i_mode;
    struct pipe_inode_info *i_pipe;
} __attribute__((preserve_access_index));

struct file {
    struct inode *f_inode;
    const struct file_operations *f_op;
    void *private_data;
} __attribute__((preserve_access_index));

struct fdtable {
    unsigned int max_fds;
    struct file **fd; //current fd array
    unsigned long *open_fds;
} __attribute__((preserve_access_index));

struct files_struct {
    struct fdtable *fdt;
	struct file  *fd_array[NR_OPEN_DEFAULT];
} __attribute__((preserve_access_index));

struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const void *ops;
    unsigned int flags;
    unsigned long private;
} __attribute__((preserve_access_index));

struct pipe_inode_info {
    unsigned int head;
    unsigned int tail;
    unsigned int ring_size;
    struct pipe_buffer *bufs;
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_exit {
    unsigned long long __unused_call_data;
    long syscall_nr;
    long ret;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_exit {
    unsigned long long __unused_call_data;
    unsigned int pid;
} __attribute__((preserve_access_index));

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, unsigned int);
 __type(value, unsigned int);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} blockme SEC(".maps");


SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_exit *ctx){

	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&blockme, &pid);
	 
	return 0;	
}


SEC("tracepoint/syscalls/sys_exit_splice")
int trace_splice_exit(struct trace_event_raw_sys_exit *ctx){
	bpf_printk("FILE EXITSPLICE");

    struct pt_regs *regs;
    struct task_struct *task;

    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    unsigned long fd_out = PT_REGS_PARM3_CORE(regs);
    unsigned long *_Nullable off_out = (unsigned long *_Nullable)PT_REGS_PARM4_CORE(regs);

	if(!off_out){
		return 0;
	}


	
    struct files_struct *files;
    struct fdtable *fdt;
    unsigned int max_fds;

    files = BPF_CORE_READ(task, files);
	if(!files) {
		bpf_printk("FILE FILES OUT OF BOUNDS");
		return 0;
    }

    fdt = BPF_CORE_READ(files, fdt);
	if(!fdt) {
		bpf_printk("FILE FDT OUT OF BOUNDS");
		return 0;
    }

	// The verifier must be pleased	
	max_fds = BPF_CORE_READ(fdt, max_fds);
	bpf_printk("MAX: %lu", max_fds);	
    if (fd_out < 0 || fd_out >= max_fds) {
        return 0; 
    }

    struct file **fd_array = BPF_CORE_READ(fdt, fd);  // Fetch fd array pointer
    if (!fd_array){
		bpf_printk("FILE FDARRAY OUT OF BOUNDS");
        return 0;
	}
	
	struct file *target_file = NULL;
	if (!(fd_out > 0 && fd_out <= max_fds)){
		bpf_printk("FILE FD OUT OF BOUNDS");
		return 0;
	}
	bpf_core_read(&target_file, sizeof(target_file), &fd_array[fd_out]);

	if(!target_file) {
		bpf_printk("FILE NOT FOUND");
		return 0;
    }

      
    struct pipe_inode_info *pipe = BPF_CORE_READ(target_file, f_inode, i_pipe);

	if(!pipe) {
		bpf_printk("FILE PIPE NOT FOUND");
		return 0;
    }

	unsigned int pid = bpf_get_current_pid_tgid() >> 32; 

	struct pipe_buffer *bufs = BPF_CORE_READ(pipe, bufs);
    int head = BPF_CORE_READ(pipe, head);
    int ring_size = BPF_CORE_READ(pipe, ring_size);
    unsigned int curbuf = (head - 1) & (ring_size - 1);
    struct pipe_buffer *current_buffer = &bufs[curbuf];
	
	unsigned int flags = BPF_CORE_READ(current_buffer, flags);
	if(flags & PIPE_BUF_FLAG_CAN_MERGE){
		bpf_printk("FILE Suspicous behaviour related to DirtyPipe detected in %d. Signal alert", pid);	
		int isfull = bpf_map_update_elem(&blockme, &pid, &pid, BPF_ANY);
		if(isfull < 0){
			bpf_printk("FILE Cannot track anymore processes with suspicous behavior...");
			bpf_printk("Signal Alert or Reboot immediatly");
		}
	}
	return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(patch_dirtypipe, struct file *file, int mask)
{
    struct pt_regs *regs;
    struct task_struct *task;
	int syscall;

    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    syscall = regs->orig_ax;


    if (syscall != WRITE_SYSCALL){
	    return 0;
    }
	
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;

    void *ptr = bpf_map_lookup_elem(&blockme, &pid);
    int checkme = 0;
	if (ptr) {
		checkme = *(int *)ptr;
		if(checkme == pid){
			bpf_printk("FILE BEFORE DELETE");
			bpf_map_delete_elem(&blockme, &pid);
			return -EPERM;
		}
	}

    return 0;
}
char LICENSE[] SEC("license") = "GPL";

