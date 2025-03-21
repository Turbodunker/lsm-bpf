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

#define X86_64_READ_SYSCALL 0
#define READ_SYSCALL X86_64_READ_SYSCALL

#define X86_64_WRITE_SYSCALL 0
#define WRITE_SYSCALL X86_64_WRITE_SYSCALL

#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#define MAX_ENTRIES 10240
#define NR_OPEN_DEFAULT 64 //TODO verify this...

#define S_IFMT  00170000
#define S_IFIFO  0010000

typedef long long int __kernel_loff_t;
typedef __kernel_loff_t loff_t;
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

//struct file_operations {
//    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
//} __attribute__((preserve_access_index));

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

// Our simplified pipe info structure to store in the map
struct pipe_info {
    unsigned int head;
    unsigned int tail;
    unsigned int ring_size;
    unsigned long inode_number;  // To identify the pipe
};

struct trace_event_raw_sys_exit {
    unsigned long long __unused_call_data;
    long syscall_nr;
    long ret;
} __attribute__((preserve_access_index));

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, unsigned int);
 __type(value, unsigned long);
} values SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, unsigned int);
 __type(value, unsigned int);
} blockme SEC(".maps");


// Helper function to check if a specific bit is set in a bitmap
static inline unsigned int test_bit(int nr, const unsigned long *addr)
{
    return 1UL & (addr[nr / (sizeof(unsigned long) * 8)] >> (nr % (sizeof(unsigned long) * 8)));
}


SEC("tracepoint/syscalls/sys_exit_splice")
int trace_splice_exit(struct trace_event_raw_sys_exit *ctx){
	unsigned int pid = bpf_get_current_pid_tgid() >> 32; 
	bpf_printk("FILE in sys_exit_splice from %u", pid);
	struct pipe_inode_info **pipe_ptr = bpf_map_lookup_elem(&values, &pid);
	if (!pipe_ptr || !*pipe_ptr) {
	    bpf_printk("FILE no pipe_inode_info pointer");
	    return 0;
	}
	
	struct pipe_inode_info *pipe = *pipe_ptr;
	unsigned int head = BPF_CORE_READ(pipe, head);
	unsigned int tail = BPF_CORE_READ(pipe, tail);
	unsigned int ring_size = BPF_CORE_READ(pipe, ring_size);
	bpf_printk("FILE head: %u", head);
	bpf_printk("FILE tail: %u", tail);
	bpf_printk("FILE ring: %u", ring_size);
	unsigned int flags = BPF_CORE_READ(pipe, bufs, flags);
	bpf_printk("FILE flags: %u", flags);
	if(flags & PIPE_BUF_FLAG_CAN_MERGE){
		bpf_printk("FILE CAN_MERGE FLAG FOUND, BLOCKING NEXT READ/WRITE OP");
		bpf_map_update_elem(&blockme, &pid, &pid, BPF_ANY);
	}
	
	return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(patch_dirtypipe, struct file *file, int mask)
{
    struct pt_regs *regs;
    struct task_struct *task;
    int syscall;
    struct pipe_inode_info *pipe;
    unsigned int i;
    unsigned int pipe_flags;



    task = bpf_get_current_task_btf();
    regs = (struct pt_regs *) bpf_task_pt_regs(task);
    syscall = regs->orig_ax;


    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    void *ptr = bpf_map_lookup_elem(&blockme, &pid);
    int checkme = ptr ? *(int *)ptr : 0;
	bpf_printk("FILE pid: %u, blocked pid %u", pid, checkme);
	if(checkme == pid){
		return -EPERM;
	}
    if (syscall != SPLICE_SYSCALL){
	    return 0;
    }
    bpf_printk("SYSCALL: %u", syscall);

    unsigned long fd_out = PT_REGS_PARM3_CORE(regs);
	bpf_printk("OUT_FD: %lu", fd_out);




    unsigned long out_off = PT_REGS_PARM4_CORE(regs);
    unsigned long size = PT_REGS_PARM5_CORE(regs);
    struct files_struct *files;
    struct fdtable *fdt;
    unsigned int max_fds;

    files = BPF_CORE_READ(task, files);
	if(!files) {
		return 0;
    }

    fdt = BPF_CORE_READ(files, fdt);
	if(!fdt) {
		return 0;
    }
	
	max_fds = BPF_CORE_READ(fdt, max_fds);
	bpf_printk("MAX: %lu", max_fds);	
    if (fd_out < 0 || fd_out >= max_fds) {
        return 0; 
    }
    // Verify fd is open using open_fds bitmap
    unsigned long *open_fds;
    open_fds = BPF_CORE_READ(fdt, open_fds);
    
    // Calculate the position in the bitmap
    unsigned int word_index = fd_out / (sizeof(unsigned long) * 8);
    unsigned long bit_position = fd_out % (sizeof(unsigned long) * 8);
    unsigned long bit_mask = 1UL << bit_position;
    
    // Read the bitmap word
    unsigned long bitmap_word;
    bpf_probe_read_kernel(&bitmap_word, sizeof(bitmap_word), &open_fds[word_index]);
    if (!(bitmap_word & bit_mask)) {
        bpf_printk("FD %lu is not open", fd_out);
        return 0;
    }
	bpf_printk("FILE FD IS OPEN");
	
    //struct file *my_file = BPF_CORE_READ(files, fd_array[fd_out-1]);
    struct file **fd_array = BPF_CORE_READ(fdt, fd);  // Fetch fd array pointer
    if (!fd_array){
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
	bpf_printk("FILE FOUND");

    // Verify this is actually a pipe file
    struct inode *inode = BPF_CORE_READ(target_file, f_inode);
    if (!inode) {
        bpf_printk("FILE PIPE NOT FOUND fd: %d", fd_out);
        return 0;
    }	
    // Check if the inode is a pipe
    // S_IFIFO (named pipe/FIFO): 0x1000
    unsigned short mode = BPF_CORE_READ(inode, i_mode);
    if ((mode & S_IFMT) != S_IFIFO) {
        bpf_printk("FILE FD %lu is not a pipe/FIFO (mode: %x)", fd_out, mode);
        return 0;
    }
      
    pipe = BPF_CORE_READ(target_file, f_inode, i_pipe);
	if(!pipe) {
		bpf_printk("FILE PIPE NOT FOUND");
		return 0;
    }
	bpf_printk("FILE PIPE FOUND");
    bpf_map_update_elem(&values, &pid, &pipe, BPF_ANY);


    return 0;
}

char LICENSE[] SEC("license") = "GPL";

