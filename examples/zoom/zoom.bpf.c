#include <linux/bpf.h>
// #include "vmlinux.h"
#include <stdlib.h>
#include <stdint.h>
// #include <stdio.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <string.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define PROT_EXEC 4
#define X86_64_UNSHARE_SYSCALL 272
#define X86_64_EXECVE_SYSCALL 59
#define UNSHARE_SYSCALL X86_64_UNSHARE_SYSCALL
#define EXECVE_SYSCALL X86_64_EXECVE_SYSCALL
#define RESTRICTED_SYMLINK 5244566
// #define RESTRICTED_INODE 13257375 // /opt/zoom/ZoomLauncher (/usr/bin/zoom is a symlink to this)
#define RESTRICTED_LIBRARY 5249011
#define RESTRICTED_INODE 942434 //$HOME/test/helloworld
#define EFAULT 14 /* Bad address */

#define MAX_PATH_SIZE 4096 // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))
#define statfunc static __attribute__((__always_inline__))

struct buffer {
  uint8_t data[MAX_PERCPU_ARRAY_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, uint32_t);
  __type(value, struct buffer);
  __uint(max_entries, 1);
} heaps_map SEC(".maps");

static struct buffer *get_buffer() {
  uint32_t zero = 0;
  return (struct buffer *)bpf_map_lookup_elem(&heaps_map, &zero);
}
const char target_exec[] = "helloworld";
const char restricted_lib[] = "libc.so.6"; 

// struct linux_bprm {
//     
// } __attribute__((perserve_access_index));


struct qstr {
    const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
    struct dentry *dentry;
} __attribute__((preserve_access_index));


struct file {
    struct path f_path;
} __attribute__((preserve_access_index));


struct mm_struct {
    struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
    struct mm_struct *mm;
    char comm[TASK_COMM_LEN]; //TASK_COMM_LEN
} __attribute__((preserve_access_index));

struct inode {
    unsigned long i_ino;
} __attribute__((preserve_access_index));


statfunc long get_path_str_from_path(unsigned char **path_str, struct path *path, struct buffer *out_buf) {

  long ret;
  struct dentry *dentry, *dentry_parent;
  const unsigned char *name;
  size_t name_len;

  dentry = BPF_CORE_READ(path, dentry);

  size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

  #pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {

    dentry_parent = BPF_CORE_READ(dentry, d_parent);


    // Add this dentry name to path
    name_len = LIMIT_PATH_SIZE(1024);
    name = BPF_CORE_READ(dentry, d_name.name);

    name_len = name_len + 1; // add slash
    // Is string buffer big enough for dentry name?
    if (name_len > buf_off) { break; }
    volatile size_t new_buff_offset = buf_off - name_len; // satisfy verifier
    ret = bpf_probe_read_kernel_str(
      &(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset) // satisfy verifier
    ]),
      name_len,
      name);
    if (ret < 0) { return ret; }

    if (ret > 1) {
      buf_off -= 1;                                    // remove null byte termination with slash sign
      buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
      out_buf->data[buf_off] = '/';
      buf_off -= ret - 1;
      buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
    } else {
      // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
      break;
    }
    dentry = dentry_parent;
  }

  // Is string buffer big enough for slash?
  if (buf_off != 0) {
    // Add leading slash
    buf_off -= 1;
    buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
    out_buf->data[buf_off] = '/';
  }

  // Null terminate the path string
  out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
  *path_str = &out_buf->data[buf_off];
  return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}









// Map to track processes that match our target
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint32_t);
    __type(value, uint8_t);
} tracked_pids SEC(".maps");


char LICENSE[] SEC("license") = "GPL";


// SEC("lsm/bprm_check_security")
// // int BPF_PROG(julemand1, struct inode *inode, int mask, int ret) {
// int BPF_PROG(is_zoom, struct linux_binprm *bprm) {
//     
//     static const char fmt[] = "Hello from: %u\n";
//
//
//     //Get filename of the command
//     char comm[TASK_COMM_LEN];
//     bpf_get_current_comm(comm, sizeof(comm));
//     bpf_trace_printk(fmt, sizeof(fmt), comm);
//
//     // why tf is this ok? because we know the loop will stop after max 16 iterations?
//     #pragma unroll
//     for (int i = 0; i < sizeof(target_exec) - 1; i++) {
//         if (comm[i] != target_exec[i])
//             return 0;
//     }
//
//     // static const char fmt2[] = "PID: %u\n";
//     //
//     // // If it matches, add PID to our tracking map
//     // __uint32_t pid = bpf_get_current_pid_tgid() >> 32;
//     // __u8 value = 1;
//     // bpf_map_update_elem(&tracked_pids, &pid, &value, BPF_ANY);
//     // bpf_trace_printk(fmt2, sizeof(fmt2), pid);
//     // }
//     
//
//
//     
//     return 0;
// }

SEC("lsm/mmap_file")
int BPF_PROG(julemand2, struct file *file, unsigned long prot, unsigned long flags){
    

    static const char fmt[] = "!!! HELLO FROM: %s !!!";

    //Get filename of the command
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_trace_printk(fmt, sizeof(fmt), comm);

    // why tf is this ok? because we know the loop will stop after max 16 iterations?
    #pragma unroll
    for (int i = 0; i < sizeof(target_exec) - 1; i++) {
        if (comm[i] != target_exec[i])
            return 0;
    }

    static const char fmt2[] = "!!! LOOK AT ME: !!! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    // if(!(prot & PROT_EXEC))
    //     return 0;

    bpf_trace_printk(fmt2, sizeof(fmt2));
    // __uint32_t pid = bpf_get_current_pid_tgid() >> 32;
    // __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    // // bpf_trace_printk(fmt, sizeof(pid), pid);
    // if (!tracked)
    //     return 0;
    //
    // bpf_trace_printk(fmt, sizeof(pid), pid);
    // unsigned char fname[256];
    // bpf_d_path(&file->f_path, fname, sizeof(fname));
    // // const unsigned char **pname = &file->f_path.dentry->d_name.name;
    // //bpf_d_path(&file->f_path, fname, sizeof(fname));
    // // BPF_CORE_READ(fname, file, f_path.dentry, d_name.name); 
    // static const char fmt3[] = "### PATH: %s ###";
    // 
    // bpf_trace_printk(fmt3, sizeof(fname), fname);

    // Get full path
    //bpf_d_path(&file->f_path, fname, sizeof(fname));
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // or struct task_struct *task = (struct task_struct *)ctx->args[0];
    // struct file *file = BPF_CORE_READ(task, mm, exe_file); 
    struct path *path = __builtin_preserve_access_index(&file->f_path);
    // bpf_trace_printk("Path: %s\n", sizeof(path), path);
    struct buffer *string_buf = get_buffer();
    if (string_buf == NULL) { return 0; }
    unsigned char *file_path = NULL;
    get_path_str_from_path(&file_path, path, string_buf);

    bpf_printk("PATH --> %s\n", file_path);

    // bpf_d_path(&pname, fname, sizeof(fname));
    // #pragma unroll
    // for (int i = 0; i < sizeof(restricted_lib) - 1; i++) {
    //     if (fname[i] != restricted_lib[i])
    //         return 0;
    // }
    
    // // Log the blocked attempt
    // uint32_t count = 1;
    // uint32_t *existing = bpf_map_lookup_elem(&block_attempts, &pid);
    // if (existing)
    //     count += *existing;
    // bpf_map_update_elem(&block_attempts, &pid, &count, BPF_ANY);
    
    // Block the library load
    return 0;

}



// const char restricted[] = "ld-linux-x86-64.so.2";
// const char restricted[] = "libc.so.6";
// const char restricted[] = "helloworldAAAAAAAAAAAA";
// const char restricted[] = "helloworld";

// SEC("lsm/inode_permission")
// int BPF_PROG(julemand, struct inode *inode, int mask, int ret)
// {
//     //struct pt_regs *regs;
//     //struct task_struct *task;
//     //kernel_cap_t caps;
//     //int syscall;
//     //unsigned long flags;
//     //char buf[256]
//
//     // If previous hooks already denied, go ahead and deny this one
//     if (ret) {
//         return ret;
//     }
//     
//     // static const char abc[] = "ALLAAH\n";
//     // bpf_trace_printk(abc, sizeof(abc));
//     // If we somehow know the i_ino 
//     // unsigned long val = BPF_CORE_READ(inode, i_ino);
//     // unsigned long val = inode->i_ino;
//     // static const char fmt[] = "Inode: %u\n";
//     // bpf_trace_printk(fmt, sizeof(fmt), val);
//     // if (val == RESTRICTED_SYMLINK){
//     //     return -EPERM;
//     // }
//
//     // char filename[16];
//     // bpf_get_current_comm(&filename, sizeof(filename));
//     // 
//     // if (bpf_strncmp(filename, sizeof(filename), restricted)){
//     //     return 0;
//     // }
//
//     // Get BTF pointer to the task_struct(process)
//     //struct task_struct *task = bpf_get_current_task_btf()
//     
//     //int path_len = bpf_probe_read_user(buf, sizeof(buf), restricted)
//     //Check if process did an execve
//     //if (task->in_execve) {
//     //    return -EPERM
//     //}
//
//     // task = bpf_get_current_task_btf();
//     //regs = (struct pt_regs *) bpf_task_pt_regs(task);
//     // In x86_64 orig_ax has the syscall interrupt stored here
//
//     //caps = task->cred->cap_effective;
//
//
//     // Only process UNSHARE syscall, ignore all others
//     //syscall = regs->orig_ax;
//     //if (syscall != EXECVE_SYSCALL) {
//     //    return 0;
//     //}
//
//     // PT_REGS_PARM1_CORE pulls the first parameter passed into the unshare syscall
//     //flags = PT_REGS_PARM1_CORE(regs);
//
//     // Ignore any unshare that does not have CLONE_NEWUSER
//     //if (!(flags & CLONE_NEWUSER)) {
//     //    return 0;
//     //}
//
//     return 0;
// }
