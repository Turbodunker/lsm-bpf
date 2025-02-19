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
#define X86_64_READ_SYSCALL 59
#define EXECVE_SYSCALL X86_64_EXECVE_SYSCALL
#define RESTRICTED_SYMLINK 5244566
// #define RESTRICTED_INODE 13257375 // /opt/zoom/ZoomLauncher (/usr/bin/zoom is a symlink to this)
#define RESTRICTED_LIBRARY 5249011
#define RESTRICTED_INODE 544164 //$HOME/secret
#define EFAULT 14 /* Bad address */




// Define file access flags
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002
#define O_CREAT     00000100
#define O_APPEND    00002000
#define MAY_READ    00000004


struct pt_regs {
	long unsigned int di;
	long unsigned int orig_ax;
} __attribute__((preserve_access_index));

struct qstr {
    const unsigned char *name;
} __attribute__((preserve_access_index));

struct dentry {
    struct inode *d_inode;
    struct dentry *d_parent;
    struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
    struct dentry *dentry;
} __attribute__((preserve_access_index));


struct file {
    struct path f_path;
    unsigned int f_flags;
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




// Map to keep the directories we want to protect(1-level down only!)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned long);
    __type(value, unsigned long);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} protected_directories SEC(".maps");

// Map to track inodes of the content in the protected directories
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, unsigned long);
    __type(value, unsigned long);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} protected_inodes SEC(".maps");



char LICENSE[] SEC("license") = "GPL";

// Helper function to check if an inode is protected
static inline int is_protected(unsigned long i_ino) {
    // unsigned long *found_dir = bpf_map_lookup_elem(&protected_directories, &i_ino);
    unsigned long *found_content = bpf_map_lookup_elem(&protected_inodes, &i_ino);

    // if(found_dir != NULL)
    //      return 1;
    if(found_content != NULL)
        return 1; 
    
    return 0;
}

// Mark an inode as protected
// static inline void protect_inode(unsigned long i_ino) {
//     // unsigned long val = i_ino;
//     bpf_map_update_elem(&protected_inodes, &i_ino, &i_ino, BPF_ANY);
// }

// Helper to check parent directory and protect new inode
static inline void check_parent_and_protect(struct inode *dir, struct dentry *dentry) {
    // unsigned long dir_ino = BPF_CORE_READ(dir, i_ino);
    
    // If inode is protected
    unsigned long dir_inum = BPF_CORE_READ(dir, i_ino); 
    if (bpf_map_lookup_elem(&protected_directories, &dir_inum)) {
        // Get the new inode
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        unsigned int i_ino = BPF_CORE_READ(inode, i_ino);
        // If the inum of the new entry is the same then we don't need to update
        if(i_ino == dir_inum){
            return;
        }
        if (inode) {
            unsigned long i_ino = BPF_CORE_READ(inode, i_ino);
            bpf_map_update_elem(&protected_inodes, &i_ino, &i_ino, BPF_ANY);
        }
    }
}

// Track regular files
SEC("lsm/inode_create")
int BPF_PROG(track_new_file, struct inode *dir, struct dentry *dentry, mode_t mode) {
    check_parent_and_protect(dir, dentry);
    return 0;
}

// // Track directories
// SEC("lsm/inode_mkdir")
// int BPF_PROG(track_new_dir, struct inode *dir, struct dentry *dentry, mode_t mode) {
//     check_parent_and_protect(dir, dentry);
//     return 0;
// }

// // Track symbolic links
// SEC("lsm/inode_symlink")
// int BPF_PROG(track_new_symlink, struct inode *dir, struct dentry *dentry, const char *old_name) {
//     check_parent_and_protect(dir, dentry);
//     return 0;
// }
//
// Track hard links
// SEC("lsm/inode_link")
// int BPF_PROG(track_new_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
//     check_parent_and_protect(dir, new_dentry);
//     return 0;
// }

// // Track special files (device nodes, FIFOs, sockets)
// SEC("lsm/inode_mknod")
// int BPF_PROG(track_new_special, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev) {
//     check_parent_and_protect(dir, dentry);
//     return 0;
// }

// Main hook to enforce access control
SEC("lsm/file_permission")
int BPF_PROG(check_file_permission, struct file *file, int mask) {
    // struct task_struct *task;
    struct dentry *dentry;
    struct inode *dir;

    // Filter out anything that can't read anyway
    if (!(mask & MAY_READ))
        return 0;

    dentry = file->f_path.dentry;
    unsigned long inode_num = BPF_CORE_READ(dentry, d_inode, i_ino);
    if (bpf_map_lookup_elem(&protected_directories, &inode_num)) {
        if (mask & MAY_READ) {
            return -EACCES; 
        }
    }

    // Get parent directory
    dir = dentry->d_parent->d_inode;

    // Check if this is one of the directories that should be blocked from reading

    check_parent_and_protect(dir, dentry);
    
    // Get inode number
    unsigned long i_ino = file->f_path.dentry->d_inode->i_ino;
    
    // Check if this is a protected inode
    if (is_protected(i_ino)) {
        // Deny if MAY_READ is set
        if(mask & MAY_READ) { return -EACCES; }
    }
    
    return 0;
}
//
// SEC("lsm/inode_permission")
// int BPF_PROG(get_dir, struct inode *inode, int mask, int ret)
// {
//     // struct pt_regs *regs;
//     // struct task_struct *task;
//     struct dentry *dentry;
//     // int syscall;
//     
//     // If previous hooks already denied, go ahead and deny this one
//     if (ret) {
//         return ret;
//     }
//
//     // task = bpf_get_current_task_btf();
//     // regs = (struct pt_regs *) bpf_task_pt_regs(task);
//     // // In x86_64 orig_ax has the syscall interrupt stored here
//     // syscall = regs->orig_ax;
//     //
//     // // Only process UNSHARE syscall, ignore all others
//     // if (syscall != X86_64_READ_SYSCALL) {
//     //     return 0;
//     // }
//
//
//     if(inode->i_ino == RESTRICTED_INODE || inode->d_entry) { 
//         // pid = bpf_get_current_pid_tgid();
//         // uint32_t val = pid;
//         // bpf_map_update_elem(&tracked_pids, &pid, &val, BPF_NOEXIST);
//         
//         //MAY_READ is set?
//         if (mask & 4) {
//             return -EACCES;
//         }
//     }
//
//     
//     return 0;
// }
//
// SEC("lsm/file_permission")
// int BPF_PROG(block_secret_dir, struct file *file, int mask)
// {
//     // static unsigned long pid;
//     // struct inode *d_inode
//     // struct dentry *dentry;
//     // static const char fmt1[] = "HELLO"; 
//     // static const char fmt2[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; 
//     // static const char fmt3[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; 
//     // bpf_trace_printk(fmt1, sizeof(fmt1));
//     // bpf_trace_printk(fmt2, sizeof(fmt2));
//     // bpf_probe_read(&d_inode, sizeof(d_inode), &file->f_path.dentry->d_parent->d_inode->i_ino);
//     
//     if(file->f_path.dentry->d_parent->d_inode->i_ino == RESTRICTED_INODE | file->f_path.dentry->d_inode->i_ino == RESTRICTED_INODE){
//             
//          if (mask & 4) {
//              return -EACCES;            
//         }
//     }
//
//     
//
//     return 0;
// }
