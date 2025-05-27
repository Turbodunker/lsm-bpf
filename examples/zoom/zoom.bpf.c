#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define TASK_COMM_LEN 16
#define ZOOM "/opt/zoom/zoom"

char LICENSE[] SEC("license") = "GPL";

// Map for all inodes we don't want zoom to access
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, unsigned int);
  __type(value, u8);
  __uint(max_entries, 1000);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} deny_dir SEC(".maps");

// Map to signal map is full
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u8);
  __type(value, u8);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_full SEC(".maps");

extern int LINUX_KERNEL_VERSION __kconfig;

SEC("lsm/file_open")
int BPF_PROG(deny_dir_zoom, struct file *file, int ret) {

  if (ret != 0) {
    return ret;
  }
  char buf[15];
  struct task_struct *current = bpf_get_current_task_btf();

  // bpf_rcu_read_lock();
  // bpf_d_path(BPF_CORE_READ(current, mm, exe_file, f_path), buf, sizeof(buf));
  // bpf_rcu_read_unlock();
  // if(LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 12, 0)){
  //   bpf_printk("using bad") ;
  // struct path path = BPF_CORE_READ(current, mm, exe_file, f_path);
    bpf_d_path(&current->mm->exe_file->f_path, buf, sizeof(buf));
  // } else {
  //   struct file *exe_file = bpf_get_tast_exe_file(current);
  //   if(!exe_file){
  //     return 0;
  //   }
  //   bpf_path_d_path(&exe_file->f_path, buf, sizeof(buf));
  //   bpf_put_file(exe_file);
  // }



  if (!bpf_strncmp(buf, 15, ZOOM)) {

    // Check if the file is in the denylist
    ino_t ino = BPF_CORE_READ(file, f_inode, i_ino);
    u8 *marked = bpf_map_lookup_elem(&deny_dir, &ino);
    if (!marked) {
      u8 isfull = 1;
      u8 *isfull_ptr = bpf_map_lookup_elem(&map_full, &isfull);
      if(isfull_ptr){
        return -EPERM;
      }
      return 0;
    }
    return -EPERM;
  }
  return ret;
}
