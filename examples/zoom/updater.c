#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {

  if (argc != 3) {
    fprintf(stderr, "Invalid argument. Usage: %s <u/d> <inode>", argv[0]);
    return 1;
  }
  const char *ud = argv[1];
  const char *u = "u";
  const char *d ="d";
  const unsigned int inode = strtoul(argv[2], NULL, 10);
  const char *map_path = "/sys/fs/bpf/deny_dir";
  const char *map_full_path = "/sys/fs/bpf/map_full";
  
  // Gets the pinned map object
  int map = bpf_obj_get(map_path);
  if (map < 0) {
    fprintf(stderr, "failed to get map object\n");
    return 1;
  }
  int map_full = bpf_obj_get(map_full_path);
  if (map < 0) {
    fprintf(stderr, "failed to get map_full object\n");
    return 1;
  }
  __u8 marked = 1;

  if(!strncmp(ud, u, strlen(u))){
    int res = bpf_map_update_elem(map, &inode,  &marked, BPF_ANY);
    printf("added %u\n", inode);
    if (res == 0){
      bpf_map_delete_elem(map_full, &marked);
    } else {
      printf("map is full\n");
      bpf_map_update_elem(map_full, &marked, &marked, BPF_ANY);
    }

  }
  else if(!strncmp(ud, d, strlen(d))){
    bpf_map_delete_elem(map, &inode);
    bpf_map_delete_elem(map_full, &marked);
    printf("deleted %u\n", inode);
  }
  return 0;
}


