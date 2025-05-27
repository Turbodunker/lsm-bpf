#include "zoom.skel.h"
// #include <bpf/libbpf.h>
// #include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[]) {

  if (argc != 2) {
    fprintf(stderr, "Invalid argument. Usage: %s </path/to/deny_list.txt>",
            argv[0]);
    goto cleanup;
  }
  struct zoom_bpf *skel;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_print_fn);

  // Loads and verifies the BPF program
  skel = zoom_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "failed to load and verify BPF skeleton\n");
    goto cleanup;
  }
  // int deny_dir_fd = bpf_map__fd(skel->maps.deny_dir);
  // if (deny_dir_fd < 0) {
  //   fprintf(stderr, "failed to find the deny_dir map file descriptor\n");
  //   goto cleanup;
  // }

  FILE *deny_ptr;
  deny_ptr = fopen(argv[1], "r");
  if (!deny_ptr) {
    fprintf(stderr, "failed to open deny-list. Check the path argument\n");
    goto cleanup;
  }

  char *line = NULL;
  size_t len = 0;
  unsigned int ino;
  __u8 marked = 1;
  __u32 valsize = bpf_map__value_size(skel->maps.deny_dir);
  __u32 keysize = bpf_map__key_size(skel->maps.deny_dir);
  __u32 valsize2 = bpf_map__value_size(skel->maps.map_full);
  __u32 keysize2 = bpf_map__key_size(skel->maps.map_full);

  while ((getline(&line, &len, deny_ptr)) != -1) {
    if (sscanf(line, "%u", &ino) != 1) {
      fprintf(stderr, "malformed denylist.txt, check for newlines\n");
      goto cleanup;
    }

    int res = bpf_map__update_elem(skel->maps.deny_dir, &ino, keysize, &marked, valsize, BPF_ANY);
    if (res == 0){
      bpf_map__delete_elem(skel->maps.map_full, &marked, keysize2, BPF_ANY);
    } else {
      printf("map is full\n");
      bpf_map__update_elem(skel->maps.map_full, &marked, keysize2, &marked, valsize2, BPF_ANY);

    }
  }
  free(line);
  fclose(deny_ptr);

  // Attaches the loaded BPF program to the LSM hook
  int err;
  err = zoom_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "failed to attach BPF skeleton\n");
    goto cleanup;
  }

  printf("LSM loaded! ctrl+c to exit.\n");

  // The BPF link is not pinned, therefore exiting will remove program
  for (;;) {
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  zoom_bpf__destroy(skel);
  return err;
}
