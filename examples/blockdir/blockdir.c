//https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include "blockdir.skel.h"

#define RESTRICTED_INODE 544164 //$HOME/secret

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}


// void get_dir_inodes(const char *d_path){
//     DIR *dir;
//     struct dirent *entry;
//     struct stat statbuf;
//     char fullpath[PATH_MAX];
//
//     dir = opendir(dirpath);
//     if (dir == NULL) {
//         fprintf(stderr, "Error opening directory '%s': %s\n", dirpath, strerror(errno));
//         return;
//     }
//
//     if(stat(dirpath, &statbuf) == 0) {
//         printf("Directory '%s' inode: %lu\n", dirpath, (unsigned long)statbuf.st_ino);
//     }

int main(int argc, char *argv[])
{
    struct blockdir_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Loads and verifies the BPF program
    skel = blockdir_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // Attaches the loaded BPF program to the LSM hook
    err = blockdir_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("LSM loaded! ctrl+c to exit.\n");

    // Once loaded, the map should be pinned and I should be able to get it
    int dir_map_fd = bpf_obj_get("/sys/fs/bpf/protected_directories");
    unsigned long dir_inodes[] = { RESTRICTED_INODE };

    for (int i = 0; i < sizeof(dir_inodes)/sizeof(dir_inodes[0]); i++) {
        bpf_map_update_elem(dir_map_fd, &dir_inodes[i], &dir_inodes[i], BPF_ANY);
    }

    int content_map_fd = bpf_obj_get("/sys/fs/bpf/protected_inodes");
    // TODO: make a function for this
    unsigned long content_inodes[] = { 541343, 541448, 411345, 541426, 541443, 541345, 541507 };
    
    for (int i = 0; i < sizeof(content_inodes)/sizeof(content_inodes[0]); i++) {
        bpf_map_update_elem(content_map_fd, &content_inodes[i], &content_inodes[i], BPF_ANY);
    }


    // The BPF link is not pinned, tberefore exiting will remove program
    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    blockdir_bpf__destroy(skel);
    return err;
}
