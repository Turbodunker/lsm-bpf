1. Objective \
Block read-operations for one or more user-specified directories and all files(regular, directory and special) in said directories(1-level down). Opening and writing to files are ok. Assume the LSM BPF program(s) are loaded sometime after boot.

    1. One or more (target) directories must be able to block read operations
    2. Only files(regular/directory/special) that are the immediate child nodes for target directories should be blocked from reading. 
    3. Symbolic- and Hardlinks to protected files should not be readable during load.
    4. Bind mounts of a target directory to anywhere else on the same filesystem should not make protected files readable
    5. Using chroot to sandbox inside a target directory should not circumvent protections.
    6. Aliases to protected files should not be able to circumvent protections.
    7. Special files like FIFO(named pipe) should not be able to circumvent protections. Should still work if pipe is opened prior to pattern being loaded. Note again that writing is ok. 
    8. Memory mapping of protected files, after pattern is loaded, should not circumvent protections

2. Name \
Blockdir-read

3. Hook points \
For finding hooks to consider I've through the hooks on the [kernel documentation for my kernel version](https://www.kernel.org/doc/html/v6.8/core-api/kernel-api.html). I searched for keywords file, inode and read and also traced the hooks called with function_graph to narrow down the search.
Furthermore this article [File Monitoring with eBPF and Tetragon (Part 1)](https://isovalent.com/blog/post/file-monitoring-with-ebpf-and-tetragon-part-1/) was used to decide what hooks to pick

- file-permission
    This hook-point was chosen because file-permission is called before accessing an open file. In particular right before "various" read/write operations, and since we want to block all read operations to a given directory, this was expected to catch a lot of cases. This comes with the trade-off of the hook being called on every file access.
    It's intended to be used to revalidate permissions for privilege bracketing or policy changes, which is also inline with the objective. There is one caveat with this hook however: it does not check for memory mapped files. Therefore this pattern will only block reads for files already mapped into memory, and it may be best suited to be loaded at boot-time to avoid such cases.

- mmap_file
    This hook-point was chosen to handle cases where new files are memorymapped after the pattern is loaded.
    It's called whenever an mmap operation(ie. not just the specifc mmap syscall, but also e.g. mremap) is performed on a file and it's intended use is to check permissions, which makes it an ideal choice for this pattern.
    This pattern will use it to check if the application requests that pages may be read from that given file, in particular the inode of the file before it's mapped to memory.
    If this is the case, then the operation is denied.
    One could modify the resulting protection in this hook, such that all associated pages cannot be read, and let the operation proceed. 
    However, assuming the requesting application actually needs the permissions they are asking for, I argue it's better to deny permission here instead of causing an issue later.


Other hooks that were considered:

- mmap_addr
    In addition to catching and monitoring all files that are mmapped after the program is loaded, this may allow to block already mapped files, given that the memory addresses are passed to the program via user space. This should be possible, but is left as future work for now.

- inode_permission
    This node sounded promising at first, but it's "called whenever a file is opened(as well as many other opreations), whereas the file_security_ops permission hook is called when the actual read/write operations are perfomed". I therefore assumed this hook would add more overhead than file_permission.  

- file_open 
    This is expected to add less overhead than file_permission, as it would only be called once when the file is accessed initially, and not for every subsequent access. However it would not catch any files that were already opened prior to the LSM BPF program being loaded.

- inode_rmdir/unlink/rename
    These were considerd when having to remove inodes in case any files were removed. The objective does not mention anything about removing files so this should still be possible with this pattern. However I've been completely unable to delete any elements from protected_inode map, but more on this in the Design.


4. Implementation
    1. User space \
    The userspace part of the pattern takes a list of paths to directories and produces two maps: protected_directories and protected_files. 
    The first is a map of the inodes of the directories the pattern should block read operations from, while the latter is all the inodes at first level of said directories, i.e. all the files.
    Both maps has the inode as both key and value, though we really only need to store the key.
    ```c
    // After BPF Program is loaded and attached to LSM hook the following can be added to userspace application:
    int dir_map_fd = bpf_obj_get("/sys/fs/bpf/protected_directories");
    //These should be user defined. Just hardcoded here cause its easier to test
    char *target_paths[] = {"/home/mblomqvist/secret", "/home/mblomqvist/secondsecret"};
    int target_count = sizeof(target_paths) / sizeof(target_paths[0]);
    ino_t dir_list[1024];
    ino_t file_list[1024];

    // get_files_inodes just a helper that saves the inodes of the target 
    // dirs in dir_list and 1-level inodes of files in file_list.
    // limit is 1024 inodes in both lists.
    int totalfiles = get_files_inodes(target_paths, target_count, dir_list, file_list, 1024, 1024);
    if (totalfiles < 0) {
        perror("Error getting inodes");
        return 1;
    }

    for (int i = 0; i < target_count; i++) {
        bpf_map_update_elem(dir_map_fd, &dir_list[i], &dir_list[i], BPF_ANY);
    }

    int content_map_fd = bpf_obj_get("/sys/fs/bpf/protected_files");
    
    for (int i = 0; i < totalfiles; i++) {
        bpf_map_update_elem(content_map_fd, &file_list[i], &file_list[i], BPF_ANY);
    }
    ```
    
    2. Kernel space \
    The kernel space part may only add inodes to the protected_files map, e.g. if a new file appears in one of the protected directories and there is an attempt to read from it.
    That is, the inode is only added to the map once an attempt to read from it has been made. 
    ```c
    // Map to keep the directories we want to protect(1-level down only!)
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, ino_t);
        __type(value, ino_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    } protected_directories SEC(".maps");
    
    // Map to track inodes of the content in the protected directories
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, ino_t);
        __type(value, ino_t);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    } protected_files SEC(".maps");

    // Helper to check parent directory and protect new inode. This is the essence of the pattern
    static inline int check_parent_and_protect(unsigned long parent_ino, unsigned long current_ino) {
        if (bpf_map_lookup_elem(&protected_directories, &parent_ino)) {
            bpf_map_update_elem(&protected_files, &current_ino, &current_ino, BPF_ANY);
        }
    
        int *found_content = bpf_map_lookup_elem(&protected_files, &current_ino);
        if(found_content != NULL) { return 1; }
        return 0;
    }
    
    // Main hook to enforce access control
    SEC("lsm/file_permission")
    int BPF_PROG(check_file_permission, struct file *file, int mask) {
    
        // Filter out anything that doesn't ask for read anyway
        if (!(mask & MAY_READ))
            return 0;
        
        // Block if current file is a target directory
        ino_t file_ino = BPF_CORE_READ(file, f_path.dentry, d_inode, i_ino);
        if (bpf_map_lookup_elem(&protected_directories, &file_ino)) { return -EPERM; }
    
        // Block if current file's dentry-parent is a target directory
        ino_t dir_ino = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
        if (check_parent_and_protect(dir_ino, file_ino)) { return -EPERM; }
    
        return 0;
    }
    
    SEC("lsm/mmap_file")
    int BPF_PROG(check_mmap_file_permission, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    
        // Filter out anything that doesn't ask for read anyway
        if (!(reqprot & PROT_READ))
            return 0;
    
        ino_t file_ino = BPF_CORE_READ(file, f_path.dentry, d_inode, i_ino);
        if (bpf_map_lookup_elem(&protected_directories, &file_ino)) { return -EPERM; }
    
        ino_t dir_ino = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode, i_ino);
        if (check_parent_and_protect(dir_ino, file_ino)) { return -EPERM; }
    
        return 0;
    }
    ```

5. Protocol
    This patterns protocol is initiated by the user space, right after the BPF programs are loaded. The user space part needs a list of absolute paths for the directories that should be blocked for reading. Then it will populate the both maps with inodes and never update them again. At any point the kernel space may add inodes to the protected_files map, in so far the inode of the files current directory is found in protected_directories map. US -> KS(updates here).

6. Design
   I decided to not filter on any specifc set of syscalls for this pattern. In part because the objective does not mention any specific syscalls, but rather read "operations" and there seems to be a meaningful difference here. Most importantly that not all read operations results in the read syscall, e.g. memory mapped files, but there could be more, and tracking down all syscalls made by the read operations required in the objective, to check if they made a read syscall, seemed needlesly complex compared to using file_permission on most file read-write operations. I would have to use at least one hook anyway, and I expected the syscall-apathetic approach to be faster in the end... will see.

    I decided to use an inode-based approach over a path-based approach because the objectives requirements mentions it must work for hardlinks, bind mounts and chroot.
    This would not be possible if I only check on a collection of paths, as the above 3 cases could have different paths for the same file. 

    This pattern needs two maps, as it uses inodes for both deciding if a file should be protected(ie. the directories inodes), and to decide if a file can be read from or not(ie. the files in the directories). 
    
    Why use 2 maps?
    Consider if a new file "public.txt" is created in subdir/ in: 
    /protected/subdir/public.txt
    We should be able to read the content of public.txt, but if we only have a single map of inodes we cannot meaningfully distingush between protected/ and subdir/.
    The dentry struct only contains information about it's parent dentry(from which we can extract an inode number ino_t). 
    
    A major issue currently is that I can't remove inodes from the tracking map... not sure what to try anymore. This is an issue because if files are removed from a target directory, it's inode number may be reassigned to another file somewhere else on the filesystem. This file should not be blocked from reading and will could(probably will) cause severe side-effects the longer the program runs and the more files are moved out of the target directories. 
    
    One solution to this is to not allow either the target directory or their content to be deleted while the pattern is loaded. TODO: add to requirements? or can this be solved? should we spend more time on this?

    If one of the files in the target directories is a non-empty directory, they cannot be removed. If they are empty, then they can be removed. 
    A semi-side-effect is that using opendir, readdir closedir(library functions dirent.h, man 3 readdir) don't give a "permission denied" when running the program, but when I strace I get a permission denied at getdents64 syscall, which according to the man pages of readdir syscall(man 2 readdir) is the syscall that superseds readdir(the syscall). 
    But using ls on a dir I get the error on the terminal. Is this cause by the fork from execve?

    Another side-effect is that the pattern does not allow for any executable to be run in the target directories.
    

    Does this pattern do anything that DAC can't do already? I think it would make more sense if the pattern restricted the way the user can read from the file. Unless there is a usecase for reaffirming access permissions even if read-flag is not set for user/group etc.
    

7. Evaluation
Correctness - Create set of unit-tests from the requirement specification. Pending until confirmation this makes sense to do..

For evaluating ressource usage: Create a workload with a lot of file accesses and compare execution time overhead of file_permission vs inode_permission. Potentially file_open. Potentially include varitations on above with read syscall being checked instead of MAY_READ.


