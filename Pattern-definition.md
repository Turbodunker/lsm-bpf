# What is a pattern and what does a pattern consist of?
A pattern is a small generalized LSM BPF program with a specific objective. 
Patterns can be combined to make new patterns altogether, but their main purpose is to serve as small and repeatable generalizations for implementing larger, more complex programs. It can be thought of as a "building block" or a helper function. A single pattern consists of the following elements. \ 
Comment: should we make it a guideline that the pattern description is specific enough such that there is only one (meaningful) way of implementing it? Or is that going too far? \
A pattern consists of the following elements:
1. Objective
2. Trigger
3. Hook points
4. Pre-requisites(optional)
5. Limitations/Side-effects(semi-optional)
6. Evaluation criteria
Note: merge 5+6 into design decisions. INclude code example
### Objective
* High-level description of what the objective of the pattern. This must testable by quantitative methods.
* Example: Block read-operations for one or more user-specified directories and all files in that directory. Opening and writing to files are ok. This should only work 1-level of the directory, ie. not recursively. (NOte: should this work for all userS?) 

### Trigger
* The system call triggering a kernel function to hook into. Note that we are not hooking into syscalls via tracepoints. This does not seem like a part of lsm and neither does it seem like a good idea for our purposes. See [Using syscalls can cause TOCTOU issues](https://isovalent.com/blog/post/file-monitoring-with-ebpf-and-tetragon-part-1/) 
* Example: A process attempts to perform syscall READ on (non-mmapped)file F, which triggers hook in kernel function security_file_permission.

### Hook points
* What hooks does this pattern use?
* Example: file_permission+mmap_file hook 

### Kernel objects

### User objects

### Pre-requisites - current definition should be looked at
Information or Objects needed before the pattern can be used
* Example: BPF Map populated with user-defined paths to files and pinned on /sys/fs/bpf/ 

### Limitations/Side-effects
Any limitations or side effects one may introduce by using this pattern
* Example: Pattern does not work for files already mmapped prior to LSM BPF program being loaded
* Example: Pattern may cause new inodes to be blocked arbitrarily(TODO: update list when inodes are deleated) or eventually fs will run out.
* Example: Map sizes are not dynamic and limited in size.

### Evaluation criteria 
- qualitative or quantitative, is it on a scale
- Need a better description 
- what are we evaluating? correctness, resource usage(network traffic, cpu cycles etc.) 
A collection of tests to evaluate the implementation of the pattern
1. Cat file in directory or ls content of directory or subdirectories - Tested and works
2. Create new directory or file in secret and read from that - Tested and works
3. Write and execute files - Tested and works. Doing echo "123" >> secret/flag.txt > password.txt from outside secret will still append 123 to the flag.txt, but only write 123 to password.txt. Neither evilcat or helloworld(inside secret/) can be executed.
4. Symbolic + Hardlinks(previously existing and new ones) - Tested and works
5. chroot - Tested with /bin/ls only, but works for that
6. bind mounts - sudo mount --bind $HOME/secret $HOME/test we get the following:
7. aliases - 
8. special files - FIFO and pipes
9. memory mapped files - see script

* Test structure
```
mmap.exe -> (binary that mmaps argv[1] and prints it every second)
symlink -> {linkme.txt,helloworld,evilcat}  (both before and created after LSM-BPF programs loaded)
hardlink -> {linkme.txt,helloworld,evilcat} (both before and created after LSM-BPF programs loaded)
secret
├── bin
│   ├── bash
│   └── ls
├── evilcat
├── evilcat.c
├── myppipe 
├── flag.txt
├── helloworld
├── helloworld.c
├── lib
│   ├── libc.so.6
│   ├── libpcre2-8.so.0
│   ├── libselinux.so.1
│   └── libtinfo.so.6
├── lib64
│   ├── ld-linux-x86-64.so.2
│   ├── libc.so.6
│   └── libtinfo.so.6
├── linkme.txt
├── newdir (created after LSM-BPF programs loaded)
├── renamedfile.txt (created after LSM-BPF programs loaded)
└── subsecret
    ├── newfile.txt (created after LSM-BPF programs loaded)
    ├── notsecret.txt
    └── subsubsecret
        └── public.txt
```
