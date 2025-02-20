# What is a pattern and what does a pattern consist of?
A pattern is a small generalized LSM BPF program with a specific objective. 
Patterns can be combined to make new patterns altogether, but their main purpose is to serve as small and repeatable generalizations for implementing larger, more complex programs. It can be thought of as a "building block" or a helper function. A single pattern consists of the following elements. \ 
Comment: should we make it a guideline that the pattern description is specific enough such that there is only one (meaningful) way of implementing it? Or is that going too far?

### Objective
* High-level description of what the objective of the pattern. This must testable by quantitative methods.
* Example: Filter (and deny/drop requests) to all incoming write operations to socket x except those ip's in whitelist y.

### Trigger
* Either a system call or an "event" triggering a kernel function to hook into.
* Seems like [Using syscalls can cause TOCTOU issues](https://isovalent.com/blog/post/file-monitoring-with-ebpf-and-tetragon-part-1/)
* Example: A process attempts to call syscall READ on file F, which triggers kernel function security_file_permission.

### Hook
* What hooks does this pattern use?
* Example: Following previous example: file_permission hook gets the file_struct for F aswell as it's permissions mask. 

* Pre-requisites(optional): Information needed before the pattern can be used
* Limitations/Side-effects: Any limitations or side effects one may introduce by using this pattern
* Evaluation criteria: A collection of tests to evaluate the implementation of the pattern

# Example:

### Objective
Block read-operations for one or more specified directories and all files in that directory. (Note that opening and writing to files are not mentioned)
### System Call or Kernel function
file_permission + mmap_file \
The first hook is called for "various read/write operations", but NOT for open. This is ideal as we still need to be able to write to files(and therefore also need to open them, so file_open is not useful). The second is only there as the first does not check for memory mapped files. TODO: fix already mapped files case




* Input/Hook: 
    1. inode_permission: Called right before file is opened. Gives inode and permission mask 
    2. file_permission: Called right before read or write operation is performed. Gives file object and it's permission mask
    3. inode_create: Called when a new inode is created, regardless of what kind of file it is
* Objective: Block all read(and only read!) accesses to this directory and it's files. All sub-directories of the target directory should not be affected. 
* Pre-requisites: Inode number of the directory in question. In particular two maps: One for the directories to block(a list of inode numbers given as user input), and another for the content of the directories(currently hardcoded, but should be done in userspace). 
* Limitations/Side-effects: ???
* Evaluation criteria: Are sym- and hardlinks blocked for reading? Can we still write to and execute files in the directory? Does it work for mounted directories? Can you bypass with alias? Concrete examples where the same file can have multiple names are hard links, bind mounts, and chroot.
* Test structure: $HOME/secret/subsecret/subsubsecret
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
