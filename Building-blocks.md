# What does a building block consist of:
* Either a system call or a kernel function. [Using syscalls can cause TOCTOU issues] (https://isovalent.com/blog/post/file-monitoring-with-ebpf-and-tetragon-part-1/)
* Input/Hook: What does this building block get as input? These inputs depend on the LMS Hook being used. 
* Objective: What we want the building block to achieve. This must be a testable objective.
* Pre-requisites(optional): Information needed before the building-block can be used
* Limitations/Side-effects: Any limitations or side effects one may introduce by using this building block
* Evaluation criteria: A collection of tests to evaluate the implementation of the building block

## Block read-operations for directory and all files in that directory.
* System Call or Kernel function: file_permission - why? only called
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
symlink -> {linkme.txt,helloworld,evilcat}  (both before and created after LSM-BPF programs loaded)
hardlink -> {linkme.txt,helloworld,evilcat} (both before and created after LSM-BPF programs loaded)
secret
├── bin
│   ├── bash
│   └── ls
├── evilcat
├── evilcat.c
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
``
