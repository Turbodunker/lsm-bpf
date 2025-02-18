# What does a building block consist of:
* At least one system call (is this the only way of accessing kernel space?)
* Input/Hook: What does this building block get as input? These inputs depend on the LMS Hook being used. 
* Objective: What we want the building block to achieve. This must be a testable objective.
* Pre-requisites(optional): Information needed before the building-block can be used
* Evaluation criteria: A collection of tests to evaluate the implementation of the building block

## Block read-operations for directory and all files in that directory.
* System Call: execve. Why? earliest syscall I can trace
* Input/Hook: 
    1. inode_permission: Called right before file is opened. Gives inode and permission mask 
    2. file_permission: Called right before read or write operation is performed. Gives file object and it's permission mask
* Objective: Block all read(and only read!) accesses to this directory and it's files. All sub-directories of the target directory should not be affected. 
* Pre-requisites: Inode number of the directory in question.
* Evaluation criteria: Are sym- and hardlinks blocked for reading? Can we still write to and execute files in the directory? Does it work for mounted directories? Can you bypass with alias?
* 