1. Objective
Block read-operations for one or more user-specified directories and all files(regular, directory and special) in said directories. Opening and writing to files are ok. 
This should only work on 1-level of the directory, ie. not recursively. This includes all users(root included), and should protect at all times from the moment the BPF programs are loaded. Files that were loaded into memory prior to the BPF programs being loaded are exempt from this protection.

2. Syscalls




3. Hook points
4. User space data
5. Kernel space data
6. Protocol
7. Implementation
8. Design

