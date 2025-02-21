# What is a pattern and what does a pattern consist of?
A pattern is a small generalized LSM BPF program with a specific objective. 
Patterns can be combined to make new patterns altogether, but their main purpose is to serve as small and repeatable generalizations for implementing larger, more complex programs. It can be thought of as a "building block" or a helper function. A single pattern consists of the following elements. 

A pattern consists of the following elements:
1. Objective
2. Trigger
3. Hook points
4. User space data
5. Kernel space data 
6. Protocol
7. Implementation 
8. Design


### Objective
High-level description of what the objective of the pattern. This must testable by quantitative methods.
* Example: Block read-operations for one or more user-specified directories and all files in that directory. Opening and writing to files are ok. This should only work 1-level of the directory, ie. not recursively. (NOte: should this work for all userS?) 

### Trigger
The system call(s) triggering the kernel function(s) to hook into. Note that we are not hooking into syscalls via tracepoints.

### Hook points
The hooks points used by this pattern.

### User space data
What data is required from, and provided by, user space.

### Kernel space data
What data is required from, and provided by, kernel space.

### Protocol
Description of how the above user and kernel space data is exchanged. The level of detail should depend of the Objective of the pattern, e.g. if time-restrictions are integral to the Objective, then the protocol should probably account for this. As a minimum a protocol should include a description of what data is being exchanged, and how it's processed.

### Implementation
A code-snippet of how the pattern is being implemented. 

### Design
A discussion/argumentation for why the points 2-7 are good choices for archieving the Objective, as well as any limitations or side-effects these may incur.   



