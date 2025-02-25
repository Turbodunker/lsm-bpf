# What is a pattern and what does a pattern consist of?
A pattern is a small generalized LSM BPF program with a specific objective. 
Patterns can be combined to make new patterns altogether, but their main purpose is to serve as small and repeatable generalizations for implementing larger, more complex programs. It can be thought of as a "building block" or a helper function. A single pattern consists of the following sections. 

A pattern consists of the following sections:
1. Name
2. Objective
3. Hook points
4. User space data
5. Kernel space data 
6. Protocol
7. Implementation 
8. Design
9. Evaluation

### Name
An identifier to make it easier to distinguish between patterns.

### Objective
High-level description of the objective of the pattern. Ideally this is void of any ambiguities. This should be interpreted as a challenge to be solved, ie. what the pattern aims to achieve, and is NOT a resume of what this pattern actually does. 

### Hook points
A list of the hooks used by this pattern. 
This should be accompanied by a description of the method used for selection, aswell as an argument for why said hooks were chosen over other alternatives. 
This gets it's own section as there must always be at least 1 LSM hook associated with a pattern. 
The selection method for the hook(s) used for this pattern must be discussed here, aswell as an argument for why alternatives were not used.


### User space data
What data is required from, and provided by, user space.

### Kernel space data
What data is required from, and provided by, kernel space.

### Protocol
Description of how the above user and kernel space data is exchanged. 
The level of detail should depend of the Objective of the pattern, e.g. if timing-restrictions are integral to the Objective, then the protocol should probably account for this in some way. 
As a minimum a protocol should include a description of what data is being exchanged, and how it's processed.

### Implementation
A code-snippet of how the pattern is being implemented. 

### Design
A discussion/argumentation for why the points 2-6 are good choices for archieving the Objective, as well as any limitations or side-effects these design decisions may incur. 
This section should also describe any objective-specific aspects not included in the above sections. 
For example if the objective introduces a restriction, that the pattern only acts on 3 unamed syscalls(the 3 most used syscalls for a given workload etc.), then the selection method for these system calls must be described. 
Similarly if the objective introduces timing-restrictions then these must be


### Evaluation
This section should 
