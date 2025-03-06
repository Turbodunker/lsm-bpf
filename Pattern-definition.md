# What is a pattern and what does a pattern consist of?
A pattern is a small generalized LSM BPF program with a specific objective. 
Patterns can be combined to make new patterns altogether, but their main purpose 
is to serve as small and repeatable generalizations for implementing larger, 
more complex programs. It can be thought of as a "building block" or a helper function. 

A pattern consists of the following sections:
1. Objective
2. Name
3. Hook points
4. Implementation
    1. User space 
    2. Kernel space
5. Protocol
6. Design decisions
7. Evaluation 


### Objective
High-level description of the objective of the pattern. This is should be the first element that is determined for a pattern, and should ideally not change after it's set in stone, unless there are severe ambiguities or a more interesting pattern can be created. 
This should be interpreted as a challenge to be solved, ie. what the pattern aims to achieve, not necessarily a description of what this pattern actually achieves. 
In other words, it should be a policy description. The more specifics this contains the better as this will make the evaluation of correctness later much easier.
In particular this must include a specification list, prioritzied or not, of concrete requirements for this pattern. This is to support correctness evaluation later.

Ideally this is void of any ambiguities, but this is unlikely to be the case, especially for the first couple of objectives I'm going to come up with, as I can't reasonably predict all possible challenges that may arise when implementing the pattern. The idea of this section is to guide implementation with a concrete goal that can inform design decisions, without movin. 

### Name
An identifier to make it easier to distinguish between patterns.

### Hook points
A list of the hooks used by this pattern. 
This should be accompanied by a description of the method used for selection, aswell as an argument for why said hooks were chosen over other alternatives. 
This gets it's own section as there must always be at least 1 LSM hook associated with a pattern. 
The selection method for the hook(s) used for this pattern must be discussed here, aswell as an argument for why alternatives were not used.

### Implementation
#### User space 
This section should include the core of the code for the user space application for the pattern. 
#### Kernel space 
This section should include the core of the code for the kernel space application for the pattern. 

### Protocol
Description of how the above user and kernel space data is exchanged. 
The level of detail should depend of the Objective of the pattern, e.g. if timing-restrictions are integral to the Objective, then the protocol should account for this in some way. 
As a minimum a protocol should include a description of what data is being exchanged, and how it's processed.
If it gets real complicated include a diagram in the report.

### Design decisions
A discussion/argumentation for why the points 3-5 are good choices for archieving the Objective, as well as any limitations or side-effects these design decisions may incur. 
This section should also describe any objective-specific aspects not included in the above sections. 
For example if the objective introduces a restriction, that the pattern only acts on 3 unamed syscalls(the 3 most used syscalls for a given workload etc.), then the selection method for these system calls must be described. 
Similarly if the objective introduces other restrictions not covered in sections 3-5, then these must be discussed here aswell. 

### Evaluation
The final section should describe how to determine how well the pattern achieves the objective. This gets it's own section for each pattern, as how patterns are evaluated may vary wildly depending on the objective. 
Evaluation is split into 3 parts as a minimum: Correctness, Ressource usage and Modularity.
- Correctness is intended to measure how well the pattern complies with the specification list given in the Objective. It will be measured via Software testing, for which the specification list will be used to create unit-tests. This metric will be measured as a rate: (number of passed unit-tests/total number of unit-tests).  

However it is understood this cannot be proved to catch all scenarios/bugs. Given the time-constraints and scope of this project, this is about as well as I can do, but ideally this could be done with Hoare-logic or some other formal-system for proving correctness and/or fuzzing in case the pattern involves user input.

- Ressource usage indicates how expenssive the pattern is to use. The pattern may be proven correct wrt. the specification, but it's not worth much if it hogs all the systems ressource to load. This metric includes overhead tests where specific metrics are measured; CPU cycles/usage, syscall latency etc. Overhead should be the goto metric if the patterns specifications does not make other metrics more relevant. For example if the pattern requires a significant amount of memory in maps, then the memory usage of the maps for various workloads should take priority.
Furthermore if some hooks are closely related, one could measure overhead of using various hooks, e.g. file_permission vs. inode_permission. 


- Modularity is the measure of...

