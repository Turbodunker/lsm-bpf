# Questions:
* Multiple CPU's at work for simple Hello World. The order of the hooks seems to be the same every run. But are there race-conditions between hooks?

* What are the complete set of LSM hooks that can be used with lsm-bpf(kernel 6.8)?

``` mermaid
    mindmap
        root((lsm-bpf))
            LSM-Hooks
                What hooks can we use?
                    Use function_graph to trace triggered hooks by syscall
                        Are events subject to race-conditions?
            BPF Programs
                What is license GPL and is required(and why)?
```