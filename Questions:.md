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
                What is license GPL and is required and why?
            Examples
                deny_unshare
                    id1["error: bpf_object__probe_loading():Operation not permitted(1). Couldn't load trivial BPF program. Check RLIMIT_MEMLOCK is set big enough value"]

```