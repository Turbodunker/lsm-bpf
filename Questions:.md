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
                ("We can define structs(e.g. task_struct) and only their fields we will need to access?")
                    We HAVE to redefine structs we will be using, but only the fields we need to use. CO-RE handles the rest... i think
            Examples
                deny_unshare
                    id1["error: bpf_object__probe_loading():Operation not permitted(1). Couldnt load trivial BPF program. Check RLIMIT_MEMLOCK is set big enough value"]
                        id2["update /etc/security/limits.conf: https://github.com/coreos/fedora-coreos-tracker/issues/1164"]
                        workaround["workaround: remove the CAP_SYS_ADMIN check"]
                Zoom
                    First iteration: get the i_ino value outside the script and hardcode it in. Deny all accesses to this inode to test
                        Success... but not very useful
                    Second iteration: get the i_ino value from the BPF program

```