# Useful links 

## eBPF specific and example programs
* https://docs.ebpf.io/
* https://docs.kernel.org/bpf/
* [helperfunctions](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
* [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c)
* [libbpf-tools examples](https://github.com/iovisor/bcc/tree/master/libbpf-tools)
### Utilities
* https://github.com/libbpf/libbpf
* https://github.com/bpftrace/bpftrace
* https://github.com/iovisor/bcc/tree/master/libbpf-tools
* https://github.com/lumontec/lsmtrace - Seems to only work for kernel <= 5.12... but I could probably fix it... but it's not needed atm.

## Use-cases
* https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/

## Kernel stuff & hooks
* https://elixir.bootlin.com/linux/v6.8/source lookup of my kernel version
* https://www.kernel.org/doc/html/v5.1/security/LSM.html hook definitions with explainer text
* https://litux.nl/mirror/kerneldevelopment/0672327201/toc.html struct definitions
# Useful commands
Tracing LSM Hooks by syscall:
https://stackoverflow.com/questions/77534507/how-to-determine-lsm-hook-from-a-syscall
```
-p = the tracer used, 
-g = only trace this function and functions it calls
-F = only consider this executable

trace-cmd record -p function_graph -g '*execve*' -F $HOME/test/helloworld # OR /usr/bin/zoom
trace-cmd report | cat | grep bpf_lsm
```


Debug binaries 
```
llvm-objdump -rd <binary>
```

Find all (dynamically linked) shared library dependencies for a binary
```
lld <binary>
```

# BPF helpers and macros
* BPF_CORE_READ(ptr1, ptr2, ...) for pointer chasing
* bpf_get_current_comm get filename into buffer... if it's 15bytes(last is NUL)
* bpf_path_d_path should use this, but my kernel is outdated... should maybe upgrade