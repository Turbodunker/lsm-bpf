# Useful links 

## eBPF specific
* https://docs.ebpf.io/
* https://docs.kernel.org/bpf/
* [helperfunctions](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
### Utilities
* https://github.com/libbpf/libbpf
* https://github.com/bpftrace/bpftrace
* https://github.com/iovisor/bcc/tree/master/libbpf-tools
* https://github.com/lumontec/lsmtrace - Seems to only work for kernel <= 5.12

## Use-cases
* https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/

## Kernel stuff
https://elixir.bootlin.com/linux/v6.8/source

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

# BPF helpers and macros
* BPF_CORE_READ(ptr1, ptr2, ...) for pointer chasing
* bpf_get_current_comm get filename into buffer