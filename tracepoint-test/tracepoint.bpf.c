#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_open")
int BPF_TRACEPOINT(sys_enter_open)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("sys_enter_open: pid = %d\n", pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int BPF_TRACEPOINT(sys_enter_openat)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("sys_enter_openat: pid = %d\n", pid);
    return 0;
}