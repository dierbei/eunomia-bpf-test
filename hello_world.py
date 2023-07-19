#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./trace_sys_sync.py
# test by running 'sync' in another session while tracing

from bcc import BPF

# BPF program code to trace sys_sync
code = """
#include <linux/ptrace.h>
int trace_sys_sync(struct pt_regs *ctx) {
    bpf_trace_printk("sys_sync() called\\n");
    return 0;
}
"""

# Load BPF program
bpf = BPF(text=code)
bpf.attach_kprobe(event="sys_sync", fn_name="trace_sys_sync")

# Print trace messages
print("Tracing sys_sync()... Ctrl+C to exit.")
bpf.trace_print()

