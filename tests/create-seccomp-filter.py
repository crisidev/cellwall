#!/usr/bin/env python3
"""
Create a simple seccomp BPF filter that allows all syscalls.
This is used for testing the seccomp loading mechanism.
"""
import struct
import sys

# BPF instruction format: struct sock_filter {
#   __u16 code;   /* Actual filter code */
#   __u8  jt;     /* Jump true */
#   __u8  jf;     /* Jump false */
#   __u32 k;      /* Generic multiuse field */
# };

# Simple filter that returns SECCOMP_RET_ALLOW for all syscalls
# BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW
SECCOMP_RET_ALLOW = 0x7fff0000

instructions = [
    # Return ALLOW
    (0x06, 0, 0, SECCOMP_RET_ALLOW),  # BPF_RET | BPF_K
]

# Write binary BPF program to stdout
for code, jt, jf, k in instructions:
    sys.stdout.buffer.write(struct.pack('=HBBI', code, jt, jf, k))
