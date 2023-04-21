#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chal.py
from pwn import *

# Set up pwntools for the correct architecture
exe = 'chal.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return
    else:
        return process(["python3", "chal.py"] + argv, *a, **kw)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

N_ROUNDS = 64
for i in range(N_ROUNDS):
    io.sendlineafter(b"m1 = ", b"aa"*16)
    io.sendlineafter(b"m2 = ", b"bb"*16)
    io.recvuntil(b"c = ")
    c = bytes.fromhex(io.recvlineS())
    iv, c = c[:16], c[16:]
    io.sendlineafter(b"c' = ", c.hex())
    io.recvuntil(b"m = ")
    m = bytes.fromhex(io.recvlineS())
    bb = int(m[0] ^ iv[0] != 0xaa)
    io.sendlineafter(b"b' = ", str(bb))

io.interactive()

