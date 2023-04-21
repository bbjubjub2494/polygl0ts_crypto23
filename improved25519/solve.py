#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chal.py
from pwn import *

exe = "chal.py"

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.REMOTE:
        return ...
    else:
        return process([exe] + argv, *a, **kw)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.recvuntil("pk = ")
pk = bytes.fromhex(io.recvlineS())

m = b"This was signed with improved25519"

io.recvuntil("sig = ")
sig = bytes.fromhex(io.recvlineS())

from kat import *

checkvalid(sig, m, pk)

R = decodepoint(sig[0 : b // 8])
A = decodepoint(pk)
S = decodeint(sig[b // 8 : b // 4])
h = Hint(encodepoint(R) + pk + m)
r = Hint(m)
# S = (r + Hint(encodepoint(R) + pk + m) * a) % l
a = (S - r) * pow(h, -1, l) % l
assert A == scalarmult(B, a)

m = b"gib flag"
S = (r + Hint(encodepoint(R) + pk + m) * a) % l
sig = encodepoint(R) + encodeint(S)

checkvalid(sig, b"gib flag", pk)

io.sendlineafter(b"admin signature (in hex): ", sig.hex())

io.interactive()
