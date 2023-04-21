#!/usr/bin/env python3

import kat
import secrets

FLAG = "EPFL{XXXXXXXXXXXXXXX}"


def improved_signature(m, sk, pk):
    from kat import H, bit, Hint, b, B, scalarmult, encodepoint, encodeint, l

    h = H(sk)
    a = 2 ** (b - 2) + sum(2**i * bit(h, i) for i in range(3, b - 2))
    r = Hint(m)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


kat.signature = improved_signature

sk = secrets.token_bytes(16)
pk = kat.publickey(sk)
m = b"This was signed with improved25519"
sig = kat.signature(m, sk, pk)

print(f"pk = {pk.hex()}")
print(f"sig = {sig.hex()}")

sig = bytes.fromhex(input("admin signature (in hex): "))
try:
    kat.checkvalid(sig, b"gib flag", pk)
except Exception:
    pass
else:
    print(FLAG)
