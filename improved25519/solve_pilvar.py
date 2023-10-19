from kat import *
from pwn import *


lmao = process("./chal.py")

#log.info(b"pk = "+lmao.recvline())
#og.info(b"a = "+lmao.recvline())
#og.info(b"S = "+lmao.recvline())
#og.info(b"R = "+lmao.recvline())

pk = bytes.fromhex(lmao.recvline()[5:-1].decode())
#print(pk)

sig = lmao.recvline()[6:-1]

#print(sig)
#print(sig[:64].decode())
#print(sig[64:].decode())
R = decodepoint(bytes.fromhex(sig[:64].decode()))

#print(len(sig))
S = decodeint(bytes.fromhex(sig[64:].decode()))

first_m = b"This was signed with improved25519"
r = Hint(first_m)
R = scalarmult(B, r)
#S = r + Hint(encodepoint(R) + pk + m) * a % l
#S - r = Hint(encodepoint(R) + pk + m) * a % l
a = ((S - r) * pow(Hint(encodepoint(R) + pk + first_m),-1,l)) % l
log.info("pk = "+pk.hex())
log.info(b"a = "+str(a).encode())
log.info(b"S = "+str(S).encode())
log.info(b"R = "+str(R).encode())



m = b"gib flag"
r = Hint(m)
R = scalarmult(B, r)
S = (r + Hint(encodepoint(R) + pk + m) * a) % l
lmao.sendlineafter(b"admin signature (in hex): ", (encodepoint(R) + encodeint(S)).hex().encode())
#lmao.interactive()
