import secrets

from Crypto.Util.strxor import strxor as xor

nonce = b"secret nonce"
key = secrets.token_bytes(32)

msg1, msg2 = [bytes.fromhex(m) for m in open("output", 'r').read().splitlines()]
msg1 = msg1.ljust(len(msg2), b"\0")
crib = b"Lorem Ipsum Dolor Sit Amet"
print(xor(crib, xor(msg1, msg2)[:len(crib)]))
