import secrets

from Crypto.Cipher import ChaCha20_Poly1305

nonce = b"secret nonce"
key = secrets.token_bytes(32)

def encrypt(msg):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(bytes(msg, "utf8"))
    return ct+tag

flag = "EPFL{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}"
message1 = flag
message2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

print(encrypt(message1).hex())
print(encrypt(message2).hex())
