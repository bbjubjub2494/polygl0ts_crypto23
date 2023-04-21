import secrets

from Crypto.Cipher import ChaCha20_Poly1305

nonce = b"secret nonce"
key = secrets.token_bytes(32)

def encrypt(msg):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(bytes(msg, "utf8"))
    return ct+tag

flag = "EPFL{1F_Y0U_R3U5E_NONCE5_CL4P_Y0UR_8ANDS}"
message1 = flag
message2 = "Lorem Ipsum Dolor Sit Amet"

print(encrypt(message1).hex())
print(encrypt(message2).hex())
