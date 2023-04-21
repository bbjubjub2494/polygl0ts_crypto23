#!/usr/bin/env python3

import secrets

from Crypto.Cipher import AES

FLAG = "EPFL{SEcUriTY_pr00F$?_Wh3r3_we_R_go1n9_we_d0nt_n3Ed_pr00fs}"

def win():
    print("flag:", FLAG)

def input_hex(prompt):
    data = input(prompt)
    data = bytes.fromhex(data)
    return data

def game():
    key = secrets.token_bytes(32)

    b = secrets.choice([0,1])

    m1 = input_hex("m1 = ")
    assert len(m1) == 16

    m2 = input_hex("m2 = ")
    assert len(m2) == 16

    m_b = [m1,m2][b]

    cipher = AES.new(key, AES.MODE_CBC)
    c = cipher.iv + cipher.encrypt(m_b)
    print(f"c = {c.hex()}")

    cc = input_hex("c' = ")
    m = AES.new(key, AES.MODE_ECB).decrypt(cc)
    print(f"m = {m.hex()}")

    bb = int(input("b' = "))
    if bb not in range(2):
        raise ValueError("b' must be a bit")
    return b == bb

N_ROUNDS = 64
for _ in range(N_ROUNDS):
    ok = game()
    if not ok:
        print("you lost")
        break
else:
    win()
