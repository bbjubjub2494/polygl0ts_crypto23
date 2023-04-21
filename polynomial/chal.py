import secrets

MOD = 251 # known prime

key = [secrets.randbelow(MOD) for _ in range(3)]

flag = b"EPFL{XXXXXXXXXXXXXXXXX}"

def enc(data):
    return [sum(k*pow(2*x,i,MOD) for i,k in enumerate(key)) % MOD for x in data]

print(enc(flag))
