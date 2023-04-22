# credit: https://github.com/snowflake8
import galois
import numpy as np


output = [40, 238, 34, 149, 109, 191, 206, 216, 216, 206, 87, 214, 214, 20, 46, 4, 214, 189, 206, 17, 189, 228, 176, 20, 189, 100, 46, 80, 78, 4, 80, 228, 87, 191, 189, 4, 20, 214, 87, 78, 46, 206, 214, 87, 228, 119, 68]
start = b"EPFL{"
last_line = [[1, (2*c) %251, (4*c**2) %251] for  i, c in enumerate(start)] + [[1, (2*c) %251, (4*c**2) %251] for  i, c in enumerate(b'}')]

b = output[:len(start)] + [output[-1]]

print(last_line)
print(b)
GF251 = galois.GF(251)
k1,k2,k3 = np.linalg.solve(GF251(last_line[:3]), GF251(b[:3])).tolist()

print([((k1 + 2*k2*c + 4 * k3 *c**2) % 251) == output[i] for  i, c in enumerate(start)])
decrypt = {}
for i in range(126):
    decrypt[(k1 + 2*k2*i + 4 * k3 *i**2) % 251] = chr(i)

res = ""
for o in output:
    res += decrypt[o]

print(res)
