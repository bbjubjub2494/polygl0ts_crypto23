MOD = 251
data = eval(open("output").read())

prefix = b"EPF"

mat = [[pow(2*x,j, MOD) for j in range(3)] + [y] for x, y in zip(prefix, data)]

for i in range(3):
    l = mat[i][i]
    r = pow(l,-1,MOD)
    mat[i] = [r *x%MOD for x in mat[i]]
    for j in range(3):
        if i == j:
            continue
        m = mat[j][i]
        mat[j] = [(x-m*y) %MOD for x,y in zip(mat[j],mat[i])]

key = [mat[i][3] for i in range(3)]

flag = ""
for y in data:
    # solve a*x^2 + b*x + c = y
    c,b,a = key
    c -= y
    delta = pow(b,2,MOD) - 4*a*c
    sqrt_delta = pow(delta, (MOD+1)//4, MOD)
    x1 = (-b - sqrt_delta) * pow(2*a,-1,MOD) % MOD
    x2 = (-b + sqrt_delta) * pow(2*a,-1,MOD) % MOD
    x = x2 if x1 & 1 else x1
    x //= 2
    flag += chr(x)

print(flag)
