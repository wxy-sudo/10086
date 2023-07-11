import hashlib
import math
import random

def Legendre_symbol(a, p): 
    return pow(n, (p - 1) // 2, p)

def modular_sqrt(a, p):
    if p <= 0 or p % 2 == 0 or Legendre_symbol(a, p)!=1:
        return None
    if a == 0 or a == 1:
        return a
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    b = 2
    while pow(b, (p - 1) // 2, p) != p - 1:
        b += 1
    s, t = 0, p - 1
    while t % 2 == 0:
        s += 1
        t //= 2
    # 利用 Tonelli-Shanks 算法计算模平方根
    x = pow(a, (t + 1) // 2, p)
    e = pow(a, t, p)
    y = x
    for _ in range(1, s):
        z = pow(y, 2, p) * e % p
        if z == p - 1:
            y = y * b % p
        else:
            x = x * pow(b, pow(2, s - _ - 1, p - 1), p) % p
            y = y * pow(b, pow(2, s - _, p - 1), p) % p
            e = z
    return x

def elliptic_curve_hash(u):
    h = int(hashlib.sha256(str(u).encode()).hexdigest(), 16)
    for i in range(0, p):
        x = (h + i) % p
        d = (x ** 3 + a * x + b) % p
        if pow(d, (p - 1) // 2, p) % p == 1:
            y = modular_sqrt(d, p)
            return [x, y]
    return None

def elliptic_curve_hash_set(s):
    result = [0, 0]
    for x in s:
        point = elliptic_curve_hash(x)
        if point is not None:
            result[0] += point[0]
            result[1] += point[1]
    return result


if __name__ == '__main__':
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    G = 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7, 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0

    m1 = 'liujiaming'
    m2 = 'sdu'
    h1 = elliptic_curve_hash(m1)
    h2 = elliptic_curve_hash(m2)

    print("Elliptic Curve Message Hash of '{}':\n{}".format(m1, h1))
    print("Elliptic Curve Message Hash of '{}':\n{}".format(m2, h2))
    s1 = {m1, m2}
    h3 = elliptic_curve_hash_set(s1)
    print("Elliptic Curve Message Hash Set of {}: \n{}".format(s1, h3))
    if (h3[0] == h2[0] + h1[0] and h3[1] == h2[1] + h1[1]):
        print("The sum of ECMH('{}') and ECMH('{}') matches ECMH({})".format(m1, m2, s1))
    else:
        print("The sum of ECMH('{}') and ECMH('{}') does not match ECMH({})".format(m1, m2, s1))
    s3 = s1 - {m1}
    h3 = elliptic_curve_hash_set(s3)
    print("Elliptic Curve Message Hash Set of {} after removing '{}':\n{}".format(s1, m1, h3))
    if (h3 == h2):
        print("ECMH({} - '{}') matches ECMH('{}')".format(s1, m1, m2))
    else:
        print("ECMH({} - '{}') does not match ECMH('{}')".format(s1, m1, m2))
