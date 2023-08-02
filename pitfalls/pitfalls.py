import random
  
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b
def Euc(a, m):
    if gcd(a, m) != 1 and gcd(a, m) != -1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    if u1 > 0:
        return u1 % m
    else:
        return (u1 + m) % m

def add(m, n):
    if (m == 0):
        return n
    if (n == 0):
        return m
    he = []
    if (m != n):
        if (gcd(m[0] - n[0], p) != 1 and gcd(m[0] - n[0], p) != -1):
            return 0
        else:
            k = ((m[1] - n[1]) * Euc(m[0] - n[0], p)) % p
    else:
        k = ((3 * (m[0] ** 2) + a) * Euc(2 * m[1], p)) % p
    x = (k ** 2 - m[0] - n[0]) % p
    y = (k * (m[0] - x) - m[1]) % p
    he.append(x)
    he.append(y)
    return he

def mul(n, l):
    if n == 0:
        return 0
    if n == 1:
        return l
    t = l
    while (n >= 2):
        t = add(t, l)
        n = n - 1
    return t

def ECDSA_sig(m, n, G, d,k):
    e = hash(m)
    R = mul(k, G)
    r = R[0] % n
    s = (Euc(k, n) * (e + d * r)) % n
    return r, s

def ECDSA_ver(m, n, G, r, s, P):
    e = hash(m)
    w = Euc(s, n)
    v1 = (e * w) % n
    v2 = (r * w) % n
    w = add(mul(v1, G), mul(v2, P))
    if (w == 0):
        print('false')
        return False
    else:
        if (w[0] % n == r):
            print('true')
            return True
        else:
            print('false')
            return False



#SM2-pitfalls
def Leaking_K_of_Leaking_d(r,n,k,s,m):
    r_reverse=Euc(r,n)
    e=hash(m)
    d=r_reverse * (k*s-e)%n
    return d

def Reuse_K_of_Leaking_d(r1,s1,m1,r2,s2,m2,n):
    e1=hash(m1)
    e2=hash(m2)
    d=((s1 * e2 - s2 * e1) * Euc((s2 * r1 - s1 * r1), n)) % n
    return d

def Using_Same_K(s1,m1,s2,m2,r,d1,d2,n):
    e1=hash(m1)
    e2=hash(m2)
    d2_1 = ((s2 * e1 - s1 * e2 + s2 * r * d1) * Euc(s1 * r, n)) % n
    d1_1 = ((s1 * e2 - s2 * e1 + s1 * r * d2) * Euc(s2 * r, n)) % n
    if(d2==d2_1 and d1_1==d1):
        print("使用相同的k攻击成功")
        return 1
    else:
        return 

if __name__ == '__main__':
    m="10086"
    m_1="1008610086"
    x=5
    y=1
    G = [5, 1]
    a = 2
    b = 2
    p = 17
    n = 19
    k=2
    d = 5
    P = mul(d, G)
    print("m=",m)
    print("m1=",m_1)
    r,s=ECDSA_sig(m,n,G,d,k)
    print("k leakage:")
    print("r=",r,"s=",s)
    if (d == Leaking_K_of_Leaking_d(r,n,k,s,m)):
        print("k泄露攻击成功,d=",d)

    print("k use more than once:")
    r_1,s_1=ECDSA_sig(m_1,n,G,d,k)
    r_2,s_2=ECDSA_sig(m,n,G,7,k)
    print("r1=",r_1,"s1=",s_1)
    print("r2=",r_2,"s2=",s_2)
    if (d == Reuse_K_of_Leaking_d(r,s,m,r_1,s_1,m_1,n)):
        print("k复用成功,d=",d)
        
    print("same k:")
    print("r=",r)
    print("s1=",s_1)
    print("s2=",s_2)
    Using_Same_K(s_1,m_1,s_2,m,r,5,7,n)
