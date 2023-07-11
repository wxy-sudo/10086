# impl sm2 with RFC6979

## SM2_Sign

### 实现思路

先定义椭圆曲线上的加法和点乘运算

```
def add(x1, y1, x2, y2):
    if x1 == x2 and y1 == p - y2:
        return False
    lamda = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p if x1 != x2 else ((3 * x1 * x1 + a) * pow(2 * y1, p - 2, p)) % p
    x3 = (lamda * lamda - x1 - x2) % p
    y3 = (lamda * (x1 - x3) - y1) % p
    return x3, y3
```

```
def ecc_scalar_mult(x, y, k):
    qx, qy = None, None
    while k > 0:
        if k & 1:
            if qx is None:
                qx, qy = x, y
            else:
                qx, qy = add(qx, qy, x, y)
        k >>= 1
        x, y = add(x, y, x, y)
    return (qx, qy)

```

接着完成预计算的过程

```
m = "wxy10086"
m = hex(int(binascii.b2a_hex(m.encode()).decode(), 16)).upper()[2:]
print("m = ", m)
IDa = "wxy_10086_10086"
ida = hex(int(binascii.b2a_hex(IDa.encode()).decode(), 16)).upper()[2:]

# Construct message to be signed (m1)
ENTLa = '{:04X}'.format(len(ida) * 4)
m1 = ENTLa + ida + '{:064X}'.format(a) + '{:064X}'.format(b) + '{:064X}'.format(xG) + '{:064X}'.format(yG) + '{:064X}'.format(Pa[0]) + '{:064X}'.format(Pa[1])
Za = hex(int(Hash(m1), 16))[2:].upper()

```

接下来完成签名的函数

```
def signature(m,Za):
    m1=Za+m
    e=Hash(m1)
    k=randint(1,n)
    print("k = ", k)
    x1,y1=ecc_scalar_mult(xG, yG, k)
    print("x1 = ", x1)
    print("y1 = ", y1)
    r=(int(e,16)+x1)%n
    s=(invert(1+da,n)*(k-r*da))%n
    return (hex(r)[2:].upper(),hex(s)[2:].upper())
```

最后完成验证的过程

```
def Verify(r,s,Za,m,Pa):
    if int(r,16) not in range(1,n-1):
        return False
    if int(s,16) not in range(1,n-1):
        return False
    m1=Za+m
    e=Hash(m1)
    t=(int(r,16)+int(s,16))%n
    if t==0:
        return False
    x1,y1=ecc_scalar_mult(Pa[0],Pa[1],t)
    x2,y2=ecc_scalar_mult(xG, yG, int(s, 16))
    x1,y1=add(x2,y2,x1,y1)
    R=(int(e,16)+x1)%n
    if(hex(R)[2:].upper()==r):
        return True
    return False
```

### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project11/sm2_sign.png)

## SM2_Enc

### 实现思路

同样先实现椭圆曲线上的加法与点乘运算

```
def add(x1, y1, x2, y2):
    if x1 == x2 and y1 == p - y2:
        return False
    lamda = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p if x1 != x2 else ((3 * x1 * x1 + a) * pow(2 * y1, p - 2, p)) % p
    x3 = (lamda * lamda - x1 - x2) % p
    y3 = (lamda * (x1 - x3) - y1) % p
    return x3, y3

def ecc_scalar_mult(x, y, k):
    qx, qy = None, None
    while k > 0:
        if k & 1:
            if qx is None:
                qx, qy = x, y
            else:
                qx, qy = add(qx, qy, x, y)
        k >>= 1
        x, y = add(x, y, x, y)
    return (qx, qy)
```

接着实现生成密钥的函数，使得到的key与消息的长度相等，从而可以实现异或操作

```
def KDF(z,klen):
    ct=1
    k=''
    for i in range(math.ceil(klen/256)):
        t=hex(int(z+'{:032b}'.format(ct),2))[2:]
        k=k+hex(int(Hash(t),16))[2:]
        ct=ct+1
    k='0'*((256-(len(bin(int(k,16))[2:])%256))%256)+bin(int(k,16))[2:]
    return k[:klen]
```

最后实现加密和解密的操作

```
def encrypt(m):
    m_bin = bin(int.from_bytes(m.encode(), 'big'))[2:]

    m_bin = m_bin.zfill((len(m_bin) + 3) // 4 * 4)

    while True:
        k = randint(1, n)
        if k != da:
            break

    x1, y1 = ecc_scalar_mult(xG, yG, k)
    plen = len(hex(p)[2:])
    x1_hex = hex(x1)[2:].zfill(plen)
    y1_hex = hex(y1)[2:].zfill(plen)
    x2, y2 = ecc_scalar_mult(Pa[0], Pa[1], k)
    x2_bin = bin(x2)[2:].zfill(256)
    y2_bin = bin(y2)[2:].zfill(256)
    t = KDF(x2_bin + y2_bin, len(m_bin))
    c2_hex = hex(int(m_bin, 2) ^ int(t, 2))[2:].zfill(len(m_bin) // 4)
    c3_hex = Hash(x2_bin + m_bin + y2_bin).upper()
    return x1_hex + y1_hex, c2_hex, c3_hex
```

```
def decrypt(c1, c2, c3):
    # Parse public key coordinates from ciphertext
    plen = len(hex(p)[2:])
    x1_hex = c1[:plen]
    y1_hex = c1[plen:]

    # Convert public key coordinates to integers
    x1 = int(x1_hex, 16)
    y1 = int(y1_hex, 16)

    if pow(y1, 2, p) != (pow(x1, 3, p) + a * x1 + b) % p:
        return False

    x2, y2 = ecc_scalar_mult(x1, y1, da)
    x2_bin = bin(x2)[2:].zfill(256)
    y2_bin = bin(y2)[2:].zfill(256)
    t = KDF(x2_bin + y2_bin, len(c2) * 4)

    m_bin = bin(int(c2, 16) ^ int(t, 2))[2:].zfill(len(c2) * 4)

    u_hex = Hash(x2_bin + m_bin + y2_bin).upper()

    if c3 != u_hex:
        return False

    m = int(m_bin, 2).to_bytes(len(m_bin) // 8, 'big').decode()

    return m
```

### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project11/sm2_enc.png)





