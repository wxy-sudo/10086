from random import randint
import math
from gmpy2 import invert
import random
from SM3 import *

import binascii



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



def signature(m,Za):
    m1=Za+m
    e=Hash(m1)
    k=randint(1,n)
    x1,y1=ecc_scalar_mult(xG, yG, k)
    r=(int(e,16)+x1)%n
    s=(invert(1+da,n)*(k-r*da))%n
    return (hex(r)[2:].upper(),hex(s)[2:].upper())

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



p=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
xG=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
yG=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

da=0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
# Generate public key Pa
Pax, Pay = ecc_scalar_mult(xG, yG, da)
Pa = (Pax, Pay)

# Convert message and ID to hexadecimal strings
m = "wxy10086"
m = hex(int(binascii.b2a_hex(m.encode()).decode(), 16)).upper()[2:]
IDa = "wxy_10086_10086"
ida = hex(int(binascii.b2a_hex(IDa.encode()).decode(), 16)).upper()[2:]

# Construct message to be signed (m1)
ENTLa = '{:04X}'.format(len(ida) * 4)
m1 = ENTLa + ida + '{:064X}'.format(a) + '{:064X}'.format(b) + '{:064X}'.format(xG) + '{:064X}'.format(yG) + '{:064X}'.format(Pa[0]) + '{:064X}'.format(Pa[1])
Za = hex(int(Hash(m1), 16))[2:].upper()

# Generate signature
sign = signature(m, Za)
print("r = ", sign[0])
print("s = ", sign[1])
# Verify signature and print result
if Verify(*sign, Za, m, Pa):
    print("Signature is valid:")
    
else:
    print("Signature is not valid.")
print("The result of verification is: ",Verify(*sign, Za, m, Pa))
