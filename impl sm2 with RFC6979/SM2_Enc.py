from random import randint
import math
from SM3 import *
from gmpy2 import invert
import random
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

def KDF(z,klen):
    ct=1
    k=''
    for i in range(math.ceil(klen/256)):
        t=hex(int(z+'{:032b}'.format(ct),2))[2:]
        k=k+hex(int(Hash(t),16))[2:]
        ct=ct+1
    k='0'*((256-(len(bin(int(k,16))[2:])%256))%256)+bin(int(k,16))[2:]
    return k[:klen]


def encrypt(m):
    # Convert message to binary string
    m_bin = bin(int.from_bytes(m.encode(), 'big'))[2:]

    # Pad message with zeros to ensure length is a multiple of 4
    m_bin = m_bin.zfill((len(m_bin) + 3) // 4 * 4)

    # Generate a random key k
    while True:
        k = randint(1, n)
        if k != da:
            break

    # Compute public key coordinates
    x1, y1 = ecc_scalar_mult(xG, yG, k)

    # Format public key coordinates as hexadecimal strings
    plen = len(hex(p)[2:])
    x1_hex = hex(x1)[2:].zfill(plen)
    y1_hex = hex(y1)[2:].zfill(plen)

    # Compute shared secret
    x2, y2 = ecc_scalar_mult(Pa[0], Pa[1], k)
    x2_bin = bin(x2)[2:].zfill(256)
    y2_bin = bin(y2)[2:].zfill(256)
    t = KDF(x2_bin + y2_bin, len(m_bin))

    # XOR message with shared secret to obtain ciphertext
    c2_hex = hex(int(m_bin, 2) ^ int(t, 2))[2:].zfill(len(m_bin) // 4)

    # Compute tag
    c3_hex = Hash(x2_bin + m_bin + y2_bin).upper()

    return x1_hex + y1_hex, c2_hex, c3_hex


def decrypt(c1, c2, c3):
    # Parse public key coordinates from ciphertext
    plen = len(hex(p)[2:])
    x1_hex = c1[:plen]
    y1_hex = c1[plen:]

    # Convert public key coordinates to integers
    x1 = int(x1_hex, 16)
    y1 = int(y1_hex, 16)

    # Verify that public key is on the curve
    if pow(y1, 2, p) != (pow(x1, 3, p) + a * x1 + b) % p:
        return False

    # Compute shared secret
    x2, y2 = ecc_scalar_mult(x1, y1, da)
    x2_bin = bin(x2)[2:].zfill(256)
    y2_bin = bin(y2)[2:].zfill(256)
    t = KDF(x2_bin + y2_bin, len(c2) * 4)

    # XOR ciphertext with shared secret to obtain message
    m_bin = bin(int(c2, 16) ^ int(t, 2))[2:].zfill(len(c2) * 4)

    # Compute tag
    u_hex = Hash(x2_bin + m_bin + y2_bin).upper()

    # Verify tag
    if c3 != u_hex:
        return False

    # Convert message to string
    m = int(m_bin, 2).to_bytes(len(m_bin) // 8, 'big').decode()

    return m

p=0xBDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F
a=0xBB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985
b=0x1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1
n=0xBDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677
xG=0x4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640
yG=0x02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2
da=0x58892B807074F53FBF67288A1DFAA1AC313455FE60355AFD
Pa=ecc_scalar_mult(xG, yG, da)
m = "wxy_10086"
c1, c2, c3 = encrypt(m)
print("Original message:", m)
print("Encrypted message:")
print("c1:", c1)
print("c2:", c2)
print("c3:", c3)
m2 = decrypt(c1, c2, c3)
print("Decrypted message:", m2)
