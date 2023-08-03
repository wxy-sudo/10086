import sys
import struct
import random
from math import gcd, ceil, floor
from gmssl import sm3
import socket
import threading
import time


def int_hex(str):
    return int(str, 16)


def sm3_hash(message):
    message = message.encode('utf-8')
    msg_list = [i for i in message]
    hash_hex = sm3.sm3_hash(msg_list)

    return hash_hex


def inv(a, m):
    if gcd(a, m) != 1:
        return None

    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        d, x, y = extended_gcd(b, a % b)
        return d, y, x - (a // b) * y

    t1, x, t2 = extended_gcd(a, m)
    return x % m


def add_ECC(P, Q):
    if P == 0:
        return Q
    if Q == 0:
        return P
    x1, y1, x2, y2 = int_hex(P[0]), int_hex(P[1]), int_hex(Q[0]), int_hex(Q[1])
    q_int = int_hex(q)
    tmp1, tmp2 = y2 - y1, inv(x2 - x1 % q_int, q_int)
    l = tmp1 * tmp2 % q_int
    x = (l * l - x1 - x2) % q_int
    y = (l * (x1 - x) - y1) % q_int
    res = (hex(x)[2:], hex(y)[2:])
    return res


def double_ECC(P):
    if P == 0:
        return P
    x1, y1 = int_hex(P[0]), int_hex(P[1])
    a_int, q_int = int_hex(a), int_hex(q)
    tmp1 = 3 * x1 * x1 + a_int
    tmp2 = inv(2 * y1, q_int)
    l = (tmp1 * tmp2) % q_int
    x = (l * l - 2 * x1) % q_int
    y = (l * (x1 - x) - y1) % q_int
    Q = (hex(x)[2:], hex(y)[2:])
    return Q


def mul_ECC(P, k):
    k_bin = bin(k)[2:]
    i = len(k_bin) - 1
    Q = P
    if i > 0:
        k = k - 2**i
        while i > 0:
            Q = double_ECC(Q)
            i -= 1
        if (k > 0):
            Q = add_ECC(Q, mul_ECC(P, k))

    return Q


def check_ECC(P):
    x, y = int_hex(P[0]), int_hex(P[1])
    q_int, a_int, b_int = int_hex(q), int_hex(a), int_hex(b)
    if (y * y) % q_int == (x * x * x + a_int * x + b_int) % q_int:
        return True
    else:
        return False


def KDF(Z, klen):
    ct = int_hex("00000001")
    ceil_val = ceil(klen / v)
    floor_val = floor(klen / v)
    hash = b""

    for i in range(1, ceil_val):
        ct_hex = hex(ct)[2:]
        hash += sm3_hash(Z + (ct_hex).zfill(8))
        ct += 1
    ct_hex = hex(ct)[2:]
    if klen % v == 0:
        hash_x = sm3_hash(Z + (ct_hex).zfill(8))
    else:
        hash_x = sm3_hash(Z + (ct_hex).zfill(8))
        hash_x = hash_x[:((klen - v * floor_val) // 4)]
    K = hash.hex() + hash_x

    return K


def sm2_enc(M, P_B):
    klen = len(M) * 4
    k = hex(random.randint(1, int_hex(n) - 1))[2:]
    k_int = int_hex(k)
    C1 = mul_ECC(G, k_int)
    x2, y2 = mul_ECC(P_B, k_int)
    t = KDF(x2 + y2, klen)

    C2 = hex(int_hex(M) ^ int_hex(t))[2:]
    C3 = sm3_hash(x2 + M + y2)
    C = C1[0] + C1[1] + C2 + C3
    len_x = len(C1[0])
    len_y = len(C1[1])
    len_C2 = len(C2)

    print(f'C1: {C1}')
    print(f'C2: {C2}')
    print(f'C3: {C3}')

    return C, len_x, len_y, len_C2


def sm2_dec(CT, d_B, len_x, len_y, len_C2, klen):
    x1 = CT[:len_x]
    y1 = CT[len_x:len_x + len_y]
    C1 = (x1, y1)
    if check_ECC(C1) == False:
        print("False!")
        return ""
    x2, y2 = mul_ECC(C1, int_hex(d_B))
    t = KDF(x2 + y2, klen)

    C2 = CT[len_x + len_y:len_x + len_y + len_C2]
    M = hex(int_hex(C2) ^ int_hex(t))[2:]

    u = sm3_hash(x2 + M + y2)
    C3 = CT[len_x + len_y + len_C2:]
    if u != C3:
        print("False!")
        return ""

    return M


#参数设定
q = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
x_G = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
y_G = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
G = (x_G, y_G)
n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
#私钥
d_1 = hex(random.randint(1, int_hex(n) - 1))[2:]
d_2 = hex(random.randint(1, int_hex(n) - 1))[2:]
d_1_inv = inv(int_hex(d_1), int_hex(n))
d_2_inv = inv(int_hex(d_2), int_hex(n))
d = hex((d_1_inv * d_2_inv - 1))[2:]
P = mul_ECC(G, int_hex(d))
v = 256

C1 = ('3c8465b81aa67d75c07555024bc42b885e106b493afc70e7d2a3371a80fda3be',
      'e570c12918ff58744d2251a18cf6371ef56c9d714f8abc6e8d70af1bf73f760')
C2 = '706a1b7699ebb2be70063653162459bd1'
C3 = '757ce752698fb9faf84a8deaababceecf817d48590e91317565e9aa71dc2459e'

if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8000)
    server_socket.bind(server_address)

    server_socket.listen(1)
    print('Waiting for connecting...')

    client_socket, client_addr = server_socket.accept()
    print('Bob has connected!')

    #step1
    d_1 = d_1

    #step2
    d_1_inv = inv(int_hex(d_1), int_hex(n))
    T_1 = mul_ECC(C1, d_1_inv)
    client_socket.sendall(T_1[0].encode())
    time.sleep(2)
    client_socket.sendall(T_1[1].encode())

    #step3
    x = client_socket.recv(2048).decode()
    y = client_socket.recv(2048).decode()
    T_2 = (x, y)

    #step4
    y_inv = hex(-int_hex(C1[1]))[3:]
    C1_inv = (C1[0], y_inv)
    x_2, y_2 = add_ECC(T_2, C1_inv)

    klen = 132
    t = KDF(x_2 + y_2, klen)

    M__ = hex(int_hex(C2) ^ int_hex(t))[2:]

    tmp = x_2 + M__ + y_2
    u = sm3_hash(tmp)
    print(f'M: {M__}')

    client_socket.close()
    server_socket.close()