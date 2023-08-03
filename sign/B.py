import sys
import struct
import random
from math import gcd, ceil, floor
from gmssl import sm3
import socket
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


#参数设定
q = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
x_G = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
y_G = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
G = (x_G, y_G)
n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
#私钥
d_A = hex(random.randint(pow(2, 127), pow(2, 128)))[2:]
P_A = mul_ECC(G, int_hex(d_A))
v = 256

if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8000)

    print('Connecting to Alice...')

    try:
        client_socket.connect(server_address)
        print('Connect to Alice successfully!')
    except Exception:
        print('Failed to connect to Alice!')
        sys.exit()

    #step1
    x = client_socket.recv(2048).decode()
    y = client_socket.recv(2048).decode()
    P_1 = (x, y)
    print(f'P_1: {P_1}')

    #step2
    d_2 = random.randint(1, int_hex(n) - 1)
    d_2_inv = inv(d_2, int_hex(n))
    P = mul_ECC(P_1, d_2_inv)

    y_G_inv = hex(-int_hex(y_G))[3:]
    G_inv = (x_G, y_G_inv)
    P = add_ECC(P, G_inv)
    print(f'P: {P}')

    #step3
    x = client_socket.recv(2048).decode()
    y = client_socket.recv(2048).decode()
    e = client_socket.recv(2048).decode()
    Q_1 = (x, y)
    print(f'Q_1, e: {Q_1, e}')

    #step4
    k_2 = random.randint(1, int_hex(n) - 1)
    k_3 = random.randint(1, int_hex(n) - 1)

    Q_2 = mul_ECC(G, k_2)
    tmp = mul_ECC(Q_1, k_3)
    x_1, y_1 = add_ECC(tmp, Q_2)

    r = (int_hex(x_1) + int_hex(e)) % int_hex(n)
    s_2 = (d_2 * k_3) % int_hex(n)
    s_3 = (d_2 * (r + k_2)) % int_hex(n)

    r = hex(r)[2:]
    s_2 = hex(s_2)[2:]
    s_3 = hex(s_3)[2:]

    client_socket.sendall(r.encode())
    time.sleep(2)
    client_socket.sendall(s_2.encode())
    time.sleep(2)
    client_socket.sendall(s_3.encode())
    print(f'r, s_2, s_3: {r,s_2,s_3}')

    #step5...

    client_socket.close()