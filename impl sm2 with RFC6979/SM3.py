IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
      0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
T_lst = [0x79cc4519, 0x7a879d8a]
def LShift(content,bit_num):
    bit_num=bit_num%32
    res1=(content<<bit_num)&0xffffffff
    res2=(content>>(32-bit_num))&0xffffffff
    return res1|res2
def FF(X, Y, Z, i):
    if i >= 0 and i <= 15:
            return X ^ Y ^ Z
    else:
        return ((X & Y) | (X & Z) | (Y & Z))


def GG(X, Y, Z, i):
    if i >= 0 and i <= 15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (~X & Z))


def P0(s):
    return s ^ LShift(s, 9) ^ LShift(s, 17)


def P1(s):
    return s ^ LShift(s, 15) ^ LShift(s, 23)

def T(i):
    if i>=0 and i<=15:
        return T_lst[0]
    else:
        return T_lst[1]

def Padding(message):
    #输入的参数需为整型
    m=bin(message)[2:]
    if len(m)%4!=0:
        m='0'*(4-(len(m)%4))+m
    mes_len=len(m)
    k=448-((len(m)+1)%512)
    len_pad='0'*(64-len(bin(mes_len)[2:]))+bin(mes_len)[2:]
    m=m+'1'+'0'*k+len_pad
    #m=int(m,2)
    return m

def Group(message):
    res=[]
    group_num=int(len(message)/512)
    for i in range(group_num):
        res.append(message[512*i:512*i+512])
    return res

def Expand(mes_group):
    W_0=[]
    W_1=[]
    for i in range(16):
        W_0.append(int(mes_group[32*i:32*i+32],2))

    for j in range(16,68):
        aa=W_0[j-16]
        bb=W_0[j-9]
        cc=LShift(W_0[j-3],15)
        dd=LShift(W_0[j-13],7)
        ee=P1(aa^bb^cc^dd)
        ff=ee^W_0[j-6]
        W_0.append(P1(W_0[j-16]^W_0[j-9]^LShift(W_0[j-3],15))^LShift(W_0[j-13],7)^W_0[j-6])
    for j in range(64):
        W_1.append(W_0[j]^W_0[j+4])
    #print(W_0)
    #print(W_1)
    #print(len(W_0)," ",len(W_1))
    return [W_0,W_1]

def CF(W,V):
    A,B,C,D,E,F,G,H=V
    for j in range(64):
        SS1=LShift((LShift(A,12)+E+LShift(T(j),j))%(2**32),7)
        SS2=SS1^LShift(A,12)
        TT1=(FF(A,B,C,j)+D+SS2+W[1][j])%(2**32)
        TT2=(GG(E,F,G,j)+H+SS1+W[0][j])%(2**32)
        D=C
        C=LShift(B,9)
        B=A
        A=TT1
        H=G
        G=LShift(F,19)
        F=E
        E=P0(TT2)
    return [A^V[0],B^V[1],C^V[2],D^V[3],E^V[4],F^V[5],G^V[6],H^V[7]]

def Hash(m):
    m=int(m,16)
    m_bitstr=Padding(m)
    m_group=Group(m_bitstr)
    new_V=IV
    for B in m_group:
        W=Expand(B)
        new_V=CF(W,new_V)
    res=''
    for x in new_V:
        res+='{:0>8x}'.format(x)
    return res
