from gmssl import sm2,sm3, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import base64

#SM4参数
key = b'wxy10086'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #  bytes类型

#SM2参数
rk_A = '0d1d31b70ef5d8d04d1d58158b2b418321a5b3dc8c68cdfe821a5e8c42d7e201'
pk_A = '36cd1616a0fdf51a57c9ac9c492d1049f8dd2579625814e1ddc9bd8d8de0b251530eced795456dc46802a5b1e1cfb7897ba39045e4619fcee3a0200e2a450ed7'
rk_B = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
pk_B = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

def SM2_PGP_enc(data):


    newData = data.encode()
    sm2_crypt_A = sm2.CryptSM2(public_key=pk_A, private_key=rk_A)
    random_hex_str = func.random_hex(sm2_crypt_A.para_len)

    newData_sm3=sm3.sm3_hash(func.bytes_to_list(newData)).encode()
    print('SM3 Hash结果:')
    print(newData_sm3)

    sign_sm3=sm2_crypt_A.sign(newData_sm3, random_hex_str)
    print('SM2签名结果:')
    print(sign_sm3)

    tmp_sm4=sign_sm3.encode()+newData

    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_ecb(tmp_sm4)  # bytes类型
    print('SM4加密结果:')
    print(encrypt_value)

    sm2_crypt_B = sm2.CryptSM2(public_key=pk_B, private_key=None)
    enc_data = sm2_crypt_B.encrypt(key)
    print('SM2加密结果:')
    print(enc_data)

    message=enc_data+encrypt_value
    print('PGP加密结果:')
    print(message)
    return message

def SM2_PGP_dec(message):
    key_enc=message[:112]
    encrypt_value=message[112:]
    sm2_crypt_B = sm2.CryptSM2(public_key=pk_B, private_key=rk_B)
    key_sm4=sm2_crypt_B.decrypt(key_enc)
    print('获取得到临时密钥:')
    print(key_sm4)
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key_sm4,SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
    sig=decrypt_value[:128]
    data=decrypt_value[128:]
    print('获得SM2签名:')
    print(sig)
    print('解得的明文:')
    print(data.decode())
    newData_sm3 = sm3.sm3_hash(func.bytes_to_list(data)).encode()
    sm2_crypt_A = sm2.CryptSM2(public_key=pk_A,private_key=None)
    verify=sm2_crypt_A.verify(sig, newData_sm3)
    print('验证结果:')
    print(verify)

print('需传递的会话密钥')
print(key)
print('明文消息:')
data='wxy10086'
print(data)
print("开始生成PGP消息")
message=SM2_PGP_enc(data)
print('\n\n\n')
print("解密验证PGP消息")
SM2_PGP_dec(message)

