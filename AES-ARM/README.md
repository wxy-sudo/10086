# AES impl with ARM instruction

## 实现思路

- ``aes128_key_expand_armv8``用于对主密钥进行扩展，生成各轮的轮密钥
- ``aes_enc``通过已知的明文和轮密钥生成相应的轮密钥

## 实现结果

由于电脑并非arm架构，因而并没有得到该代码的运行结果，这里仅给出实现的代码。
