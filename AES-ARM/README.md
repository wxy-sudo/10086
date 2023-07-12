# AES impl with ARM instruction

## 实现思路

- ``aes128_key_expand_armv8``用于对主密钥进行扩展，生成各轮的轮密钥
- ``aes_enc``通过已知的明文和轮密钥生成相应的轮密钥

## 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project8/AES-ARM.png)
