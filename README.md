# Cryptography

成员：王鑫阳

学号：202100150054

## 项目列表

<div align="center">

| 项目号  | 项目名称| 对应文件夹 |
| ---------- | -----------|-----------|
| 1   | implement the naïve birthday attack of reduced SM3   | [sm3_birthdayAttack](https://github.com/wxy-sudo/wxy-s/tree/main/sm3_birthdayAttack) |
| 2   | implement the Rho method of reduced SM3   | [sm3_rho_method](https://github.com/wxy-sudo/wxy-s/tree/main/sm3_rho_method) |
| 3   | implement length extension attack for SM3, SHA256, etc.   | [sm3_lengthExtensionAttack](https://github.com/wxy-sudo/wxy-s/tree/main/sm3_lengthExtensionAttack) |
| 4   | do your best to optimize SM3 implementation (software)   | [optimize SM3](https://github.com/wxy-sudo/wxy-s/tree/main/optimize%20SM3) |
| 5   | Merkle Tree   | [Merkle Tree](https://github.com/wxy-sudo/wxy-s/tree/main/Merkle%20Tree) |
| 8   | AES impl with ARM instruction   | [AES-ARM](https://github.com/wxy-sudo/wxy-s/tree/main/AES-ARM) |
| 9   | AES、SM4 implementation   | [AES、SM4 implementation](https://github.com/wxy-sudo/wxy-s/tree/main/AES%E3%80%81SM4%20implementation) |
| 10   | report on the application of this deduce technique in Ethereum with ECDSA   | [deduce technique in Ethereum with ECDSA](https://github.com/wxy-sudo/wxy-s/blob/main/deduce%20technique%20in%20Ethereum%20with%20ECDSA/README.md) |
| 11   | impl sm2 with RFC6979   | [impl sm2 with RFC6979](https://github.com/wxy-sudo/wxy-s/tree/main/impl%20sm2%20with%20RFC6979) |
| 12   | verify the above pitfalls with proof-of-concept code   | [pitfalls](https://github.com/wxy-sudo/wxy-s/tree/main/pitfalls) |
| 13   | Implement the above ECMH scheme   | [ECMH](https://github.com/wxy-sudo/wxy-s/tree/main/ECMH) |
| 14   | Implement a PGP scheme with SM2   | [SM2_PGP](https://github.com/wxy-sudo/wxy-s/tree/main/SM2_PGP) |
| 19   | forge a signature to pretend that you are Satoshi   | [forge_Satoshi](https://github.com/wxy-sudo/wxy-s/tree/main/forge%20Satoshi) |
| 22   | research report on MPT   | [MPT report](https://github.com/wxy-sudo/wxy-s/blob/main/MPT%20report/README.md) |
| 额外   | 信安赛项目(基于格的多关键字模糊可搜索加密)   | [信安赛项目](https://github.com/wxy-sudo/wxy-s/tree/main/%E4%BF%A1%E5%AE%89%E8%B5%9B%E9%A1%B9%E7%9B%AE)|

</div>

## Project1: implement the naïve birthday attack of reduced SM3

### 实现思路

#### 生日攻击

举个例子：当老师问一个有30名学生的班级（n = 30）每个人的生日在哪一天（为简便，此处省略闰年）以确定是否有两个学生同一天生日（对应碰撞 ）。从直觉角度考虑，几率看起来很小。若老师选择特定日期（例如9月16日），则至少有一名学生在那天出生的概率是
1−(364/365)^{30}，约为7.9%。但是，与我们的直觉相反的是，至少一名学生和另外任意一名学生有着相同生日的概率大约为70.63%（n = 30时）

定义一字典 D，其键值表示某一消息的哈希值，内容是原始消息。依次对不同消息计算哈希值，然后判断哈希值在字典中是否已经存在，若存在，则输出当前消息以及字典中的哈希值所对应的消息，否则将该哈希值与消息本身存入字典中，继续计算。该算法的时间复杂度和空间复杂度均为 $O(2^{\frac{n}{2}})$。

### 实现结果

针对 *32* 位简化 SM3 算法的生日攻击

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project1/32bit.png)

针对 *48* 位简化 SM3 算法的生日攻击

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project1/48bit.png)

## Project2: implement the Rho method of reduced SM3

### 实现思路

考虑数列 $\lbrace H_n\rbrace$，其中 $H_0=seed,\ H_{n+1}=hash(H_n)$，易知该数列最终一定会进入一个循环，且数列进入循环前的最后一个值与该循环周期的最后一个值能够发生碰撞。设此循环的周期为 $\rho$，求出该 $\rho$ 的值，然后，令变量 $i$ 和 $j$ 分别从 $H_0$ 和 $H_\rho$ 出发同步迭代，并逐次比较 $i$ 和 $j$ 的值，当判断出二者第一次相等时，即找到了碰撞发生的位置。其中，求 $\rho$ 值可通过如下算法实现：

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/huan.png)

采用 $Rho$  $method$对 $SM3$寻找碰撞，我们先选取一个随机的 $seed$作为起始值，随后每次分别对消息进行一次 $SM3$和两次 $SM3$，直到找出一组碰撞

```cpp
    EVP_Digest(data, 32, out1, &out1_size, EVP_sm3(), NULL);
    EVP_Digest(out1, 32, out2, &out2_size, EVP_sm3(), NULL);
    while(1) {
        EVP_Digest(out1, 32, out3, &out1_size, EVP_sm3(), NULL);
        EVP_Digest(out2, 32, out2, &out2_size, EVP_sm3(), NULL);
        EVP_Digest(out2, 32, out4, &out2_size, EVP_sm3(), NULL);
        uint32_t key1 = 0;
        std::memcpy(&key1, out3, COLLISION_BYTE);
        

        uint32_t key2 = 0;
        std::memcpy(&key2, out4, COLLISION_BYTE);

        if (key1 == key2) {
            printf("找到碰撞！！！\n");
            printf("第一段消息为：");
            printf_hex(out1, 32);
            printf("\n");
            printf("第一段消息哈希值为：");
            printf_hex(out3, 32);
            printf("\n");

            printf("第二段消息为：");
            printf_hex(out2, 32);
            printf("\n");
            printf("第二段消息哈希值为：");
            printf_hex(out4, 32);
            printf("\n");
            break;

        }
```

优化思路：令变量 $i$ 在数列中迭代：第一轮迭代 $1$ 次得到 $H_1$，将其与 $H_0$ 比较；第二轮迭代 $2$ 次得到 $H_2$ 和 $H_3$，依次与 $H_1$ 比较；第三轮迭代 $4$ 次得到 $H_4$, $H_5$, $H_6$ 和 $H_7$，依次与 $H_3$ 比较……如是重复，每轮迭代 $2^{n-1}$ 次，并依次与上一轮最后一次迭代得到的值比较，直到比较出相同为止，此时 $i$ 在当前轮中迭代的次数即为 $\rho$. 经测试，该算法比原始 Rho Method 通过两变量一快一慢遍历数列求 $\rho$ 值的效率更高，用该算法最终找到一组碰撞的平均总耗时约能达到原方法的 $0.6$ 倍。

### 实现结果

#### 24bit

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/24bit.png)

#### 48bit

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/48bit.png)

## Project3: implement length extension attack for SM3, SHA256, etc.

### 实现思路

这里实现MAC的密钥我们每次选取随机值，因此首先生成随机数生成器

```cpp
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> dis(0, 255);
```

随后生成随机的密钥

```cpp
uint8_t* key = new uint8_t[64];
for (int i = 0; i < 64; i++) {
  key[i] = static_cast<uint8_t>(dis(gen));
}
```

接着利用已知的key和message实现MAC

```cpp
sm3_update(&sig_ctx, key, 64, data, times);
sig_ctx.nblocks = 0;
sm3_update(&sig_ctx, message, sizeof(message)-1, data, times);
sm3_final(&sig_ctx, digest, data, times);
```

接着对扩展的消息再执行一次MAC计算，并且由于上一次填充了足够的消息，SM3压缩的缓冲区内此时为空，因此将ctx.num设为0

```cpp
uint8_t appended_message[] = "appended! ";
sig_ctx.num = 0;
sig_ctx.nblocks += 1;
sm3_update(&sig_ctx, appended_message, sizeof(appended_message)-1, data, times);
sm3_final(&sig_ctx, digest, data, times);
```

接着对长度扩展后的消息直接进行MAC，与长度扩展攻击得到的MAC进行比较

```cpp
sm3_ctx sig_ctx1;
sm3_init(&sig_ctx1);
sm3_update(&sig_ctx1, pdata, 128 + sizeof(appended_message)-1, message, times);
sig_ctx1.nblocks -= 1; //key不能算在nblocks中，所以要减1
sm3_final(&sig_ctx1, digest2, message, times);
```

### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project3/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6%94%BB%E5%87%BB.png)

经过比较发现，长度扩展攻击获得的MAC和直接对消息进行MAC的值一致，因此长度扩展攻击成功！

## Project4: do your best to optimize SM3 implementation (software)

这里我主要通过 $SIMD$指令对 $SM3$的压缩函数进行了优化，同时调用了 $OpenMD$库对 $sm3$的压缩函数进行了并行计算，进一步提高了 $SM3$的速度。

```cpp
static void sm3_compress(uint32_t digest[sm3_digest_BYTES / sizeof(uint32_t)], const uint8_t block[sm3_block_BYTES]) {
	int j;
	uint32_t W[68], W1[64];
	const uint32_t* pblock = (const uint32_t*)(block);

	uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3];
	uint32_t E = digest[4], F = digest[5], G = digest[6], H = digest[7];

	uint32_t SS1, SS2, TT1, TT2, T[64];

	for (j = 0; j < 16; j++) W[j] = _byteswap_ulong(pblock[j]);

	for (j = 16; j < 68; j++) {
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ rol(W[j - 3], 15)) ^ rol(W[j - 13], 7) ^ W[j - 6];
	}

	for (j = 0; j < 64; j++)W1[j] = W[j] ^ W[j + 4];

	for (j = 0; j < 16; j++) {
		T[j] = 0x79CC4519;
		SS1 = rol((rol(A, 12) + E + rol(T[j], j)), 7);
		SS2 = SS1 ^ rol(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C, C = rol(B, 9), B = A, A = TT1;
		H = G, G = rol(F, 19), F = E, E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {
		T[j] = 0x7A879D8A;
		SS1 = rol((rol(A, 12) + E + rol(T[j], j)), 7);
		SS2 = SS1 ^ rol(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C, C = rol(B, 9), B = A, A = TT1;
		H = G, G = rol(F, 19), F = E, E = P0(TT2);
	}

	digest[0] ^= A, digest[1] ^= B, digest[2] ^= C, digest[3] ^= D;
	digest[4] ^= E, digest[5] ^= F, digest[6] ^= G, digest[7] ^= H;
}
```

我将上述代码改成
```cpp
void sm3_compress_simd(uint32_t digest[8], const unsigned char block[64])
{

	int j;
	uint32_t W[68], W1[64];
	const uint32_t* pblock = (const uint32_t*)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1, SS2, TT1, TT2, T[64];


	for (j = 0; j < 16; j++) W[j] = _byteswap_ulong(pblock[j]);
	
#pragma omp parallel for
	for (j = 0; j < 6; j++) {
		W[16 + 8 * j] = P1(W[16 + 8 * j - 16] ^ W[16 + 8 * j - 9] ^ rol(W[16 + 8 * j - 3], 15)) ^ rol(W[16 + 8 * j - 13], 7) ^ W[16 + 8 * j - 6];
		W[17 + 8 * j] = P1(W[17 + 8 * j - 16] ^ W[17 + 8 * j - 9] ^ rol(W[17 + 8 * j - 3], 15)) ^ rol(W[17 + 8 * j - 13], 7) ^ W[17 + 8 * j - 6];
		W[18 + 8 * j] = P1(W[18 + 8 * j - 16] ^ W[18 + 8 * j - 9] ^ rol(W[18 + 8 * j - 3], 15)) ^ rol(W[18 + 8 * j - 13], 7) ^ W[18 + 8 * j - 6];
		W[19 + 8 * j] = P1(W[19 + 8 * j - 16] ^ W[19 + 8 * j - 9] ^ rol(W[19 + 8 * j - 3], 15)) ^ rol(W[19 + 8 * j - 13], 7) ^ W[19 + 8 * j - 6];
		W[20 + 8 * j] = P1(W[20 + 8 * j - 16] ^ W[20 + 8 * j - 9] ^ rol(W[20 + 8 * j - 3], 15)) ^ rol(W[20 + 8 * j - 13], 7) ^ W[20 + 8 * j - 6];
		W[21 + 8 * j] = P1(W[21 + 8 * j - 16] ^ W[21 + 8 * j - 9] ^ rol(W[21 + 8 * j - 3], 15)) ^ rol(W[21 + 8 * j - 13], 7) ^ W[21 + 8 * j - 6];
		W[22 + 8 * j] = P1(W[22 + 8 * j - 16] ^ W[22 + 8 * j - 9] ^ rol(W[22 + 8 * j - 3], 15)) ^ rol(W[22 + 8 * j - 13], 7) ^ W[22 + 8 * j - 6];
		W[23 + 8 * j] = P1(W[23 + 8 * j - 16] ^ W[23 + 8 * j - 9] ^ rol(W[23 + 8 * j - 3], 15)) ^ rol(W[23 + 8 * j - 13], 7) ^ W[23 + 8 * j - 6];
	}
#pragma omp parallel for
	for (j = 64; j < 68; j++) {
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ rol(W[j - 3], 15)) ^ rol(W[j - 13], 7) ^ W[j - 6];
	}
	

	for (j = 0; j < 2; j++) {
		__m256i a1 = _mm256_loadu_epi32(&W[0 + 32 * j]);
		__m256i a2 = _mm256_loadu_epi32(&W[8 + 32 * j]);
		__m256i a3 = _mm256_loadu_epi32(&W[16 + 32 * j]);
		__m256i a4 = _mm256_loadu_epi32(&W[24 + 32 * j]);

		__m256i b1 = _mm256_loadu_epi32(&W[4 + 32 * j]);
		__m256i b2 = _mm256_loadu_epi32(&W[12 + 32 * j]);
		__m256i b3 = _mm256_loadu_epi32(&W[20 + 32 * j]);
		__m256i b4 = _mm256_loadu_epi32(&W[28 + 32 * j]);

		__m256i c1 = _mm256_xor_si256(a1, b1);
		__m256i c2 = _mm256_xor_si256(a2, b2);
		__m256i c3 = _mm256_xor_si256(a3, b3);
		__m256i c4 = _mm256_xor_si256(a4, b4);

		_mm256_storeu_epi32(&W1[0 + 32 * j], c1);
		_mm256_storeu_epi32(&W1[8 + 32 * j], c2);
		_mm256_storeu_epi32(&W1[16 + 32 * j], c3);
		_mm256_storeu_epi32(&W1[24 + 32 * j], c4);
	}

	for (j = 0; j < 16; j++) {
		SS1 = rol((rol(A, 12) + E + rol(0x79CC4519, j)), 7);
		SS2 = SS1 ^ rol(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = rol(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rol(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {
		SS1 = rol((rol(A, 12) + E + rol(0x7A879D8A, j)), 7);
		SS2 = SS1 ^ rol(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = rol(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rol(F, 19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;

}
```

最终优化结果如图

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project4/%E4%BC%98%E5%8C%96SM3.png)

加速了接近35%，同时经过检验，该优化保证了SM3的结果正确

## Project5: Impl Merkle Tree following RFC6962

### 实现思路

哈希树中，哈希值的求取通常使用诸如SHA-2的加密哈希函数，但如果只是用于防止非故意的数据破坏，也可以使用不安全的校验和获取，比如CRC。

哈希树的顶部为顶部哈希（top hash），亦称根哈希（root hash）或主哈希（master hash）。以从 P2P 网络下载文件为例：通常先从可信的来源获取顶部哈希，如朋友告知、网站分享等。得到顶部哈希后，则整棵哈希树就可以通过 P2P 网络中的非受信来源获取。下载得到哈希树后，即可根据可信的顶部哈希对其进行校验，验证数据是否完整、是否遭受破坏。

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project5/Merkle%20Tree%20tu.png)

创建 `MerkleTree` 类，通过递归实现其创建和遍历，验证某一元素是否存在时，先通过遍历找到其对应的叶子节点，若未找到则证明不存在，否则依次验证该叶子节点每个父节点是否正确，如果全部正确则证明存在，否则返回异常。

### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project5/Merkle%20Tree.png)

## Project8: AES impl with ARM instruction

### 实现思路

- ``aes128_key_expand_armv8``用于对主密钥进行扩展，生成各轮的轮密钥
- ``aes_enc``通过已知的明文和轮密钥生成相应的轮密钥

### 实现结果

由于电脑并非arm架构，因而并没有得到该代码的运行结果，这里仅给出实现的代码。

## Project9: AES / SM4 software implementation

### 实现思路

利用构建查找表的方法加速AES与SM4的运行速度，原理见下图：

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project9/1.png)

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project9/2.png)

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project9/3.png)

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project9/4.png)

通过构建一个 $T$盒，我们可以减少行移位等操作的运算次数，从而实现对 $AES$/ $SM4$的优化。

### 实现结果

#### AES

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project9/AES.png)

#### SM4

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project9/SM4.png)

## Project10: report on the application of this deduce technique in Ethereum with ECDSA

### ECDSA

#### $KeyGen$:
- $P=d G, n$ is order

#### $Sign(\mathrm{M})$ :
- ${Sign}(m)$
- $k \leftarrow Z_n^*, R=k G$
- $r=R_x \bmod n, r \neq 0$
- $e={hash}(m)$
- $s=k^{-1}(e+d r) \bmod n$

#### $Verify(\mathrm{r,s})$ of m with P :
- $e={hash}(m)$
- $w=s^{-1} \bmod n$
- $\left(r^{\prime}, s^{\prime}\right)=e \cdot w G+r \cdot w P$
- Check if $r^{\prime}==r$
- Holds for correct sig since
- $e s^{-1} G+r s^{-1} P=s^{-1}(e G+r P)=$
- $k(e+d r)^{-1}(e+d r) G=k G=R$


### Public Key Recovery

- $e s^{-1} G+r s^{-1} P=s^{-1}(e G+r P)$
- $P=dG=(R-e s^{-1})s r^{-1}$
  
How to compute $P$

- $e={hash}(m)$
- $s=k^{-1}(e+d r) \bmod n$

在使用Ethereum的过程中，每次需要使用ECDSA进行签名时，发送方可以不必向验证方发送自己的公钥，而是由验证方根据消息等已知信息自行求出发送方的公钥

通过这种方法，可以减少发送方发送公钥消耗的带宽，增加传输效率

little tips：由于验证方仅可获得r，也就是R的横坐标，而一个横坐标可以对应两个纵坐标，同时根据这两个纵坐标，每个纵坐标可以恢复出两个P的横坐标，最终至多可以获得4个公钥，而其中有且仅有一个公钥是发送方真正使用的公钥，因此发送方可能需要通过添加冗余信息的方法使验证方能够判断出哪个是正确的公钥。

## Project11: impl sm2 with RFC6979

### SM2_Sign

#### 实现思路

先定义椭圆曲线上的加法和点乘运算

```python3
def add(x1, y1, x2, y2):
    if x1 == x2 and y1 == p - y2:
        return False
    lamda = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p if x1 != x2 else ((3 * x1 * x1 + a) * pow(2 * y1, p - 2, p)) % p
    x3 = (lamda * lamda - x1 - x2) % p
    y3 = (lamda * (x1 - x3) - y1) % p
    return x3, y3
```

```python3
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

```python3
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

```python3
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

```python3
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

#### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project11/sm2_sign.png)

### SM2_Enc

#### 实现思路

同样先实现椭圆曲线上的加法与点乘运算

```python3
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

```python3
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

```python3
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

```python3
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

#### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project11/sm2_enc.png)

## Project13: Implement the above ECMH scheme

### 实现思路

 $ECMH$的基本要求：
- 同态或递增的多集散列函数
-  $hash({a}) + hash({b}) = hash({a,b})$
- 一个空集映射到EC的无穷大点O
- 多集合中元素的顺序并不重要
- 重复的元素是可能的，{a}和{a，a}有不同的摘要。
- 要更新一个多集的摘要，只需要计算差值。
- 可以在任何椭圆曲线上构建
- 抗碰撞性依赖于ECDLP的困难程度
- 与SM2/ECDSA签名/验证的安全假设相同
- 收益：快速的节点同步，不需要从头做起



- ``ech``函数对单独的消息m进行哈希
```python3
def ech(u):
    h = int(hashlib.sha256(str(u).encode()).hexdigest(), 16)
    for i in range(0, p):
        x = (h + i) % p
        d = (x ** 3 + a * x + b) % p
        if pow(d, (p - 1) // 2, p) % p == 1:
            y = modular_sqrt(d, p)
            return [x, y]
    return None
```

- ``echs``函数则对一个集合中的消息m进行哈希后，将他们以椭圆曲线加法加在一起
```python3
def echs(s):
    for x in s:
        point = ech(x)
        if point is not None:
            result[0],result[1] = add(result[0],result[1],point[0],point[1])
    return result
```

### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project13/ECMH.png)

## Project14: Implement a PGP scheme with SM2

### 实现思路

```
    newData_sm3=sm3.sm3_hash(func.bytes_to_list(newData)).encode()
    print('SM3 Hash结果:')
    print(newData_sm3)
```

对消息进行哈希

```
    sign_sm3=sm2_crypt_A.sign(newData_sm3, random_hex_str)
    print('SM2签名结果:')
    print(sign_sm3)
```

进行SM2签名

```
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_ecb(tmp_sm4)  # bytes类型
    print('SM4加密结果:')
    print(encrypt_value)

    sm2_crypt_B = sm2.CryptSM2(public_key=pk_B, private_key=None)
    enc_data = sm2_crypt_B.encrypt(key)
    print('SM2加密结果:')
    print(enc_data)
```

进行加密

## Project19: forge a signature to pretend that you are Satoshi

### 实现思路

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project19/%E5%AE%9E%E7%8E%B0%E6%80%9D%E8%B7%AF.png)

### 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project19/forge%20Satoshi.png)

## Project22: research report on MPT

### 实现结果

见[MPT report](https://github.com/wxy-sudo/wxy-s/blob/main/MPT%20report/README.md)

## 基于格的多关键字模糊可搜索加密

### 实现思路

随着当下云存储技术的不断发展, 越来越多的用户选择将隐私数据存储至云服务器, 结合可搜索加密技术, 用户能够随时随地检索密文数据。考虑到云端存储的密文数据总量 在持续增长, 而目前的公钥可搜索加密方案大多是基于双线性对构建的, 其计算开销大, 过长的检索耗时将会影响用户体验。与此同时, 随着量子计算机研制技术的不断突破, 攻击者可以利用量子计算机攻破目前大多数 PEKS 安全体制, 从而窃取用户的隐私数据。
由此可见, 传统 PEKS 方案面临着通讯及时性和密文安全性的双重考验, 因而, 构建 出安全高效的公钥可搜索加密方案已成为当前密码学领域的研究热点。

为了在云环境下 安全高效地检索密文数据, 本文首先基于容错学习 (Learning with Error,LWE) 的环变体和小整数解问题 (Small Integer Solutions,SIS) 的环变体, 构造了格上安全的公钥可搜索加密 (Public-key Encryption with Conjunctive Keyword Search,PEKS) 方案, 随后给出了此方案的 计算一致性及 IND-CPA-secure 安全性证明。我们使用基于 Ring-SIS/LWE 困难性的 IBE 来构建 PEKS, 相比基于双线性对构建的 PECKS 方案, 本文提出的方案能够抵抗量子 计算机攻击, 并且能保证更高的检索效率。

同时, 我们创新性地提出了一种面向多关键字的生成安全索引的方案。该方案实施的 基础为布隆过滤器, 随后利用对偶编码函数以及位置敏感 Hash 函数 (LSH) 构建文件对应 的文件索引, 在生成安全索引后使用距离可恢复加密算法对该安全索引进行加密操作, 从 而实现了针对于多关键字的密文模糊搜索。除此之外, 此方案不需要提前为安全索引创建 存储空间, 因此该搜索方案的复杂度得到了很大程度上的降低。并且, 该面向多关键字的 模糊密文搜索方案与现有方案相比较不需要提前定义字典库, 从而减小了存储上锁花费 的开销。

最后在本文中, 我们对该模糊搜索方案进行了安全性分析, 证明该方案不仅能够实现面向多关键字的密文模糊搜索, 而且保证了方案的机密性、隐私性和完整性。
在生成安全索引后, 我们将上述生成安全索引方案与基于格的 PEKS 方案相关联, 提出基于格的面向多关键字的模糊密文搜索方案。将安全索引作为 “邮递员”, 经过哈希变换后压缩为基于格的 PEKS 方案中的输人 id 。由于上述方案全部在文件搜索前便可完成, 即在发送时便进行上述操作。而搜索过程在接收方空闲时选择接收时才会按照用户需求 进行, 保证了各过程的独立性。最终我们将我们的方案与现有的 PEKS 方案进行了效率对 比。结果显示, 我们的实现具有很好的效率。并且, 当安全参数提高时, 整体运行的时间 几乎只是成比例地增长, 而不会带来额外的性能浪费, 具有较高的扩展性。

### 空间效率对比分析

为了做进一步评估，我们将本文中的实现与一些其它的PEKS方案进行了效率对比。我们分别对于四种不同的方案在同一环境下进行了测试，分别为：

    BOYa--Behnia等人使用了NTRU格的PEKS算法，空间需求较小
    
    BOYb--Behnia等人使用了NTRU格的PEKS算法，空间需求较小
    
    ZXW--Zhang,X.基于IIOT技术使用了LWE问题的PEKS算法，基于身份加密
    
    LTT——Liu,Z.Y.使用了LWE问题的公钥认证加密算法，具备抗量子能力以及更高的安全性


在对应方案的默认安全参数下，得到的空间储存需求对比见下图：

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/%E4%BF%A1%E5%AE%89%E8%B5%9B/%E7%A9%BA%E9%97%B4%E5%AF%B9%E6%AF%94.png)

BOYa方案有一个主要的存储优势，它基于NTRU，需要很小的存储开销。与我们的方案相比，我们的方案具有更小的私钥大小。与基于LWE的方案相比，我们的方案在公钥、私钥和密文存储方面具有更显著的优势。

### 时间效率对比

#### Trapdoor时间对比

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/%E4%BF%A1%E5%AE%89%E8%B5%9B/Trapdoor%E6%97%B6%E9%97%B4%E5%AF%B9%E6%AF%94.png)

#### PEKS时间对比

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/%E4%BF%A1%E5%AE%89%E8%B5%9B/PEKS%E6%97%B6%E9%97%B4%E5%AF%B9%E6%AF%94.png)

#### Test时间对比

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/%E4%BF%A1%E5%AE%89%E8%B5%9B/Test%E6%97%B6%E9%97%B4%E5%AF%B9%E6%AF%94.png)

我们注意到，对于加密算法的计时，我们的计时比BOYa长。但是，对于每个搜索查询，Test算法对每个关键字及文件对执行一次。并且我们可以注意到，该方案在实际应用中最重要的是Test测试算法的效率，用户最在意的就是关键词集合查询时所消耗的时间。因此，测试算法的效率尤为重要，这导致了计算开销。请注意，测试时间取决于安全参数、关键字的平均长度和硬件条件。在我们的环境中，如果安全参数为80，那么我们的PEKS方案的平均测试时间为0.19ms;如果安全参数为192位，则我们的PEKS方案的平均测试时间为0.97ms。对于80位的安全性，Test算法的效率比BOYa提高了约2倍，在端到端延迟方面具有优势，适合后期进行商用的推进。




