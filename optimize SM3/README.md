# do your best to optimize SM3 implementation (software)

这里我主要通过SIMD指令对SM3的压缩函数进行了优化

```
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
```
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


	for (j = 0; j < 2; j++) {
		W[0 + j * 8] = cpu_to_be32(pblock[0 + j * 8]);
		W[1 + j * 8] = cpu_to_be32(pblock[1 + j * 8]);
		W[2 + j * 8] = cpu_to_be32(pblock[2 + j * 8]);
		W[3 + j * 8] = cpu_to_be32(pblock[3 + j * 8]);
		W[4 + j * 8] = cpu_to_be32(pblock[4 + j * 8]);
		W[5 + j * 8] = cpu_to_be32(pblock[5 + j * 8]);
		W[6 + j * 8] = cpu_to_be32(pblock[6 + j * 8]);
		W[7 + j * 8] = cpu_to_be32(pblock[7 + j * 8]);
	}
	for (j = 0; j < 6; j++) {
		W[16 + 8 * j] = P1(W[16 + 8 * j - 16] ^ W[16 + 8 * j - 9] ^ ROTATELEFT(W[16 + 8 * j - 3], 15)) ^ ROTATELEFT(W[16 + 8 * j - 13], 7) ^ W[16 + 8 * j - 6];
		W[17 + 8 * j] = P1(W[17 + 8 * j - 16] ^ W[17 + 8 * j - 9] ^ ROTATELEFT(W[17 + 8 * j - 3], 15)) ^ ROTATELEFT(W[17 + 8 * j - 13], 7) ^ W[17 + 8 * j - 6];
		W[18 + 8 * j] = P1(W[18 + 8 * j - 16] ^ W[18 + 8 * j - 9] ^ ROTATELEFT(W[18 + 8 * j - 3], 15)) ^ ROTATELEFT(W[18 + 8 * j - 13], 7) ^ W[18 + 8 * j - 6];
		W[19 + 8 * j] = P1(W[19 + 8 * j - 16] ^ W[19 + 8 * j - 9] ^ ROTATELEFT(W[19 + 8 * j - 3], 15)) ^ ROTATELEFT(W[19 + 8 * j - 13], 7) ^ W[19 + 8 * j - 6];
		W[20 + 8 * j] = P1(W[20 + 8 * j - 16] ^ W[20 + 8 * j - 9] ^ ROTATELEFT(W[20 + 8 * j - 3], 15)) ^ ROTATELEFT(W[20 + 8 * j - 13], 7) ^ W[20 + 8 * j - 6];
		W[21 + 8 * j] = P1(W[21 + 8 * j - 16] ^ W[21 + 8 * j - 9] ^ ROTATELEFT(W[21 + 8 * j - 3], 15)) ^ ROTATELEFT(W[21 + 8 * j - 13], 7) ^ W[21 + 8 * j - 6];
		W[22 + 8 * j] = P1(W[22 + 8 * j - 16] ^ W[22 + 8 * j - 9] ^ ROTATELEFT(W[22 + 8 * j - 3], 15)) ^ ROTATELEFT(W[22 + 8 * j - 13], 7) ^ W[22 + 8 * j - 6];
		W[23 + 8 * j] = P1(W[23 + 8 * j - 16] ^ W[23 + 8 * j - 9] ^ ROTATELEFT(W[23 + 8 * j - 3], 15)) ^ ROTATELEFT(W[23 + 8 * j - 13], 7) ^ W[23 + 8 * j - 6];
	}

	W[64] = P1(W[48] ^ W[55] ^ ROTATELEFT(W[61], 15)) ^ ROTATELEFT(W[51], 7) ^ W[58];
	W[65] = P1(W[49] ^ W[56] ^ ROTATELEFT(W[62], 15)) ^ ROTATELEFT(W[52], 7) ^ W[59];
	W[66] = P1(W[50] ^ W[57] ^ ROTATELEFT(W[63], 15)) ^ ROTATELEFT(W[53], 7) ^ W[60];
	W[67] = P1(W[51] ^ W[58] ^ ROTATELEFT(W[64], 15)) ^ ROTATELEFT(W[54], 7) ^ W[61];

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
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(0x79CC4519, j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {
		SS1 = ROTATELEFT((ROTATELEFT(A, 12) + E + ROTATELEFT(0x7A879D8A, j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F, 19);
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

加速了接近25%，同时经过检验，该优化保证了SM3的结果正确
