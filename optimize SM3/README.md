# do your best to optimize SM3 implementation (software)

这里我主要通过SIMD指令对SM3的压缩函数进行了优化，同时调用了OpenMD库对sm3的压缩函数进行了并行计算，进一步提高了SM3的速度。

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
#pragma once
#include <stdint.h>
#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <emmintrin.h>
#include <immintrin.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include<string.h>
#include<omp.h>
#define sm3_digest_BYTES 32
#define sm3_block_BYTES 64
#define sm3_hmac_BYTES sm3_digest_BYTES

typedef struct sm3_ctx_t_simd {
	uint32_t digest[sm3_digest_BYTES / sizeof(uint32_t)];
	int nblocks;
	uint8_t block[sm3_block_BYTES * 4];
	int num;
}sm3_ctx_simd;

void sm3_init_simd(sm3_ctx_simd* ctx);
void sm3_update_simd(sm3_ctx_simd* ctx, const uint8_t* data, size_t data_len);
void sm3_final_simd(sm3_ctx_simd* ctx, uint8_t* digest);

int sm3_hash_simd(uint8_t* dgst, const uint8_t* msg, size_t len);
int sm3_hash_verify_simd(const uint8_t* data, size_t dlen, const uint8_t* digest);

void sm3_init_simd(sm3_ctx_simd* ctx) {
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x49148289;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}


#define rol(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  rol((x),9)  ^ rol((x),17))
#define P1(x) ((x) ^  rol((x),15) ^ rol((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


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

void sm3_update_simd(sm3_ctx_simd* ctx, const uint8_t* data, size_t dlen) {
	if (ctx->num) {
		unsigned int left = sm3_block_BYTES - ctx->num;
		if (dlen < left) {
			memcpy(ctx->block + ctx->num, data, dlen);
			ctx->num += dlen;
			return;
		}
		else {
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress_simd(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			dlen -= left;
		}
	}
	while (dlen >= sm3_block_BYTES) {
		sm3_compress_simd(ctx->digest, data);
		ctx->nblocks++;
		data += sm3_block_BYTES;
		dlen -= sm3_block_BYTES;
	}
	ctx->num = dlen;
	if (dlen) {
		memcpy(ctx->block, data, dlen);
	}
}

void sm3_final_simd(sm3_ctx_simd* ctx, uint8_t* digest) {
	size_t i;
	uint32_t* pdigest = (uint32_t*)(digest);
	uint64_t* count = (uint64_t*)(ctx->block + sm3_block_BYTES - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= sm3_block_BYTES) {
		memset(ctx->block + ctx->num + 1, 0, sm3_block_BYTES - ctx->num - 9);
	}
	else {
		memset(ctx->block + ctx->num + 1, 0, sm3_block_BYTES - ctx->num - 1);
		sm3_compress_simd(ctx->digest, ctx->block);
		memset(ctx->block, 0, sm3_block_BYTES - 8);
	}

	count[0] = (uint64_t)(ctx->nblocks) * 512 + (ctx->num << 3);
	count[0] = _byteswap_uint64(count[0]);

	sm3_compress_simd(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest) / sizeof(ctx->digest[0]); i++) {
		pdigest[i] = _byteswap_ulong(ctx->digest[i]);
	}
}


int sm3_hash_simd(uint8_t* dgst, const uint8_t* msg, size_t len) {
	sm3_ctx_simd* md = new sm3_ctx_simd;

	//sm3_ctx* mdctx sm3_init();
	//if (!md) goto done;
	sm3_init_simd(md);
	sm3_update_simd(md, msg, len);
	sm3_final_simd(md, dgst);
	return 0;
}

int sm3_hash_verify_simd(const uint8_t* msg, size_t len, const uint8_t* dgst) {
	uint8_t buf[32];
	sm3_hash_simd(buf, msg, len);
	return memcmp(buf, dgst, 32);
}
```

最终优化结果如图

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project4/%E4%BC%98%E5%8C%96SM3.png)

加速了接近25%，同时经过检验，该优化保证了SM3的结果正确
