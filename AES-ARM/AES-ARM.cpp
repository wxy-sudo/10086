#include <iostream>
#include <cstring>
#include <chrono>
#include <stdint.h>
#include <arm_neon.h>

void aes128_key_expand_armv8(const uint8_t key[16], uint32_t rk[44]) {

    // Load key
    uint8x16_t key128 = vld1q_u8(key);

    // Use vreinterpretq_u32_u8 to convert uint8x16_t to uint32x4_t
    uint32x4_t key0 = vreinterpretq_u32_u8(key128);

    // Round constants
    const uint8_t RC[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    // Key schedule
    uint32x4_t temp;
    for (int i = 0; i < 10; i++) {
        temp = key0;

        // RotWord
        temp = vextq_u32(temp, temp, 3);

        // SubWord
        temp = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(temp), vreinterpretq_u8_u32(vld1q_u32((const uint32_t*)&aes_sbox[0]))));

        // XOR with round constant
        temp = veorq_u32(temp, vdupq_n_u32((uint32_t)RC[i] << 24));

        // XOR with previous round key
        temp = veorq_u32(temp, key0);

        rk[i] = vgetq_lane_u32(temp, 0);
        rk[i + 1] = vgetq_lane_u32(temp, 1);
        rk[i + 2] = vgetq_lane_u32(temp, 2);
        rk[i + 3] = vgetq_lane_u32(temp, 3);

        key0 = temp;
    }
}

void aes_enc(const uint8_t in[16], uint8_t out[16], const uint32_t rk[44]) {
    
    // Load input block
    uint8x16_t block = vld1q_u8(in);

    // Round keys
    uint8_t* p8 = (uint8_t*)rk;

    // AddRoundKey
    block = veorq_u8(block, vld1q_u8(p8 + 16 * 0));

    // Round 1-9
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 1)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 2)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 3)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 4)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 5)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 6)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 7)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 8)));
    block = vaesmcq_u8(vaeseq_u8(block, vld1q_u8(p8 + 16 * 9)));

    // Final round
    block = veorq_u8(block, vld1q_u8(p8 + 16 * 10));

    // Store output block
    vst1q_u8(ou, block);
}



int main() {
    unsigned char key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char in[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char output[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    unsigned char plaintext[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint32_t rk[44];
    //aes_encrypt(in, key, output);
    aes128_key_expand_armv8(key, rk);
    aes_enc(in, output, rk);
    return 0;
}