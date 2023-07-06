#include <iostream>
#include <cstring>
#include <chrono>
using namespace std;

// T表
static const unsigned char T[256] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4,
0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6,
0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// 将4个字节转换为一个32位整数
unsigned int word(unsigned char a, unsigned char b, unsigned char c, unsigned char d) {
	return ((unsigned int)a << 24) | ((unsigned int)b << 16) | ((unsigned int)c << 8) | (unsigned int)d;
}

// 将32位整数拆分为4个字节
void split(unsigned int w, unsigned char& a, unsigned char& b, unsigned char& c, unsigned char& d) {
	a = (w & 0xff000000) >> 24;
	b = (w & 0x00ff0000) >> 16;
	c = (w & 0x0000ff00) >> 8;
	d = (w & 0x000000ff);
}

// 加密函数
void aes_encrypt(unsigned char* input, unsigned char* output, unsigned char* key) {
	unsigned int w[4];
	unsigned char state[16];
	unsigned char round_key[16];
	unsigned char temp;
    // 将输入拆分为16个字节的状态矩阵
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }

    // 将密钥拆分为4个32位整数
    for (int i = 0; i < 4; i++) {
        w[i] = word(key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]);
    }

    // 轮密钥加
    for (int i = 0; i < 16; i++) {
        state[i] ^= key[i];
    }

    // 9轮加密
    for (int round = 0; round < 9; round++) {
        // 字节替换
        for (int i = 0; i < 16; i++) {
            state[i] = T[state[i]];
        }

        // 列混淆
        for (int i = 0; i < 4; i++) {
            // 计算新列的第一个字节
            temp = state[i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i];
            round_key[i] = T[temp] ^ key[i * 4];
            // 计算新列的第二个字节
            temp = state[(i + 1) % 4] ^ state[4 + (i + 1) % 4] ^ state[8 + (i + 1) % 4] ^ state[12 + (i + 1) % 4];
            round_key[4 + i] = T[temp] ^ key[i * 4 + 1];
            // 计算新列的第三个字节
            temp = state[(i + 2) % 4] ^ state[4 + (i + 2) % 4] ^ state[8 + (i + 2) % 4] ^ state[12 + (i + 2) % 4];
            round_key[8 + i] = T[temp] ^ key[i * 4 + 2];
            // 计算新列的第四个字节
            temp = state[(i + 3) % 4] ^ state[4 + (i + 3) % 4] ^ state[8 + (i + 3) % 4] ^ state[12 + (i + 3) % 4];
            round_key[12 + i] = T[temp] ^ key[i * 4 + 3];
        }
        // 轮密钥加
        for (int i = 0; i < 16; i++) {
            state[i] ^= round_key[i];
        }
    }

    // 最后一轮加密
    // 字节替换
    for (int i = 0; i < 16; i++) {
        state[i] = T[state[i]];
    }

    // 列混淆
    for (int i = 0; i < 4; i++) {
        // 计算新列的第一个字节
        temp = state[i] ^ state[4 + i] ^ state[8 + i] ^ state[12 + i];
        round_key[i] = T[temp] ^ key[i * 4];
        // 计算新列的第二个字节
        temp = state[(i + 1) % 4] ^ state[4 + (i + 1) % 4] ^ state[8 + (i + 1) % 4] ^ state[12 + (i + 1) % 4];
        round_key[4 + i] = T[temp] ^ key[i * 4 + 1];
        // 计算新列的第三个字节
        temp = state[(i + 2) % 4] ^ state[4 + (i + 2) % 4] ^ state[8 + (i + 2) % 4] ^ state[12 + (i + 2) % 4];
        round_key[8 + i] = T[temp] ^ key[i * 4 + 2];
        // 计算新列的第四个字节
        temp = state[(i + 3) % 4] ^ state[4 + (i + 3) % 4] ^ state[8 + (i + 3) % 4] ^ state[12 + (i + 3) % 4];
        round_key[12 + i] = T[temp] ^ key[i * 4 + 3];
    }

    // 轮密钥加
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }

    // 将状态矩阵拼接为输出
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
}

int main() {
    unsigned char key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char in[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char output[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    //unsigned char key[] = "This is a key!!!"; 
    printf("\n");
    printf("   明文为：\n\n          ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", in[i]);
    }
    printf("\n");
    printf("   密钥为：\n\n          ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", key[i]);
    }
    aes_encrypt(in, output, key);
    printf("\n");
    printf("   密文为：\n\n          ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", output[i]);
    }
    auto start_time = std::chrono::steady_clock::now();
    for (int i = 0; i < 100000; i++)aes_encrypt(in, output, key);
    auto end_time = std::chrono::steady_clock::now();

    auto running_time = end_time - start_time;

    printf("\n\n");
    std::cout << "   aes加密100000次时间为： " << (std::chrono::duration <double, std::milli>(running_time).count()) << " ms" << std::endl;
    // 输出加密后的结果
    
    cout << endl;

    return 0;
}