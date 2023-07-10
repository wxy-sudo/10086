#include <iostream>
#include "openssl/evp.h"
#include "openssl/rand.h"
#include <random>
#include <time.h>
#include <unordered_map>
#include <cstring>
#include <chrono>
#include <unordered_set>

const int COLLISION_LEN = 24;
const int COLLISION_BYTE = COLLISION_LEN >> 3;
uint8_t data[32];
void printf_hex(const uint8_t str[], size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%X", str[i]);
    }
    printf("\n");
}

void printf_hex(const char str[], size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%X", str[i]);
    }
    printf("\n");
}

void rho_method() {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    uint8_t out1[32];
    uint32_t out1_size = 0;

    uint8_t out2[32];
    uint8_t out3[32];
    uint8_t out4[32];
    uint32_t out2_size = 0;
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
        memcpy(out1, out3, 32);
        memcpy(out2, out4, 32);
        
    }
    EVP_MD_CTX_free(ctx);
}


int main() {
    std::cout << "rho_method长度为：" << COLLISION_LEN << std::endl;

    RAND_bytes(data, 32);
    printf("起始随机数据为：");
    printf_hex(data, 32);

    auto start_time = std::chrono::steady_clock::now();
    rho_method();

    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;

    std::cout << "Collision time for SM3 = " << (std::chrono::duration <double, std::milli>(running_time).count())/1000 << " s" << std::endl;
    return 0;
}
