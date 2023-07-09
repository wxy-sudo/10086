#include <iostream>
#include "openssl/evp.h"
#include "openssl/rand.h"
#include <random>
#include <time.h>
#include <unordered_map>
#include <cstring>
#include <chrono>
#include <unordered_set>

//uint8_t base[32];
const int COLLISION_LEN = 24;
const int COLLISION_BYTE = COLLISION_LEN >> 3;

void printf_hex(const uint8_t str[], size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", str[i]);
    }
    printf("\n");
}

void printf_hex(const char str[], size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%X", str[i]);
    }
    printf("\n");
}

void build_table(std::unordered_map<uint64_t, uint8_t*>& hash_map) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    uint8_t out[32];
    uint32_t out_size = 0;
    uint8_t* value = new uint8_t[32];
    for (uint64_t i = 0; i < (uint64_t)429496; i++) {
        uint8_t data[32];
        
        //std::memcpy(data, base, 32);
        //*((uint64_t*)data) = i;
        RAND_bytes(data, 32);
        
        EVP_Digest(data, 32, out, &out_size, EVP_sm3(), NULL);
        uint64_t key = 0;
        std::memcpy(&key, out, COLLISION_BYTE);
        auto result2 = hash_map.find(key);
        if (result2 != hash_map.end()) {
            value = result2->second;
        }
        
        auto result = hash_map.insert(std::make_pair(key, data));
        // 如果该哈希值已经存在，输出碰撞信息
        if (!result.second) {
            std::cout << "发现碰撞的哈希值为：" << std::hex << key << std::endl;
            printf("一个原像为：");
            printf_hex(value, 32);
            printf("另一个原像为：");
            printf_hex(data, 32);
            //std::cout << "哈希输出为：";
            //printf_hex(out, 32);
            return;
        }
    }
    std::cout << "未找出一组碰撞!";
    EVP_MD_CTX_free(ctx);
}

int main() {
    std::cout << "生日攻击长度为：" << COLLISION_LEN << std::endl;

    std::unordered_map<uint64_t, uint8_t*> hash_map;
    auto start_time = std::chrono::steady_clock::now();
    build_table(hash_map);
    
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;

    std::cout << "Collision time for SM3 = " << std::chrono::duration <double, std::milli>(running_time).count() << " ms" << std::endl;
    return 0;
}
