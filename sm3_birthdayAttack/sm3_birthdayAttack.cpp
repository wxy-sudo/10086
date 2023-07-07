/*#include <iostream>
#include "openssl/evp.h"
#include "openssl/rand.h"
#include <random>
#include <time.h>
#include <unordered_map>
#include <cstring>
#include <chrono>
#include <unordered_set>

uint8_t base[32];
const int COLLISION_LEN = 48;
const int COLLISION_BYTE = COLLISION_LEN >> 3;

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

void build_table(std::unordered_map<uint64_t, uint32_t>& hash_map) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    uint8_t data[32];
    uint8_t out[32];
    uint32_t out_size = 0;

    for (uint32_t i = 0; i < (1u << (COLLISION_LEN / 2)); i++) {
        std::memcpy(data, base, 32);
        *((uint64_t*)data) = i;
        EVP_Digest(data, 32, out, &out_size, EVP_sm3(), NULL);
        uint64_t key = 0;
        std::memcpy(&key, out, COLLISION_BYTE);

        auto result = hash_map.insert(std::make_pair(key, i));
        // 如果该哈希值已经存在，输出碰撞信息
        if (!result.second) {
            std::cout << "发现碰撞的哈希值为：" << std::hex << key << std::endl;
            std::cout << "碰撞的键为：" << std::hex
                << result.first->second << " 和 " << i << std::endl;
            std::cout << "哈希输出为：";
            printf_hex(out, 32);
            return;
        }
    }
    EVP_MD_CTX_free(ctx);
}

void find_collision_birthday(const std::unordered_map<uint64_t, uint32_t>& hash_map) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    uint8_t out[32];
    uint32_t out_size = 0;

    while (true) {
        RAND_bytes(base, 32);
        EVP_Digest(base, 32, out, &out_size, EVP_sm3(), NULL);
        uint64_t key = 0;
        std::memcpy(&key, out, COLLISION_BYTE);

        auto iter = hash_map.find(key);
        if (iter != hash_map.end()) {
            std::cout << "发现碰撞的哈希值为：" << std::hex << key << std::endl;
            std::cout << "碰撞的键为：" << std::hex
                << iter->second << " 和 " << base << std::endl;
            std::cout << "哈希输出为：";
            printf_hex(out, 32);
            break;
        }
    }
    EVP_MD_CTX_free(ctx);
}*/

/*int main() {
    std::cout << "生日攻击长度为：" << COLLISION_LEN << std::endl;

    std::unordered_map<uint64_t, uint32_t> hash_map;
    auto start_time = std::chrono::steady_clock::now();
    build_table(hash_map);
    
    find_collision_birthday(hash_map);
    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time - start_time;

    std::cout << "Collision time for SM3 = " << std::chrono::duration <double, std::milli>(running_time).count() << " ms" << std::endl;
    return 0;
}*/
