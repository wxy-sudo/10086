#include <iostream>
#include <stdio.h>
#include <time.h>
#include"sm3_primitive.h"
#include <chrono>
#include <random>
#include "openssl/evp.h"

void printf_hex(const uint8_t str[], size_t len) {
	std::cout << "        ";
	for (int i = 0; i < len; i++) {
		if (i % 32 == 0) std::cout << std::endl<< "        ";
		printf("%02X", str[i]);
		
	}
	printf("\n");
}


int main() {
	// 创建随机数生成器
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);


	sm3_ctx sig_ctx;
	sm3_init(&sig_ctx);
	uint8_t* data = new uint8_t[192];
	uint8_t* pdata = data;
	
	// 创建128字节的缓冲区并填充随机值
	uint8_t* key = new uint8_t[64];
	for (int i = 0; i < 64; i++) {
		key[i] = static_cast<uint8_t>(dis(gen));
	}
	
	uint8_t* digest = new uint8_t[32];
	uint8_t* digest2 = new uint8_t[32];
	uint8_t message[] = "sm3_lengthExtensionAttack!";
	std::cout << std::endl;
	std::cout << "   密钥为: " ;
	printf_hex(key, 64);
	int times = 0;
	sm3_update(&sig_ctx, key, 64, data, times);
	sig_ctx.nblocks = 0;

	

	//std::cout << std::endl;
	//std::cout << "   Data1: ";
	//printf_hex(pdata, 128);

	sm3_update(&sig_ctx, message, sizeof(message)-1, data, times);


	sm3_final(&sig_ctx, digest, data, times);

	std::cout << std::endl;
	std::cout << "   Padding后的消息: ";
	printf_hex(pdata+64, 64);

	std::cout << std::endl;
	std::cout << "   最初消息的摘要值: ";
	printf_hex(digest, 32);

	uint8_t appended_message[] = "appended! ";
	sig_ctx.num = 0;
	sig_ctx.nblocks += 1;
	sm3_update(&sig_ctx, appended_message, sizeof(appended_message)-1, data, times);
	sm3_final(&sig_ctx, digest, data, times);

	memcpy(data + 128, appended_message, sizeof(appended_message));
	std::cout << std::endl;
	std::cout << "   进行长度扩展攻击时所使用的消息: ";
	printf_hex(pdata+64, 64 + sizeof(appended_message)-1);

	std::cout << std::endl;
	std::cout << "   长度扩展攻击后获得的摘要值: ";
	printf_hex(digest, 32);

	sm3_ctx sig_ctx1;
	sm3_init(&sig_ctx1);
	sm3_update(&sig_ctx1, pdata, 128 + sizeof(appended_message)-1, message, times);
	sig_ctx1.nblocks -= 1; //key不能算在nblocks中，所以要减1
	sm3_final(&sig_ctx1, digest2, message, times);

	std::cout << std::endl;
	std::cout << "   直接对长度扩展攻击的消息求得的摘要值: ";
	printf_hex(digest2, 32);

	return 0;
}