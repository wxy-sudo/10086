#include <iostream>
#include <stdio.h>
#include <time.h>
#include"sm3_primitive.h"
#include <chrono>
#include "openssl/evp.h"
#include "sm3_promote.h"

using namespace std;


int main() {
	unsigned char msg[] = "optimize SM3, optimize SM3,optimize SM3, optimize SM3, optimize SM3, optimize SM3, optimize SM3, optimize SM3, optimize SM3, optimize SM3";
	size_t msg_len = strlen((const char*)msg);
	unsigned char dgst1[32];
	unsigned char dgst2[32];
	uint32_t out2_size = 32;

	printf("\n");
	auto start_time = std::chrono::steady_clock::now();
	for (int i = 0; i < 1000000; i++)
		sm3_hash(dgst1, msg, msg_len);
	auto end_time = std::chrono::steady_clock::now();
	auto running_time = end_time - start_time;

	std::cout << "     优化前SM3执行1000000次时间为： " << std::chrono::duration <double, std::milli>(running_time).count() << " ms" << std::endl;
	


	start_time = std::chrono::steady_clock::now();
	for (int i = 0; i < 1000000; i++)
		sm3_hash_simd(dgst2, msg, msg_len);

	end_time = std::chrono::steady_clock::now();
	running_time = end_time - start_time;

	std::cout << "     优化后SM3执行1000000次时间为： " << std::chrono::duration <double, std::milli>(running_time).count() << " ms" << std::endl;
	printf("\n");

	
	std::cout << "     优化前SM3哈希值为： ";
	for (int i = 0; i < 32; i++)
		printf("%02x", dgst1[i]);
	printf("\n");
	std::cout << "     优化后SM3哈希值为： ";
	for (int i = 0; i < 32; i++)
		printf("%02x", dgst2[i]);
	printf("\n");
}