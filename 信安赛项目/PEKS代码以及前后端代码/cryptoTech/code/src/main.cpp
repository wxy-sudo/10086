#include<iostream>
#include <chrono>
#include<thread>
#include<algorithm>
#include<complex>
#include "util/fast_fft.hpp"
#include "ibe/user.hpp"
#include "ibe/trusted_third_party.hpp"

#include<nfl.hpp>

#define sigma_1024_ibe 5//5
#define zeta_1024_ibe 0.2//6360
#define tau_1024_ibe 0.2//5

inline NFL_POLY_COEF_TYPE str2int(char str[],int len)
{
    NFL_POLY_COEF_TYPE res=0;
    for(int i=0;i<len;++i)res=res*256+NFL_POLY_COEF_TYPE(str[i]);
    return res;
}

using namespace Ibe;
int main(void) {
	// Pool of threads
	std::thread pool[2];

    char keyword[]="engender";
    NFL_POLY_COEF_TYPE kw=str2int(keyword,strlen(keyword));

	mpz_t mod;
    mpz_init(mod);
    mpz_set(mod, Poly_t::moduli_product());
    const uint64_t modulo = mpz_get_ui(mod);


	TrustedParty thirdParty{NFL_POLY_N, NFL_POLY_Q_BITS, modulo, sigma_1024_ibe, 80};//n,k,q,sigma,lambda

    auto start1 = std::chrono::high_resolution_clock::now();

    thirdParty.generateMasterKey();

    //only compute setup time
    auto end1 = std::chrono::high_resolution_clock::now();
    auto timing1 = std::chrono::duration<double, std::milli>(end1 - start1);
    std::cout << "GenerateKey: " << timing1.count() << " ms " << std::endl;

	thirdParty.setGaussian(zeta_1024_ibe);//set parameters
	thirdParty.preCompute(2);

    User sender{NFL_POLY_N, NFL_POLY_Q_BITS, modulo, tau_1024_ibe, 0.2, 80, kw, &thirdParty};
    //sender.compute

    auto start2 = std::chrono::high_resolution_clock::now();
    sender.extractPrivateKey(kw);
    auto end2 = std::chrono::high_resolution_clock::now();

    auto timing2 = std::chrono::duration<double, std::milli>(end2 - start2);
    std::cout << "Extract: " << timing2.count() << " ms " << std::endl;

	sender.setEncrypt(kw);


    //生成随机的消息m*******************************
	Poly_t m = nfl::uniform();
	for (auto &m_i : m.poly_obj()) {
		m_i %= 2;
	}

	Poly_t * ciphertext = new Poly_t[(NFL_POLY_Q_BITS + 3)*2];
	sender.encrypt(ciphertext, m);


	auto lambdaEnc = [&sender, &m](Poly_t * ciphertext, const uint32_t length) {
		for(uint32_t i = 0; i < length; ++i) {
			sender.encrypt(ciphertext, m);
            // std::cout << "dimension: " << i<<" and m: "<<m << std::endl;
            // std::cout << "dimension: " << i<<" and ciphertext: "<<*ciphertext << std::endl;
		}
	};
	pool[0] = std::thread(lambdaEnc, ciphertext, 100);
	//pool[1] = std::thread(lambdaEnc, ciphertext + NFL_POLY_Q_BITS + 3, 100);
	auto start = std::chrono::high_resolution_clock::now();
	pool[0].join();
	//pool[1].join();
	auto end = std::chrono::high_resolution_clock::now();
	auto timing = std::chrono::duration<double, std::milli>(end - start);
    // std::cout << "m: "<<m << std::endl;
    // std::cout <<"ciphertext: "<<*ciphertext << std::endl;
	std::cout << "Encryption Time of 100 messages: " << timing.count() << " ms " << std::endl;


	Poly_t * decrypted = new Poly_t[2];
	sender.decrypt(decrypted, ciphertext);
    // std::cout<<"m:"<<m<<std::endl;
    // std::cout<<"decrypted:"<<*decrypted<<std::endl;

	auto lambdaDec = [&sender, ciphertext](Poly_t * output, const uint32_t length) {
		for(uint32_t i = 0; i < length; ++i) {
			sender.decrypt(output, ciphertext);
            // std::cout << "dimension: " << i<<" and decrypt: "<<*output << std::endl;
            // std::cout << "dimension: " << i<<" and ciphertext: "<<*ciphertext << std::endl;
		}
	};

	pool[0] = std::thread(lambdaDec, decrypted, 100);
	//pool[1] = std::thread(lambdaDec, decrypted + 1, 100);
	start = std::chrono::high_resolution_clock::now();
	pool[0].join();
	//pool[1].join();
	end = std::chrono::high_resolution_clock::now();
	timing = std::chrono::duration<double, std::milli>(end - start);
	std::cout << "Decryption Time of 100 ciphertexts: " << timing.count() << " ms " << std::endl;
    // std::cout<<"ciphertext:"<<*ciphertext<<std::endl;
    // std::cout<<"decrypted:"<<*decrypted<<std::endl;

//test whether the decryption is correct
    uint32_t correct=0;
    uint32_t error=0;
    uint32_t total=0;
    uint32_t test=0;
    uint32_t recorrect=0;
    uint32_t m1[10000];
    uint32_t decrypted1[10000];
    //Poly_t  m1{&m};
    uint32_t i=0;
    for (auto &m_i : m.poly_obj()) {
        m1[i]=m_i;
        test++;
        i++;
	}
    i=0;
    for(auto & decrypted_i : decrypted->poly_obj()) {
       if(decrypted_i==m1[i]){
           correct++;
           if(decrypted_i==1){
               recorrect++;
           }
       }
       else{
           if(m1[i]==1){
               error++;
           }
       }
        i++;
        total++;
	}
    std::cout<<"All decryption:\n"<<total<<std::endl;
    std::cout<<"Correct decryption:\n"<<correct<<std::endl;
    //std::cout<<"recorrect decryption:\n"<<recorrect<<std::endl;
    std::cout<<"error decryption:\n"<<error<<std::endl;
	return 0;
}
