#include<iostream>
#include <chrono>
#include<thread>
#include<algorithm>
#include<complex>
#include<fstream>
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
int main(int argc, char **argv) {//argv[1] is the filename, argv[2] is the keyword
	// Pool of threads
	std::thread pool[2];

    std::string filename(argv[1]);
    std::cout<<"filename: "<<filename<<std::endl;
    NFL_POLY_COEF_TYPE kw=str2int(argv[2],strlen(argv[2]));


    std::string keyword(argv[2]);
    std::cout<<"keyword: "<<keyword<<std::endl;


	mpz_t mod;
    mpz_init(mod);
    mpz_set(mod, Poly_t::moduli_product());
    const uint64_t modulo = mpz_get_ui(mod);

	TrustedParty thirdParty{NFL_POLY_N, NFL_POLY_Q_BITS, modulo, sigma_1024_ibe, 80};//n,k,q,sigma,lambda

    auto start1 = std::chrono::high_resolution_clock::now();

    //thirdParty.generateMasterKey();
    thirdParty.loadMasterKey();

	thirdParty.setGaussian(zeta_1024_ibe);//set parameters
	thirdParty.preCompute(2);

    User sender{NFL_POLY_N, NFL_POLY_Q_BITS, modulo, tau_1024_ibe, 0.2, 80, kw, &thirdParty};
    //sender.compute

    //find keys
    std::string dir="/home/karloz/PEKS_keys/"+keyword;
    std::string mkdir="";
    std::ifstream pk("/home/karloz/PEKS_keys/"+keyword+"/pk");
    
    if(!pk.good())
    {
        printf("pk not found, generating...\n");
        sender.extractPrivateKey(kw);
        mkdir = "mkdir " + dir;
        system(mkdir.c_str());
        sender.saveT(keyword);
        sender.saveX(keyword);
    }
    else
    {
        sender.getT(keyword);
        sender.getX(keyword);
    }


	sender.setEncrypt(kw);
    //sender.check();


    //生成随机的C_1
	Poly_t m = nfl::uniform();
	for (auto &m_i : m.poly_obj()) {
		m_i %= 2;
	}

	Poly_t * ciphertext = new Poly_t[(NFL_POLY_Q_BITS + 3)*2];
	sender.encrypt(ciphertext, m);

    //create a directory, if already exists, delete then create
    dir = "/home/karloz/Desktop/cryptoTech/files/"+filename;
    std::string rmdir = "rm -rf " + dir;
    //printf("rmdir: %s\n", rmdir.c_str());//delete the directory
    system(rmdir.c_str());
    mkdir = "mkdir " + dir;
    //printf("mkdir: %s\n", mkdir.c_str());//create the directory
    system(mkdir.c_str());

    //create two files -- plaintext and ciphertext
    std::string file1 = dir + "/plaintext";
    std::string file2 = dir + "/ciphertext";
    std::ofstream out1(file1);
    std::ofstream out2(file2);

    //write plaintext to file as int
    for(auto &m_i : m.poly_obj())
    {
        out1 << m_i << " ";
    }
    out1.close();

    //write ciphertext to file as int
    for(int i=0;i<(NFL_POLY_Q_BITS + 3)*2;++i)
    {
        for(auto &c_i : ciphertext[i].poly_obj())
        {
            out2 << c_i << " ";
        }
    }
    out2.close();

    //read ciphertext from file
    std::ifstream in(file2);
    Poly_t * ciphertext2 = new Poly_t[(NFL_POLY_Q_BITS + 3)*2];
    for(int i=0;i<(NFL_POLY_Q_BITS + 3)*2;++i)
    {
        for(auto &c_i : ciphertext2[i].poly_obj())
        {
            in >> c_i;
        }
    }
    in.close();


	Poly_t * decrypted = new Poly_t;
	sender.decrypt(decrypted, ciphertext2);
    //std::cout<<"decrypted:"<<*decrypted<<std::endl;

    int m1[10000];
    int i=0;
    for(auto &m_i : m.poly_obj())m1[i++]=m_i;
    i=0;
    for(auto &d_i : decrypted->poly_obj())
    {
        if(m1[i++]!=d_i)
        {
            std::cout<<"Encryption error:"<<i<<std::endl;
            return -1;
        }
    }   

    printf("save successfully!");
	return 0;
}
