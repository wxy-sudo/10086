#include <iostream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <complex>
#include <fstream>
#include <dirent.h>
#include <sys/types.h>
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
int main(int argc, char **argv) {//argv[1] is the keyword
	// Pool of threads
	std::thread pool[2];

    std::string keyword(argv[1]);
    NFL_POLY_COEF_TYPE kw=str2int(argv[1],strlen(argv[1]));

    //std::cout<<"keyword: "<<keyword<<std::endl;


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

    //sender.extractPrivateKey(kw);

    std::ifstream pk("/home/karloz/PEKS_keys/"+keyword);

    if(!pk.good()) 
    {
        printf("not found\n");
        return -1;
    }
    else
    {
        sender.getT(keyword);
        sender.getX(keyword);
        //sender.printX();
    }

	sender.setEncrypt(kw);

    //sender.check();

    std::string path="/home/karloz/Desktop/cryptoTech/files/";
    DIR *dir;
    struct dirent *ptr;
    char base[1000];

    if ((dir=opendir(path.c_str()))==NULL)
    {
        perror("Open dir error...");
        exit(1);
    }


    std::string filepath1="",filepath2="";

    Poly_t plaintext;
    Poly_t * ciphertext = new Poly_t[(NFL_POLY_Q_BITS + 3)*2];
    Poly_t * decrypted = new Poly_t;
    

    while((ptr=readdir(dir))!=NULL)
    {
        if(strcmp(ptr->d_name,".")==0 || strcmp(ptr->d_name,"..")==0)    ///current dir OR parrent dir
            continue;
        if(ptr->d_type & DT_DIR)
        {
            //std::cout<<"dir:"<<ptr->d_name<<std::endl;
            filepath1=path+ptr->d_name+"/plaintext";
            filepath2=path+ptr->d_name+"/ciphertext";

            

            //read plaintext from file
            std::ifstream in(filepath1);
            
            for(auto &m_i : plaintext.poly_obj())in >> m_i;
            in.close();

            //read ciphertext from file
            std::ifstream in2(filepath2);
            for(int i=0;i<(NFL_POLY_Q_BITS + 3)*2;++i)
                for(auto &c_i : ciphertext[i].poly_obj())in2 >> c_i;
            in2.close();

            int tag = 0;
            //decrypt
            sender.decrypt(decrypted, ciphertext);
            //check if the decryption is correct
            int m1[10000];
            int i=0;
            for(auto &m_i : plaintext.poly_obj())m1[i++]=m_i;
            i=0;
            for(auto &d_i : decrypted->poly_obj())
            {
                if(m1[i++]!=d_i)
                {
                    //std::cout<<"error:"<<i<<std::endl;
                    tag=1;
                    break;
                }
            }  
            if(!tag)std::cout<<ptr->d_name<<std::endl;
            //else std::cout<<"not match:"<<ptr->d_name<<std::endl;
        }
    }
    closedir(dir);
    
    delete[] ciphertext;
    delete decrypted;

	return 0;
}
