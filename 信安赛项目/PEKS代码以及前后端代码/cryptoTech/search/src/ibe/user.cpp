
#include<cstdint>
#include<cmath>
#include<random>
#include<algorithm>
#include<memory>
#include<thread>
#include<nfl.hpp>
#include<fstream>

#include "user.hpp"
#include "params.hpp"



/* --------------------------------------------------------------------------------------------------- */
/* Const Values -------------------------------------------------------------------------------------- */

/* Const Values End ---------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------------- */



/* --------------------------------------------------------------------------------------------------- */
/* Static Functions ---------------------------------------------------------------------------------- */

/* Static Functions End ------------------------------------------------------------------------------ */
/* --------------------------------------------------------------------------------------------------- */



/*
 * Private fields
 */
 struct Ibe::User::encapsulation {
 	//
 	const uint32_t dimension; // n
	const uint32_t param;     // k
	const uint64_t modulus;   // q
	uint32_t m; 		  	  // m

 	// ID
 	NFL_POLY_COEF_TYPE id;
 	Poly_t h_1{0};
 	Poly_t a_id[MAX_Q_BITS];
    Poly_t t{0};
 	// encryption status
 	mutable Poly_t encryption_a_id[MAX_Q_BITS];


 	// trusted party & public/private key
 	Poly_t * mpkA;
 	Poly_t mpkU{0};
 	Poly_t sk[MAX_Q_BITS];
 	TrustedParty * trustedParty;

 	// Related to Trapdoor
 	Poly_t gs[MAX_Q_BITS];//trapdoor :g

 	// Gaussian errors
 	std::unique_ptr<Gauss_t> gaussianNoiseE0;
 	std::unique_ptr<Gauss_t> gaussianNoiseE1;
 	std::unique_ptr<Gauss_t> gaussianNoiseE2;
    
    std::unique_ptr<Gauss_t> gaussianNoises;
    std::unique_ptr<fastGauss_t> fastGaussNoises;

	std::unique_ptr<fastGauss_t> fastGaussNoiseE0;
	std::unique_ptr<fastGauss_t> fastGaussNoiseE1;
	std::unique_ptr<fastGauss_t> fastGaussNoiseE2;

	// 
	std::independent_bits_engine<std::mt19937_64, NFL_POLY_Q_BITS, NFL_POLY_COEF_TYPE> randomGen;

	// Functions
	void hash(Poly_t * output, const NFL_POLY_COEF_TYPE x);
	void compute_a_id(Poly_t * output, const Poly_t & h);
	NFL_POLY_COEF_TYPE inverse(const NFL_POLY_COEF_TYPE a);
	void inverse_poly(Poly_t * output, Poly_t & input);
 };



void Ibe::User::encapsulation::hash(Poly_t * output, const NFL_POLY_COEF_TYPE x) {	
	randomGen.seed(x);
	for(auto & output_i : output->poly_obj()) {
		output_i = randomGen();
        
	}
}


void Ibe::User::encapsulation::compute_a_id(Poly_t * output, const Poly_t & h) {	
   
	memcpy(output, mpkA, sizeof(Poly_t)*2);
   
	// Pool of threads
	std::thread pool[THREADS_NUMBER];

	// Thread shares
	uint32_t thread_shares[THREADS_NUMBER]; 
	const uint32_t thread_share = param/THREADS_NUMBER;
	std::fill_n(thread_shares, THREADS_NUMBER, thread_share);
	for(uint32_t i = 0; i < param - thread_share*THREADS_NUMBER; ++i) {
		++thread_shares[i];
	}

	// Lambda for a_id
	auto lambda = [&h](Poly_t * outputs, const Poly_t * gs, const Poly_t * a, const uint32_t length) {
		for(uint32_t i = 0; i < length; ++i) {
			*outputs = h*(*gs) + (*a);
            //std::cout <<"dimension: "<<i<< " and h   : "<<h << std::endl;
            //std::cout <<"dimension: "<<i<< " and g   : "<<*gs << std::endl;
            //std::cout <<"dimension: "<<i<< " and a   : "<<*a << std::endl;
            //std::cout <<"dimension: "<<i<< " and a_id: "<<*outputs << std::endl;
			++outputs;
			++gs;
			++a;		
		}
	};

	// compute a_id
	const Poly_t * gsIndex = gs;
	const Poly_t * AIndex = (mpkA + 2);
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		const uint32_t share = thread_shares[i];
		//pool[i]  = std::thread(lambda, output, gsIndex, AIndex, share);//original a_id前两个应该为a的前两项。只对从第三项开始的a_id计算
        pool[i]  = std::thread(lambda, output+2, gsIndex, AIndex, share);
		output  += share;
		AIndex  += share;
		gsIndex += share;
	}
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		pool[i].join();
	}
    //std::cout <<  "\n compute a_id: \n"<< *output<<std::endl;
   
}


NFL_POLY_COEF_TYPE Ibe::User::encapsulation::inverse(const NFL_POLY_COEF_TYPE a) {
   // NFL_POLY_COEF_TYPE u0 = 1, v0 = 0;
   // NFL_POLY_COEF_TYPE u1 = 0, v1 = 1;
   // NFL_POLY_COEF_TYPE res0 = a, res1 = modulus, quo = 0;
   // NFL_POLY_COEF_TYPE tmp;
    
    POLY_COEF_TYPE u0 = 1, v0 = 0;
    POLY_COEF_TYPE u1 = 0, v1 = 1;
    POLY_COEF_TYPE res0 = a, res1 = modulus, quo = 0;
    POLY_COEF_TYPE tmp;
   //exgcd
    while (res1 != 0) {
      quo = res0 / res1;
      
      tmp = res0, res0 = res1, res1 = tmp % res1;
      
      tmp = u0, u0 = u1, u1 = tmp - quo*u1;
      
      tmp = v0, v0 = v1, v1 = tmp - quo*u1;
       
    }
    return (u0 > 0) ? u0 : u0 + modulus;
}

void Ibe::User::encapsulation::inverse_poly(Poly_t * output, Poly_t & input) {
    uint32_t i = 0;
    NFL_POLY_COEF_TYPE invs[dimension];
    NFL_POLY_COEF_TYPE j;
	for(auto & input_i : input.poly_obj()) {
		invs[i++] = inverse(input_i);
        j=inverse(input_i);
        
	}
	output->set(invs, invs + dimension, false);
}


/* --------------------------------------------------------------------------------------------------- */
/* Public Interface ---------------------------------------------------------------------------------- */
/* @Override */
Ibe::User::User(const uint32_t n, const uint32_t k, const uint64_t q, const double_t tau, const double_t gamma, const uint32_t lambda, \
	            const NFL_POLY_COEF_TYPE id, TrustedParty * trustedParty) noexcept : \
impl(new encapsulation {.dimension = n, .param = k, .modulus = q}) {
	// initialize global parameters
	impl->id = id;
	impl->m = k + 2;
    
    //std::cout<<"\na:"<<std::endl;
	// initialize trusted party & public keys
	impl->mpkA = trustedParty->getPublicKey(&impl->mpkU);
    
    
    for(uint32_t i = 0; i < impl->m; ++i) {
        //std::cout << "dimension: " << i<<" and a : "<<impl->mpkA[i]<< std::endl;
        //++aa;
    }
      
     
    
	impl->trustedParty = trustedParty;
    

	// prebuild the Gaussian noises
	impl->fastGaussNoiseE0.reset(new fastGauss_t(tau, lambda, n));
	impl->gaussianNoiseE0.reset(new Gauss_t(impl->fastGaussNoiseE0.get()));

	impl->fastGaussNoiseE1.reset(new fastGauss_t(gamma, lambda, n));
	impl->gaussianNoiseE1.reset(new Gauss_t(impl->fastGaussNoiseE1.get()));

	impl->fastGaussNoiseE2.reset(new fastGauss_t(tau, lambda, n));
	impl->gaussianNoiseE2.reset(new Gauss_t(impl->fastGaussNoiseE2.get()));

    impl->fastGaussNoises.reset(new fastGauss_t(0.5, lambda, n));
	impl->gaussianNoises.reset(new Gauss_t(impl->fastGaussNoises.get()));

	// build gs and NTT
	NFL_POLY_COEF_TYPE gi = 1;
	for(uint32_t i = 0; i < k; ++i) {
		impl->gs[i].set(gi);
		impl->gs[i].ntt_pow_phi();
        //std::cout<<"g: "<<impl->gs[i]<<std::endl;
		gi <<= 1;
	}
    
    //std::cout<<"\nhash:"<<std::endl;
	// compute h
	Poly_t h{0};
	impl->hash(&h, id);
    //std::cout<<"id: "<<id<<std::endl;
    //std::cout<<"h : "<<h<<std::endl;
    //std::cout<<"\ninverse_h:"<<std::endl;
	// inverse h
	impl->inverse_poly(&(impl->h_1), h);
    //std::cout<<"h_1: "<<impl->h_1<<std::endl;
    //std::cout<<"\ncompute a_id:"<<std::endl;
	// compute a_id
	impl->compute_a_id(impl->a_id, h);
    for(uint32_t i = 0; i < impl->m; ++i) {
     //   std::cout << "dimension: " << i<<" , a_id : "<<impl->a_id[i]<< std::endl;    
    }
    //std::cout <<std::endl;
}

/* @Override */
Ibe::User::~User(void) noexcept {

}


/* @override */
void Ibe::User::extractPrivateKey(const NFL_POLY_COEF_TYPE id) const noexcept {
    Poly_t h{0};
    impl->hash(&h, id);
    // std::cout<<"id: "<<id<<std::endl;
    // std::cout<<"h : "<<h<<std::endl;
    // std::cout<<"\ninverse_h:"<<std::endl;
	//impl->trustedParty->extract(impl->sk, impl->a_id, impl->h_1);//original
    impl->trustedParty->extract(impl->sk, impl->a_id, impl->h_1,impl->t);
    
    impl->t=h*impl->t;

}


/* @override */
void Ibe::User::setEncrypt(const NFL_POLY_COEF_TYPE targetId) const noexcept {
	// compute h
	Poly_t h{0};
	impl->hash(&h, targetId);

	// compute a_id
	impl->compute_a_id(impl->encryption_a_id, h);//在加密算法时用到encryption_a_id
    
}

/* @override */
void Ibe::User::encrypt(Poly_t * output, const Poly_t & msg) const noexcept {
    //std::cout <<std::endl<<  "encrypt: \n" << std::endl;
	// prepare the plaintext
	Poly_t plaintext{msg};
	for (auto & plaintext_i : plaintext.poly_obj()) {
		plaintext_i *= (impl->modulus/2);
    }//compute q/2*m

    //std::cout<<"brforeNTT-m*q/2:"<<plaintext<<std::endl;
    plaintext.ntt_pow_phi();//ntt_pow_phi() corresponds to invntt_pow_invphi()
    
    //std::cout<<"afterNTT-m*q/2:"<<plaintext<<std::endl;
    //plaintext.invntt_pow_invphi();
    //std::cout<<"invntt-m:"<<plaintext<<std::endl;
     
    // uniform noise
    Poly_t s = nfl::uniform();
    Gauss_t noise1 = *(impl->gaussianNoises.get());
    s.set(noise1);
    s.ntt_pow_phi();
    //std::cout << "s: "<<s<< std::endl;
	
    // gaussian noise e0
    const Poly_t * A_idIndex = impl->encryption_a_id;//设置另外的id后的数
    
    
    const Poly_t * sk_id = impl->sk;
    const Poly_t * sk = impl->sk;
    
    Poly_t test{0};
    Poly_t bx1{0};
    Poly_t bx2{0};
    const Poly_t * A_id = impl->encryption_a_id;
    for(uint32_t i = 0; i < impl->m; ++i) {
		test=test+(*sk)*(*A_id);
        
        ++sk;
		++A_id;
	} 
    //std::cout << "u: "<<impl->mpkU<< std::endl;
    //std::cout << "sk*a_id: "<<test<< std::endl;
    
    test=impl->mpkU+impl->t-test;
    test=test*s;
    test.invntt_pow_invphi();

    std::cout << "u+ht-sk*a_id: "<<test<< std::endl;//shoule be 0

    //std::cout << "(u+ht-sk*a_id)s: "<<test<< std::endl;
    //std::cout << "c=a_id*s+e0:"<< std::endl;
    Gauss_t noiseE0 = *(impl->gaussianNoiseE0.get());
    for(uint32_t i = 0; i < impl->m - impl->param; ++i) {//about dimension=impl->m - impl->param
    	output->set(noiseE0);//original
       
        output->ntt_pow_phi();
        
       //std::cout << "dimension: " << i<<" and e0: "<<*output << std::endl;
        bx1=bx1+(*sk_id)*(*output) ;
       
    	*output = *output + s*(*A_idIndex);
        
        //std::cout << "dimension: " << i<<" and c: "<<*output << std::endl;
        
        ++sk_id;
    	++output;
    	++A_idIndex;
    }
    
    // std::cout << "c=a_id*s+e0:"<< std::endl;
    // gaussian noise e1
    Gauss_t noiseE1 = *(impl->gaussianNoiseE1.get());
    for(uint32_t i = 0; i < impl->param; ++i) {
    	output->set(noiseE1);
        
    	output->ntt_pow_phi();
        
       //std::cout << "dimension: " << i<<" and e1: "<<*output << std::endl;
       bx1=bx1+(*sk_id)*(*output) ;
       
    	*output = *output + s*(*A_idIndex);
        //std::cout << "dimension: " << i<<" and c: "<<*output << std::endl;
       // std::cout << "dimension: " << i<<" and sk_id: "<<*sk_id << std::endl;
        //std::cout << "dimension: " << i<<" and a_id: "<<*A_idIndex << std::endl;
        //std::cout << "dimension: " << i+2<<" ciphertext: "<<*output << std::endl;
        //std::cout << "dimension: " << i<<" and address of A_idIndex: "<<A_idIndex << std::endl;
      	++sk_id;
    	++output;
    	++A_idIndex;
    }
    
  // std::cout  <<  "sk*(e0,e1): " << bx1<<std::endl;
   bx2=bx2-bx1;
  // std::cout  <<  "-sk*(e0,e1): " << bx2<<std::endl;
    // final
    Gauss_t noiseE2 = *(impl->gaussianNoiseE2.get());
	output->set(noiseE2);
   
	output->ntt_pow_phi();
    
    //std::cout <<"e2: "<<*output<< std::endl;
    test =test +*output ;
    bx2=bx2+*output ;
	*output = *output + (impl->mpkU+impl->t)*s + plaintext;//compute c=u*s+e2+q/2*m,and the dimension = 1.original
    //*output = *output + impl->mpkU*s + plaintext;
	
   // *output = *output + plaintext;//compute c=e2+q/2*m
    
    
   //std::cout <<"c=e2+m*q/2: "<<*output<< std::endl;
  
   //std::cout <<"e2-sk*(e0,e1): "<<bx2<< std::endl;
    bx2.invntt_pow_invphi();
    //std::cout<<"e2-sk(e0,e1)-invntt: "<<bx2 << std::endl;
   
}


/* @override */
void Ibe::User::decrypt(Poly_t * output, const Poly_t * cipher) const noexcept {
   // std::cout << std::endl<<  "decrypt: \n" << std::endl;
	Poly_t bx{0};
    Poly_t test{0};
	const Poly_t * sk_id = impl->sk;
   
	for(uint32_t i = 0; i < impl->m; ++i) {
		bx = bx + (*sk_id)*(*cipher);
       // std::cout << "dimension: " << i<<" and ciphertext: "<<*cipher << std::endl;
       // std::cout << "dimension: " << i<<" and sk_id     : "<<*sk_id << std::endl;
       // std::cout << "dimension: " << i<<" and sk*(e0,e1): "<<bx << std::endl;
        
		++sk_id;
		++cipher;
	} 
   // std::cout<<"sk*(e0,e1): "<<bx << std::endl;

    //std::cout << std::endl<<  "compute c-b^T*x:\n " << std::endl;
	*output = *cipher - bx;
  //  std::cout <<  "decrypt: "<<*output << std::endl;
	output->invntt_pow_invphi();
    //std::cout <<  "invvtt-decrypt: "<<*output << std::endl;
   
	const uint64_t modulus_4  = impl->modulus /4;
	const uint64_t modulus_34 = 3*modulus_4;
	for(auto & output_i : output->poly_obj()) {
        output_i=output_i%impl->modulus;
		output_i = ((output_i >= modulus_4) && output_i <= modulus_34) ? 1 : 0;
	}
    
    //const uint32_t modulus_2  = impl->modulus /2;
    //std::cout<<"q="<<impl->modulus<<std::endl;

}

void Ibe::User::saveT(std::string filename) noexcept
{
	std::ofstream pk("/home/karloz/PEKS_keys/"+filename+"/pk");
	for(auto t_i : impl->t.poly_obj()) pk << t_i << " ";
	pk.close();
}

void Ibe::User::getT(std::string filename) noexcept
{
	std::ifstream pk("/home/karloz/PEKS_keys/"+filename+"/pk");
	for(auto &t_i : impl->t.poly_obj()) pk >> t_i;
	//for(auto t_i : impl->t.poly_obj()) std::cout << t_i <<' ';
	pk.close();
}

void Ibe::User::saveX(std::string filename) noexcept
{
	std::ofstream skey("/home/karloz/PEKS_keys/"+filename+"/sk");
	for(int i=0;i<MAX_Q_BITS;i++)
		for(auto x_i : impl->sk[i].poly_obj()) skey << x_i << " ";
	skey.close();
}

void Ibe::User::getX(std::string filename) noexcept
{
	std::ifstream skey("/home/karloz/PEKS_keys/"+filename+"/sk");
	for(int i=0;i<MAX_Q_BITS;i++)
		for(auto &x_i : impl->sk[i].poly_obj()) 
		{
			skey >> x_i;
			//std::cout<<x_i<<" ";
		}
	skey.close();
}

void Ibe::User::check() noexcept
{
    Poly_t s = nfl::uniform();
    Gauss_t noise1 = *(impl->gaussianNoises.get());
    s.set(noise1);
    s.ntt_pow_phi();
    //std::cout << "s: "<<s<< std::endl;
	
	const Poly_t * A_idIndex = impl->encryption_a_id;//设置另外的id后的数
    
    
    const Poly_t * sk_id = impl->sk;
    const Poly_t * sk = impl->sk;

	std::cout<<"x:";
	for(int i=0;i<MAX_Q_BITS;i++)
		for(auto x_i : impl->sk[i].poly_obj()) std::cout<<x_i<<" ";
    Poly_t test{0};
    const Poly_t * A_id = impl->encryption_a_id;
    for(uint32_t i = 0; i < impl->m; ++i) {
		test=test+(*sk)*(*A_id);
        
        ++sk;
		++A_id;
	} 
    std::cout << "u: "<<impl->mpkU<< std::endl;
    std::cout << "sk*a_id: "<<test<< std::endl;
    
    test=impl->mpkU+impl->t-test;
    test=test*s;
    test.invntt_pow_invphi();

    std::cout << "u+ht-sk*a_id: "<<test<< std::endl;//shoule be 0
}

void Ibe::User::printX() noexcept
{
	std::cout<<"check x:";
	for(int i=0;i<MAX_Q_BITS;i++)
		for(auto x_i : impl->sk[i].poly_obj()) std::cout<<x_i<<" ";
	std::cout<<std::endl;

	std::cout<<"check t:";
	for(auto t_i : impl->t.poly_obj()) std::cout<<t_i<<" ";
	std::cout<<std::endl;
}