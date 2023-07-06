
#include<cstdint>
#include<cmath>
#include<random>
#include<algorithm>
#include<memory>
#include<thread>
#include<nfl.hpp>

#include "user.hpp"
#include "params.hpp"

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
}


NFL_POLY_COEF_TYPE Ibe::User::encapsulation::inverse(const NFL_POLY_COEF_TYPE a) {
    
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

Ibe::User::User(const uint32_t n, const uint32_t k, const uint64_t q, const double_t tau, const double_t gamma, const uint32_t lambda, \
	            const NFL_POLY_COEF_TYPE id, TrustedParty * trustedParty) noexcept : \
impl(new encapsulation {.dimension = n, .param = k, .modulus = q}) {
	// initialize global parameters
	impl->id = id;
	impl->m = k + 2;
	impl->mpkA = trustedParty->getPublicKey(&impl->mpkU);
    
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
		gi <<= 1;
	}
    
	Poly_t h{0};
	impl->hash(&h, id);
	// inverse h
	impl->inverse_poly(&(impl->h_1), h);
	// compute a_id
	impl->compute_a_id(impl->a_id, h);
}

/* @Override */
Ibe::User::~User(void) noexcept {

}


/* @override */
void Ibe::User::extractPrivateKey(const NFL_POLY_COEF_TYPE id) const noexcept {
    Poly_t h{0};
    impl->hash(&h, id);
    //t没有用
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
	// prepare the plaintext
	Poly_t plaintext{msg};
	for (auto & plaintext_i : plaintext.poly_obj()) {
		plaintext_i *= (impl->modulus/2);
    }//compute q/2*m

    plaintext.ntt_pow_phi();//ntt_pow_phi() corresponds to invntt_pow_invphi()
     
    Poly_t s = nfl::uniform();
    Gauss_t noise1 = *(impl->gaussianNoises.get());
    s.set(noise1);
    s.ntt_pow_phi();
	
    // gaussian noise e0
    const Poly_t * A_idIndex = impl->encryption_a_id;//设置另外的id后的数
    
    
    const Poly_t * sk_id = impl->sk;
    const Poly_t * sk = impl->sk;
    
    const Poly_t * A_id = impl->encryption_a_id;
    Gauss_t noiseE0 = *(impl->gaussianNoiseE0.get());
    for(uint32_t i = 0; i < impl->m - impl->param; ++i) {//about dimension=impl->m - impl->param
    	output->set(noiseE0);//original
       
        output->ntt_pow_phi();
        
        bx1=bx1+(*sk_id)*(*output) ;
       
    	*output = *output + s*(*A_idIndex);
        
        
        ++sk_id;
    	++output;
    	++A_idIndex;
    }
    
    Gauss_t noiseE1 = *(impl->gaussianNoiseE1.get());
    for(uint32_t i = 0; i < impl->param; ++i) {
    	output->set(noiseE1);
        
    	output->ntt_pow_phi();
       
    	*output = *output + s*(*A_idIndex);
      	++sk_id;
    	++output;
    	++A_idIndex;
    }
    
    // final
    Gauss_t noiseE2 = *(impl->gaussianNoiseE2.get());
	output->set(noiseE2);
   
	output->ntt_pow_phi();
    
	*output = *output + (impl->mpkU+impl->t)*s + plaintext;//compute c=u*s+e2+q/2*m,and the dimension = 1.original
}


/* @override */
void Ibe::User::decrypt(Poly_t * output, const Poly_t * cipher) const noexcept {
	Poly_t bx{0};
    Poly_t test{0};
	const Poly_t * sk_id = impl->sk;
   
	for(uint32_t i = 0; i < impl->m; ++i) {
		bx = bx + (*sk_id)*(*cipher);
		++sk_id;
		++cipher;
	} 
	*output = *cipher - bx;
	output->invntt_pow_invphi();
   
	const uint64_t modulus_4  = impl->modulus /4;
	const uint64_t modulus_34 = 3*modulus_4;
	for(auto & output_i : output->poly_obj()) {
        output_i=output_i%impl->modulus;
		output_i = ((output_i >= modulus_4) && output_i <= modulus_34) ? 1 : 0;
	}

}


/* Public Interface End ------------------------------------------------------------------------------ */
/* --------------------------------------------------------------------------------------------------- */