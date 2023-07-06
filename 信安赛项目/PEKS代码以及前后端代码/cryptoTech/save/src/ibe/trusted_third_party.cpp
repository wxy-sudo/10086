#include<cstdint>
#include<cmath>
#include<algorithm>
#include<memory>
#include<thread>
#include<nfl.hpp>
#include<fstream>

#include "gauss/gaussian.hpp"
#include "params.hpp"
#include "trusted_third_party.hpp"

using namespace Gaussian;

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
struct Ibe::TrustedParty::encapsulation {
	const uint32_t dimension; // n
	const uint32_t param;     // k
	const uint64_t modulus;   // q
	const uint32_t security;  // lambda
	double_t sigma;           // sigma
	uint32_t m; 		  	  // m


	 // Private key: (r, e) --> in NTT
	 Poly_t r[MAX_Q_BITS];
	 Poly_t e[MAX_Q_BITS];

	 // Public key: A, u
	 Poly_t u{nfl::uniform()};
	 Poly_t A[MAX_Q_BITS]; 

	// Gaussian
	std::unique_ptr<GaussianSampling> gaussianSampler;
	std::unique_ptr<Gauss_t> gaussianNoise;
	std::unique_ptr<fastGauss_t> fastGaussNoise;

	// SamplePre
	void samplePre(Poly_t * output, const Poly_t * a, const Poly_t & h_1, Poly_t & t) const noexcept;
};




void Ibe::TrustedParty::encapsulation::samplePre(Poly_t * output, const Poly_t * a, const Poly_t & h_1, Poly_t & t) const noexcept {
    //std::cout<<"SamplePre:"<< std::endl;
	const Poly_t * p = gaussianSampler->samplePz();//void
    //std::cout<<"p : "<<*p<<std::endl;//*
	// Pool of threads
	std::thread pool[THREADS_NUMBER];
	uint32_t thread_shares[THREADS_NUMBER]; 

	// compute v
	Poly_t v{0};
    
	const Poly_t * aIndex = a;
	const Poly_t * pIndex = p;
	for(uint32_t i = 0; i < m; ++i) {
		v = v + (*aIndex)*(*pIndex);
        //std::cout << "dimension: " << i<<" , a : "<<*aIndex<< std::endl; 
        //std::cout << "dimension: " << i<<" , p : "<<*pIndex<< std::endl; 
        //std::cout << "dimension: " << i<<" , v : "<<v<< std::endl; 
		++aIndex;
		++pIndex;
	}//v=a^T*p
   
    //std::cout<<"v   : "<<v<<std::endl;//*
    //std::cout<<"h_1 : "<<h_1<<std::endl;//*
    //std::cout<<"u : "<<u<<std::endl;//*
    //v=u-v;
    //std::cout<<"u-v : "<<v<<std::endl;//*
    //v=h_1*v;
    v = h_1*(u - v);//origin v=h^-1*(u-a^T*p)

    //std::cout<<"v : "<<v<<std::endl;//*
    
	// compute z
	uint64_t vCoefs[dimension];

	uint32_t index = 0;
	for(auto & v_i : v.poly_obj()) {
		vCoefs[index++] = (uint64_t) v_i;
	}
   
   
	Poly_t z[param];
	gaussianSampler->sampleGPoly(z, vCoefs);
   // std::cout<<"z : "<< *z<<std::endl;//*
   
    
    NFL_POLY_COEF_TYPE gi = 1;
    Poly_t gs[param];
	for(uint32_t i = 0; i < param; ++i) {
		gs[i].set(gi);
		gs[i].ntt_pow_phi();
        //std::cout<<"g: "<<gs[i]<<std::endl;
		gi <<= 1;
	}
   
    for(uint64_t i=0;i<param;i++){
        t=t+gs[i]*z[i];
       // std::cout<<"add: "<<add<<std::endl;
    }
    //add.invntt_pow_invphi();
    //std::cout<<"total-add: "<<t<<std::endl;
    t=t-v;
    //std::cout<<"g*z-v: "<<t<<std::endl;

	// lambda to compute ez, rz and x[2:]
	auto lambda2 = [](Poly_t * outputs, Poly_t * xis, const Poly_t * ei, const Poly_t * ri, const Poly_t * zi, const Poly_t * pi, const uint32_t length) {

		for(uint32_t i = 0; i < length; ++i) 
		{
			xis[i]     = pi[i] + zi[i];
			outputs[0] = outputs[0] + ei[i]*zi[i];
			outputs[1] = outputs[1] + ri[i]*zi[i];
            //std::cout<<i<<" : z[]="<< zi[i]<<std::endl;//*
            //std::cout<<i<<" : p[]="<< pi[i]<<std::endl;//*
		}
	};

	// Thread shares
	const uint32_t thread_share2 = param/THREADS_NUMBER;
	std::fill_n(thread_shares, THREADS_NUMBER, thread_share2);
	for(uint32_t i = 0; i < param - thread_share2*THREADS_NUMBER; ++i) {
		++thread_shares[i];
	}


	pIndex          = p + 2;
	Poly_t * xIndex = output + 2;
	const Poly_t * eIndex = e;
	const Poly_t * rIndex = r;
	const Poly_t * zIndex = z;
	Poly_t * erz = new Poly_t[THREADS_NUMBER*2]{0};
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		const uint32_t share = thread_shares[i];
		pool[i] = std::thread(lambda2, erz + i*2, xIndex, eIndex, rIndex, zIndex, pIndex, share);
		xIndex += share;
		eIndex += share;
		rIndex += share;
		zIndex += share;
		pIndex += share;
	}
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		pool[i].join();
	}


	// compute ez, rz and x[2:]
	Poly_t ez{0};
	Poly_t rz{0};
//	ez.ntt_pow_phi();
//	rz.ntt_pow_phi();
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		ez = ez + erz[i*2];
		rz = rz + erz[1 + i*2];
	}
	delete[] erz;

	// compute x
	output[0] = p[0] + ez;
	output[1] = p[1] + rz;
    //std::cout<<"sk0 :"<<output[0]<<std::endl;
    //std::cout<<"sk1 :"<<output[1]<<std::endl;

	delete[] p;
}




/* --------------------------------------------------------------------------------------------------- */
/* Public Interface ---------------------------------------------------------------------------------- */
/* @Override */
Ibe::TrustedParty::TrustedParty(const uint32_t n, const uint32_t k, const uint64_t q, const double_t sigma, const uint32_t lambda) noexcept : \
impl(new encapsulation {.dimension = n, .param = k, .modulus = q, .security = lambda}) {
	impl->sigma = sigma;
	impl->m = k + 2;


	// prebuild the Gaussian noise
	impl->fastGaussNoise.reset(new fastGauss_t(sigma, lambda, n));
	impl->gaussianNoise.reset(new Gauss_t(impl->fastGaussNoise.get()));

	// For the Public key
	impl->u.ntt_pow_phi();
    
	impl->A[0].set(1);
	impl->A[0].ntt_pow_phi();
}

/* @Override */
Ibe::TrustedParty::~TrustedParty(void) noexcept {

}


/* @Override */
void Ibe::TrustedParty::generateMasterKey(void) noexcept {
	// Get k
	const uint32_t k = impl->param;

	// compute a
	Poly_t a{nfl::uniform()};
	a.ntt_pow_phi();
    
    
    
	// Pool of threads
	std::thread pool[THREADS_NUMBER];

	// Thread shares
	uint32_t thread_shares[THREADS_NUMBER]; 
	const uint32_t thread_share = (k*2)/THREADS_NUMBER;
	std::fill_n(thread_shares, THREADS_NUMBER, thread_share);
	for(uint32_t i = 0; i < k*2 - thread_share*THREADS_NUMBER; ++i) {
		++thread_shares[i];
	}



	// Lambda for ^r and ê
	auto lambda1 = [this](Poly_t * output, const uint32_t length) {
		Gauss_t noise = *(impl->gaussianNoise.get());
		for(uint32_t i = 0; i < length; ++i) {
			output->set(noise);
			output->ntt_pow_phi();
            
			++output;
		}
	};

	// compute ^r
	Poly_t * rIndex = impl->r;
    
	for(uint32_t i = 0; i < THREADS_NUMBER/2; ++i) {
		pool[i] = std::thread(lambda1, rIndex, thread_shares[i]);
		rIndex += thread_shares[i];
	}
	
	//原先被注释
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		pool[i].join();
	}
	

	// compute ê
	Poly_t * eIndex = impl->e;
     
	for(uint32_t i = THREADS_NUMBER/2; i < THREADS_NUMBER; ++i) {
		pool[i] = std::thread(lambda1, eIndex, thread_shares[i]);
		eIndex += thread_shares[i];
	}
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		pool[i].join();
	}
    
	// Lambda for A
	auto lambda2 = [&a](Poly_t * output, const Poly_t * r, const Poly_t * e, const uint32_t length) {
		for(uint32_t i = 0; i < length; ++i) {
            //*output = - (a*(*r) + (*e));//original
			*output = *output-(a*(*r) + (*e));
            //std::cout << "dimension: " << i+2<<" and a': "<<a << std::endl;
            //std::cout << "dimension: " << i+2<<" and r : "<<*r << std::endl;
            //std::cout << "dimension: " << i+2<<" and e : "<<*e << std::endl;
            //std::cout << "dimension: " << i+2<<" and A : "<<*output << std::endl;
			++output;
			++r;
			++e;		
		}
	};


	// compute A
	rIndex = impl->r;
	eIndex = impl->e;
	Poly_t * AIndex = (impl->A + 2);//a=[a',-a'T],where T=[r,e],that is -a'T=-ar-e
     
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		const uint32_t share = thread_shares[i];
		pool[i]  = std::thread(lambda2, AIndex, rIndex, eIndex, share);
		AIndex  += share;
		rIndex  += share;
		eIndex  += share;
	}
	for(uint32_t i = 0; i < THREADS_NUMBER; ++i) {
		pool[i].join();
	}

	impl->A[1] = std::move(a);
        
}



/* @Override */
Poly_t * Ibe::TrustedParty::getPublicKey(Poly_t * pk) noexcept {
	memcpy(pk, &(impl->u), sizeof(Poly_t));
     
	return impl->A;
}

/* @Override */
void Ibe::TrustedParty::setGaussian(const double_t s) noexcept {
	impl->gaussianSampler.reset(new GaussianSampling(impl->dimension, impl->param, impl->modulus, impl->sigma, s, 2*impl->sigma, impl->security, impl->r, impl->e));//n,k,q,sigma=5,zeta=6360,alpha=10,lambda=80,r,e
    //std::cout << "Parameters" << std::endl;
    //std::cout << "n     :" << impl->dimension<<std::endl;
    //std::cout << "k     :" << impl->param<<std::endl;
    //std::cout << "q     :" << impl->modulus<<std::endl;
    //std::cout << "sigma :" << impl->sigma<<std::endl;
    //std::cout << "zeta  :" << s<<std::endl;
    //std::cout << "alpha :" << 2*impl->sigma<<std::endl;
    //std::cout << "lambda:" << impl->security<<std::endl;
	//std::cout << "End of gaussian" << std::endl;
}


/* @Override */
void Ibe::TrustedParty::preCompute(const uint32_t n) noexcept {
	impl->gaussianSampler->preCompute(n);
}

/* @Override */
void Ibe::TrustedParty::extract(Poly_t * output, const Poly_t * a, const Poly_t & h_1, Poly_t & t) const noexcept {
	impl->samplePre(output, a, h_1,t);
}

//load key from file
void Ibe::TrustedParty::loadMasterKey(void) noexcept {
	std::ifstream mpkA("/home/karloz/Desktop/cryptoTech/masterKey/mpkA.txt");
	std::ifstream mpkU("/home/karloz/Desktop/cryptoTech/masterKey/mpkU.txt");
	std::ifstream mskR("/home/karloz/Desktop/cryptoTech/masterKey/mskR.txt");
	std::ifstream mskE("/home/karloz/Desktop/cryptoTech/masterKey/mskE.txt");

	//printf("Loading master key\n");

	for(int i=0;i<MAX_Q_BITS;++i)
	{
		for(auto &a_i : impl->A[i].poly_obj()) {
			mpkA >> a_i;
		}
	}

	//printf("A loaded\n");

	for(auto &u_i : impl->u.poly_obj()) {
		mpkU >> u_i ;
	}

	//printf("U loaded\n");

	for(int i=0;i<MAX_Q_BITS;++i)
	{
		for(auto &r_i : impl->r[i].poly_obj()) {
			mskR >> r_i;
		}
	}

	//printf("R loaded\n");

	for(int i=0;i<MAX_Q_BITS;++i)
	{
		for(auto &e_i : impl->e[i].poly_obj()) {
			mskE >> e_i;
		}
	}

	//printf("E loaded\n");

}

/* Public Interface End ------------------------------------------------------------------------------ */
/* --------------------------------------------------------------------------------------------------- */