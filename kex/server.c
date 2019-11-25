#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../rlwe.h"
#include "../fft.h"
#include "../rlwe_rand.h"
#include "../rlwe_a.h"
#include "../rlwe_kex.h"

#define _CRT_SECURE_NO_WARNINGS
#define MAX_PEER 10
#define POLY_LEN 1024

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx) {
	if (peer < 0 || peer > MAX_PEER){
        printf("peer range error!\n");
        return -1;
    }
    
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
#if CONSTANT_TIME
	rlwe_sample_ct(s, &rand_ctx);
	rlwe_sample_ct(e, &rand_ctx);
#else
	rlwe_sample(s, &rand_ctx);
	rlwe_sample(e, &rand_ctx);
#endif
	
	uint32_t tmp[1024];
	rlwe_key_gen(tmp, a, s, e, ctx); // tmp에 as+e 저장
	for(int t=0; t<1024; t++){
		pub_keys[peer][t]=tmp[t];
	}
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx){ 
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}

	uint32_t result[1024]={0,};
	uint32_t tmp1[1024];
	uint32_t tmp2[1024];
	
	if (peer==num_peer-1){	// peer N-1
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);		
#endif	
		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[0][t]; // tmp1=pub_keys[0];
			tmp2[t]=pub_keys[peer-1][t]; // tmp2=pub_keys[peer-1];
		}

		FFT_sub(result, tmp1, tmp2); // z[0]-z[1]
		FFT_mul(result, result, s, ctx); // res*s_eve
		FFT_add(result, result, e);	
	}
	
	else if (peer==0){ // peer 0
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx); // sample from sigma2
#else
		rlwe_sample(e, &rand_ctx); // sample from sigma2
#endif	
		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[peer+1][t]; // peer=0인 경우 pub_keys[1]
			tmp2[t]=pub_keys[num_peer-1][t]; // pub_keys[N-1]
		}
		
		FFT_sub(result, tmp1, tmp2); // z[1]-z[2]
		FFT_mul(result, result, s, ctx); // res*s_alice
		FFT_add(result, result, e);
	}
	
	else{ // other peers
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);
#endif	

		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[peer+1][t];
			tmp2[t]=pub_keys[peer-1][t];
		}		
		
		FFT_sub(result, tmp1, tmp2); // res=z[2] - z[0]
		FFT_mul(result, result, s, ctx); // res= res* s_bob
		FFT_add(result, result, e); // res= res+e
	}
	
	for(int t=0; t<1024; t++){
		augmented_pub_keys[peer][t]=result[t]; // X[i] save
	}
	
	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp1, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx){
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
	
	uint32_t result[1024]={0,};	
#if CONSTANT_TIME
	rlwe_sample_ct(e, &rand_ctx);
#else
	rlwe_sample(e, &rand_ctx);
#endif	
	
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024];
	
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[num_peer-2][t]; // tmp=z_N-2
		tmp2[t]=augmented_pub_keys[num_peer-1][t]; // tmp=X_N-1
	}

	FFT_mul(tmp, tmp, s, ctx); // tmp=z_n-2 * s_n-1
	FFT_add(tmp, tmp, tmp2); // tmp=tmp+X_N-1
	FFT_add(tmp, tmp, e); // tmp=tmp+error
	
	for(int k=0; k<1024; k++){
		Y[num_peer-1][k]=tmp[k]; // Y[N-1]=tmp 값
		tmp2[k]=augmented_pub_keys[0][k]; // tmp2=X_0
	}
	
	FFT_add(tmp, tmp, tmp2); // calculate Y[0]
	for(int k=0; k<1024; k++){
		Y[0][k]=tmp[k];
		tmp2[k]=augmented_pub_keys[1][k]; // tmp2=X_1
	}
	
	
	for (int j=1; j<num_peer-1; j++){
		FFT_add(tmp, tmp, tmp2); // calculate Y[j-1] + X[j]
		for(int k=0; k<1024; k++){
			Y[j][k]=tmp[k]; // Y[j]=tmp
			tmp2[k]=augmented_pub_keys[j+1][k]; // tmp2=X_j+1
		}
	}
	
    for (int i = 0; i < num_peer; i++) // calculate b
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp=Y[i]
		}
        FFT_add(result, result, tmp); 
    }

#if CONSTANT_TIME // reconcile message b -> rec, k_n-1 is calculated
	rlwe_crossround2_ct(rec, result, &rand_ctx);
	rlwe_round2_ct(k, result);
#else
	rlwe_crossround2(rec, result, &rand_ctx);
	rlwe_round2(k, result);
#endif	
	// SHA-3 hash_session_key(uint32_t sk[1024], uint32_t result[1024])
	
	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}


/*
void hash_session_key(uint32_t k[1024], uint32_t s[1024]){
	EVP_MD_CTX *mdctx;
	if((mdctx = EVP_MD_CTX_new()) == NULL){
		handleErrors();}
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL)){
		handleErrors();}
	if(1 != EVP_DigestUpdate(mdctx, s, 1024)){
		handleErrors();}
	if((k = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha3_512()))) == NULL){
		handleErrors();}
	if(1 != EVP_DigestFinal_ex(mdctx, k, 1024)){
		handleErrors();}
	EVP_MD_CTX_free(mdctx);
}*/