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

int calculate_augmented_pubkey(int peer, uint32_t s[1024],  FFT_CTX *ctx){ 
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
	
	if (peer==2){	// peer N-1
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);		
#endif	
		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[0][t]; // tmp1=z[0];
			tmp2[t]=pub_keys[1][t]; // tmp2=z[1];
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
			tmp1[t]=pub_keys[1][t]; // tmp1=z[1];
			tmp2[t]=pub_keys[2][t]; // tmp2=z[2];
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
			tmp1[t]=pub_keys[2][t];
			tmp2[t]=pub_keys[0][t];
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


int calculate_reconcile(uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx){
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
		tmp[t]=pub_keys[1][t]; // tmp=z[1]
		tmp2[t]=augmented_pub_keys[2][t]; // tmp=X[2]
	}

	FFT_mul(tmp, tmp, s, ctx); // tmp=z[1] * s_eve
	FFT_add(tmp, tmp, tmp2); // tmp=tmp+[2]
	FFT_add(tmp, tmp, e); // tmp=tmp+error
	
	for(int k=0; k<1024; k++){
		Y[2][k]=tmp[k]; // Y[N-1]=tmp 값
		tmp2[k]=augmented_pub_keys[0][k]; // tmp2=X[0]
	}
	
	FFT_add(tmp, tmp, tmp2); // calculate Y[0]
	for(int k=0; k<1024; k++){
		Y[0][k]=tmp[k];
		tmp2[k]=augmented_pub_keys[1][k]; // tmp2=X_1
	}
	
	
	FFT_add(tmp, tmp, tmp2); // calculate Y[1]
	for(int k=0; k<1024; k++){
		Y[1][k]=tmp[k];
	}
	
    for (int i = 0; i < 3; i++) // calculate b
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

// alice (0) 세션 키 계산
int calculate_session_key_alice(uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx){
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 
	

	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[2][t]; // tmp=z[2]
		tmp2[t]=augmented_pub_keys[0][t]; // tmp2=X[0]
	}
	
	FFT_mul(tmp, tmp, s, ctx); // tmp=z[2]*s_alice
	FFT_add(tmp, tmp2, tmp); // tmp=X[0]+tmp
	
	for(int t=0; t<1024; t++){
		Y[0][t]=tmp[t]; // Y[0] 저장 (tmp)
		tmp2[t]=augmented_pub_keys[1][t]; // tmp2=X[1]
	}
	
	FFT_add(tmp, tmp, tmp2); // Y[0]+X[1]
	for(int t=0; t<1024; t++){
		Y[1][t]=tmp[t]; // Y[1] 저장 (tmp)
		tmp2[t]=augmented_pub_keys[2][t]; // tmp2=X[2]
	}

	FFT_add(tmp, tmp, tmp2); // Y[1]+X[2]
	for(int t=0; t<1024; t++){
		Y[2][t]=tmp[t]; // Y[1] 저장 (tmp)
	}
	
	uint32_t result[1024]={0,};
    for (int i = 0; i < 3; i++) // calculate b
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp=Y[i]
		}
        FFT_add(result, result, tmp);
    }


#if CONSTANT_TIME
	rlwe_rec_ct(k, result, rec);
#else
	rlwe_rec(k, result, rec);
#endif

	// SHA-3 hash_session_key(uint32_t sk[1024], uint32_t result[1024])

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	return 1;
}

// bob (1) 세션 키 계산
int calculate_session_key_bob(uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx){
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 
	

	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[0][t]; // tmp=z[0]
		tmp2[t]=augmented_pub_keys[1][t]; // tmp2=X[1]
	}
	
	FFT_mul(tmp, tmp, s, ctx); // tmp=z[0]*s_bob
	FFT_add(tmp, tmp2, tmp); // tmp=X[1]+tmp
	
	for(int t=0; t<1024; t++){
		Y[1][t]=tmp[t]; // Y[1] 저장 (tmp)
		tmp2[t]=augmented_pub_keys[2][t]; // tmp2=X[2]
	}
	
	FFT_add(tmp, tmp, tmp2); // Y[1]+X[2]
	for(int t=0; t<1024; t++){
		Y[2][t]=tmp[t]; // Y[2] 저장 (tmp)
		tmp2[t]=augmented_pub_keys[0][t]; // tmp2=X[0]
	}

	FFT_add(tmp, tmp, tmp2); // Y[2]+X[0]
	for(int t=0; t<1024; t++){
		Y[0][t]=tmp[t]; // Y[1] 저장 (tmp)
	}
	
	uint32_t result[1024]={0,};
    for (int i = 0; i < 3; i++) // calculate b
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp=Y[i]
		}
        FFT_add(result, result, tmp);
    }


#if CONSTANT_TIME
	rlwe_rec_ct(k, result, rec);
#else
	rlwe_rec(k, result, rec);
#endif

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	return 1;
}



int main(){
	uint32_t *a = rlwe_a; // 'a' is a predefined public rlwe instance
	uint32_t s_alice[1024]; // n=1024
	uint32_t s_bob[1024];
	uint32_t s_eve[1024];
	
	uint64_t rec[16];
	uint64_t k_alice[16];
	uint64_t k_bob[16];
	uint64_t k_eve[16];

	FFT_CTX ctx;
	if (!FFT_CTX_init(&ctx)) {
		printf("Memory allocation error.");
		return -1;
	}
	
	
	calculate_pubkey(0, a, s_alice, &ctx); 
	calculate_pubkey(1, a, s_bob, &ctx);
	calculate_pubkey(2, a, s_eve, &ctx);
		
	// rlwe_kex_compute_key_bob(pub_keys[0], s_bob, rec, k_bob, &ctx);
	// rlwe_kex_compute_key_alice(pub_keys[1], s_alice, rec, k_alice, &ctx); // 여기까지는 제대로 계산 됨.
	
	
	calculate_augmented_pubkey(0,s_alice, &ctx);
	calculate_augmented_pubkey(1,s_bob, &ctx);
	calculate_augmented_pubkey(2,s_eve, &ctx);
	
	calculate_reconcile(s_eve, rec, k_eve, &ctx);
	calculate_session_key_alice(s_alice, rec, k_alice, &ctx);
	calculate_session_key_bob(s_bob, rec, k_bob, &ctx);

	int keys_match = 1;
	for (int i = 0; i < 16; i++) {
		keys_match &= (k_eve[i] == k_alice[i]);
		keys_match &= (k_bob[i] == k_alice[i]);
		keys_match &= (k_eve[i] == k_bob[i]);
	}
	
	
	if (keys_match) {
		printf("Keys match.\n");
	} else {
		printf("Keys don't match! :(\n");
		FFT_CTX_free(&ctx);
		return -1;
	}

	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);
	
	return 0;
}


	
