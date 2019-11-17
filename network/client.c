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

#define _CRT_SECURE_NO_WARNINGS
#define MAX_PEER 10
#define POLY_LEN 1024

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], uint32_t pub_keys, FFT_CTX *ctx) {
	if (peer < 0 || peer > MAX_PEER){
        printf("peer range error!\n");
        return;
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
	rlwe_key_gen(pub_keys[peer], a, s, e, ctx); // pub_keys[peer]=as+e
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_augmented_pubkey(uint32_t result[1024], uint32_t s[1024], int peer, int num_peer, FFT_CTX *ctx){
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}

	memset(result, 0, sizeof(uint32_t) * 1024);
		
	if (peer==num_peer-1){	// peer N-1
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);		
		
		FFT_sub(result, pub_keys[0], pub_keys[peer-1]);
		FFT_mul(result, result, s, ctx);
		FFT_add(result, result, e);	
	}
	
	else if (peer==0){ // peer 0
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx); // sample from sigma2
#else
		rlwe_sample(e, &rand_ctx); // sample from sigma2
		
		FFT_sub(result, pub_keys[peer+1], pub_keys[num_peer-1]);
		FFT_mul(result, result, s, ctx);
		FFT_add(result, result, e);
	}
	
	else{ // other peers
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);
		
		FFT_sub(result, pub_keys[peer+1], pub_keys[peer-1]); // res=z_i+1 - z_i-1
		FFT_mul(result, result, s, ctx); // res= res* s_i
		FFT_add(result, result, e); // res= res+e
	}
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}


int calculate_reconcile(uint32_t result[1024], uint32_t s[1024], uint64_t rec[16], uint64_t k[16], int num_peer, FFT_CTX *ctx){
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}

	memset(result, 0, sizeof(uint32_t) * 1024);		
#if CONSTANT_TIME
	rlwe_sample_ct(e, &rand_ctx);
#else
	rlwe_sample(e, &rand_ctx);
	
	
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
		
	FFT_mul(tmp, pub_keys[num_peer-2], s, ctx); // tmp=z_n-2 * s_n-1 
	FFT_add(tmp, augmented_pub_keys[num_peer-1], tmp); // tmp=X_n-1+tmp
	FFT_add(Y[num_peer-1], tmp, e); // +error
	
	FFT_add(Y[0], Y[num_peer-1], augmented_pub_keys[0]); // calculate Y_n-1,0
	
	for (int j=1; j<num_peer-1; j++){
		FFT_add(Y[j], Y[j-1], augmented_pub_keys[j]); // calculate Y_n-1,j
	}
	
    for (int i = 0; i < num_peer; i++) // calculate b
    {
        FFT_add(result, result, Y[i]);
    }

#if CONSTANT_TIME // reconcile message b -> rec, k_n-1 is calculated
	rlwe_crossround2_ct(rec, result, &rand_ctx);
	rlwe_round2_ct(k, v);
#else
	rlwe_crossround2(rec, result, &rand_ctx);
	rlwe_round2(k, v);
	
	// SHA-3 hash_session_key(uint32_t sk[1024], uint32_t result[1024])
	
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_session_key(uint32_t result[1024], uint32_t s[1024], uint64_t rec[16], uint64_t k[16], int peer, int num_peer){

	memset(result, 0, sizeof(uint32_t) * 1024);		
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
		
	FFT_mul(tmp, pub_keys[peer-1], s, ctx); // tmp=z_i-1*s_i 
	FFT_add(tmp, augmented_pub_keys[peer], tmp); // tmp=X_i+tmp
	
	for (int j=1; j<num_peer; j++){
		FFT_add(Y[j], Y[j-1], augmented_pub_keys[j]); // calculate Y_n-1,j
	}
	
    for (int i = 0; i < num_peer; i++) // calculate b
    {
        FFT_add(result, result, Y[i]);
    }

#if CONSTANT_TIME
	rlwe_rec_ct(k, result, rec);
#else
	rlwe_rec(k, result, rec);
#endif

	// SHA-3 hash_session_key(uint32_t sk[1024], uint32_t result[1024])

	return 1;
}


// Save RLWE instance on PublicValue.txt, "append poly to existing file"
void save_public_value(int i, uint32_t pub_val[1024]){
		FILE *fp=fopen("PublicValue.txt", "a");

		fprintf(fp, "Peer %d's Public Value\n", i); 
		for (int i=0;i<1023;i++){
			fprintf(fp, "%lu\t", pub_val[i]);
		}
		fprintf(fp, "%lu\n", pub_val[1023]);
		fclose(fp);
	
}


// Save RLWE instance on PublicValue.txt, "append poly to existing file"
void save_public_value(int i, uint32_t pub_val[1024]){
		FILE *fp=fopen("PublicValue.txt", "a");

		fprintf(fp, "Peer %d's Public Value\n", i); 
		for (int i=0;i<1023;i++){
			fprintf(fp, "%lu\t", pub_val[i]);
		}
		fprintf(fp, "%lu\n", pub_val[1023]);
		fclose(fp);
	
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

int main(){
	uint32_t *a = rlwe_a; // 'a' is a predefined public rlwe instance
	uint32_t s_alice[1024]; // n=1024
	uint32_t b_alice[1024];
	uint32_t s_bob[1024];
	uint32_t b_bob[1024];
	uint32_t k_bob[1024];

	FFT_CTX ctx;
	if (!FFT_CTX_init(&ctx)) {
		printf("Memory allocation error.");
		return -1;
	}

	calculate_pubkey(a, s_alice, b_alice, &ctx); // b_alice=a*s_alice+e_alice
	calculate_pubkey(a, s_bob, b_bob, &ctx); // b_bob=a*s_bob+e_alice


	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);

}


	
