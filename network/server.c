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

#define BUFF_SIZE 1024
#define _CRT_SECURE_NO_WARNINGS

int rlwe_kex_generate_keypair(const uint32_t *a, uint32_t s[1024], uint32_t b[1024], FFT_CTX *ctx) {
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
	rlwe_key_gen(b, a, s, e, ctx); // b=as+e
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
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


//read peer i's public value
/*
void read_public_value(int i){
		FILE *fp=fopen("PublicValue.txt", "r");
		/*
		fscanf(fp, "Peer %d's Public Value\n", i); 
		for (int i=0;i<1023;i++){
			fprintf(fp, "%lu\t", pub_val[i]);
		}
		fprintf(fp, "%lu\n", pub_val[1023]);
		fclose(fp);
	
}*/

int main(){
	uint32_t *a = rlwe_a; // 'a' is a predefined public rlwe instance
	uint32_t s_alice[1024]; // n=1024
	uint32_t b_alice[1024];
	uint32_t s_bob[1024];
	uint32_t b_bob[1024];

	FFT_CTX ctx;
	if (!FFT_CTX_init(&ctx)) {
		printf("Memory allocation error.");
		return -1;
	}

	rlwe_kex_generate_keypair(a, s_alice, b_alice, &ctx); // b_alice=a*s_alice+e_alice
	rlwe_kex_generate_keypair(a, s_bob, b_bob, &ctx); // b_bob=a*s_bob+e_alice

	save_public_value(1,b_alice);
	save_public_value(2,b_bob);

	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);

}


	
