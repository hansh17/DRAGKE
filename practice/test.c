#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../rlwe.h"
#include "../fft.h"
#include "../rlwe_rand.h"
#include "../rlwe_a.h"


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

	uint32_t z[1024];
	FFT_add(z, b_bob, b_alice); // z=b_bob+b_alice (polynomial addition);
	
	int t=1;
	int cnt=0;
	for(int i=0;i<1024;i++){
		if(b_bob[i]+b_alice[i]!=z[i]){
			t=0;
			cnt+=1;
		}
	}
	printf("%d\n",cnt);
	if(t==1){
			printf("Modular operation isn't exist.\n");
	}
	else{
			printf("Modular operation is performed.\n");
	}
	
	
	for(int i=0;i<1024;i++){
		printf("%dth number is %d\n",i,z[i]);
	}

	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);

	return 0;

}
