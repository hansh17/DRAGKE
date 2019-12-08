#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../fft.h"
#include "../rlwe.h"
#include "../rlwe_rand.h"
#include "../rlwe_a.h"
#include "../rlwe_table2.h"

#define setbit(a,x) ((a)[(x)/64] |= (((uint64_t) 1) << (uint64_t) ((x)%64)))
#define getbit(a,x) (((a)[(x)/64] >> (uint64_t) ((x)%64)) & 1)
#define clearbit(a,x) ((a)[(x)/64] &= ((~((uint64_t) 0)) - (((uint64_t) 1) << (uint64_t) ((x)%64))))

/* Auxiliary functions for constant-time comparison */

/*
 * Returns 1 if x != 0
 * Returns 0 if x == 0
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_isnonzero_u64(uint64_t x) {
	return (x | -x) >> 63;
}

/*
 * Returns 1 if x != y
 * Returns 0 if x == y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_ne_u64(uint64_t x, uint64_t y) {
	return ((x - y) | (y - x)) >> 63;
}

/*
 * Returns 1 if x == y
 * Returns 0 if x != y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_eq_u64(uint64_t x, uint64_t y) {
	return 1 ^ ct_ne_u64(x, y);
}

/* Returns 1 if x < y
 * Returns 0 if x >= y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_lt_u64(uint64_t x, uint64_t y) {
	return (x ^ ((x ^ y) | ((x - y)^y))) >> 63;
}

/*
 * Returns 1 if x > y
 * Returns 0 if x <= y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_gt_u64(uint64_t x, uint64_t y) {
	return ct_lt_u64(y, x);
}

/*
 * Returns 1 if x <= y
 * Returns 0 if x > y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_le_u64(uint64_t x, uint64_t y) {
	return 1 ^ ct_gt_u64(x, y);
}

/*
 * Returns 1 if x >= y
 * Returns 0 if x < y
 * x and y are arbitrary unsigned 64-bit integers
 */
static uint64_t ct_ge_u64(uint64_t x, uint64_t y) {
	return 1 ^ ct_lt_u64(x, y);
}

/* Returns 0xFFFF..FFFF if bit != 0
 * Returns            0 if bit == 0
 */
static uint64_t ct_mask_u64(uint64_t bit) {
	return 0 - (uint64_t)ct_isnonzero_u64(bit);
}

/* Conditionally return x or y depending on whether bit is set
 * Equivalent to: return bit ? x : y
 * x and y are arbitrary 64-bit unsigned integers
 * bit must be either 0 or 1.
 */
static uint64_t ct_select_u64(uint64_t x, uint64_t y, uint64_t bit) {
	uint64_t m = ct_mask_u64(bit);
	return (x & m) | (y & ~m);
}

/* Returns 0 if a >= b
 * Returns 1 if a < b
 * Where a and b are both 3-limb 64-bit integers.
 * This function runs in constant time.
 */
static int cmplt_ct(uint64_t *a, uint64_t *b) {
	uint64_t r = 0; /* result */
	uint64_t m = 0; /* mask   */
	int i;
	for (i = 2; i >= 0; --i) {
		r |= ct_lt_u64(a[i], b[i]) & ~m;
		m |= ct_mask_u64(ct_ne_u64(a[i], b[i])); /* stop when a[i] != b[i] */
	}
	return r & 1;
}

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
	rlwe_key_gen(b, a, s, e, ctx);
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int rlwe_kex_compute_key_alice(const uint32_t b[1024], const uint32_t s[1024], const uint64_t c[16], uint64_t k[16], FFT_CTX *ctx) {
	uint32_t w[1024];
	FFT_mul(w, b, s, ctx);
#if CONSTANT_TIME
	rlwe_rec_ct(k, w, c);
#else
	rlwe_rec(k, w, c);
#endif
	rlwe_memset_volatile(w, 0, 1024 * sizeof(uint32_t));
	return 1;
}

int rlwe_kex_compute_key_bob(const uint32_t b[1024], const uint32_t s[1024], uint64_t c[16], uint64_t k[16], FFT_CTX *ctx) {
	int ret;
	uint32_t v[1024];
	uint32_t eprimeprime[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
#if CONSTANT_TIME
	rlwe_sample_ct(eprimeprime, &rand_ctx); // -> sample2_ct가 seg fault의 원인
#else
	rlwe_sample(eprimeprime, &rand_ctx);
#endif
	rlwe_key_gen(v, b, s, eprimeprime, ctx);
#if CONSTANT_TIME
	rlwe_crossround2_ct(c, v, &rand_ctx);
	rlwe_round2_ct(k, v);
#else
	rlwe_crossround2(c, v, &rand_ctx);
	rlwe_round2(k, v);
#endif
	rlwe_memset_volatile(v, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(eprimeprime, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

static int cmplt_ct2(uint64_t *a, uint64_t *b) {
	uint64_t r = 0; /* result */
	uint64_t m = 0; /* mask   */
	int i;
	r |= ct_lt_u64(a,b) & ~m;
	m |= ct_mask_u64(ct_ne_u64(a,b)); /* stop when a[i] != b[i] */
	
	return r & 1;
}

int main() {

	uint32_t *a = rlwe_a;
	uint32_t s_alice[1024];
	uint32_t b_alice[1024];
	uint32_t s_bob[1024];
	uint32_t b_bob[1024];
	uint64_t c[16];
	uint64_t k_alice[16];
	uint64_t k_bob[16];

	FFT_CTX ctx;
	if (!FFT_CTX_init(&ctx)) {
		printf("Memory allocation error.");
		return -1;
	}
	
	
	RAND_CTX rand_ctx;
	int ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
	rlwe_sample(s_alice, &rand_ctx);
	uint64_t rnd=RANDOM64(&rand_ctx);
	//printf("%lu", rnd);

	int i = 0;

	printf("%lu\n", rnd);
	printf("%lu\n", rlwe_table2[0]);	
	while (cmplt_ct2(rlwe_table2[i],rnd)) {
		i++;
	}
	printf("%d\n",i);

	/*
	rlwe_kex_generate_keypair(a, s_alice, b_alice, &ctx);
	rlwe_kex_generate_keypair(a, s_bob, b_bob, &ctx);

	rlwe_kex_compute_key_bob(b_alice, s_bob, c, k_bob, &ctx);
	rlwe_kex_compute_key_alice(b_bob, s_alice, c, k_alice, &ctx);

	
	int keys_match = 1;
	for (int i = 0; i < 16; i++) {
		keys_match &= (k_alice[i] == k_bob[i]);
	}
	if (keys_match) {
		printf("Keys match.\n");
	} else {
		printf("Keys don't match! :(\n");
		FFT_CTX_free(&ctx);
		return -1;
	}*/

	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);

	return 0;

}

