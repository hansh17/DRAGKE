#include <stdio.h>

#include "fft.h"
#include "rlwe.h"
#include "rlwe_rand.h"

void print_poly(uint32_t p[1024], int len)
{
    if (len > 1024)
        return;

    for (int i = 0; i < len; i++)
    {
        printf("%d ", p[i]);
    }
    printf("\n");
}

int main(void)
{
    uint32_t a[1024];
    uint32_t b[1024];

    RAND_CTX rand_ctx;
    int ret = RAND_CHOICE_init(&rand_ctx);
    if (!ret)
        return ret;

#if CONSTANT_TIME
    rlwe_sample_ct(a, &rand_ctx);
#else
    rlwe_sample(a, &rand_ctx);
#endif

    RAND_CHOICE_cleanup(&rand_ctx);
    ret = RAND_CHOICE_init(&rand_ctx);
    if (!ret)
        return ret;

#if CONSTANT_TIME
    rlwe_sample_ct(b, &rand_ctx);
#else
    rlwe_sample(b, &rand_ctx);
#endif

    print_poly(a, 10);
    print_poly(b, 10);

    uint32_t result[1024];
    FFT_add(result, a, b);
    print_poly(result, 10);

    RAND_CHOICE_cleanup(&rand_ctx);
    return 0;
}