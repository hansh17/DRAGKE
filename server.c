#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "fft.h"
#include "rlwe.h"
#include "rlwe_rand.h"

#define MAX_PEER 10
#define POLY_LEN 1024
#define KEY_LEN  16

bool check_augmented_pub_keys[MAX_PEER];

uint32_t sec_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];
uint64_t session_keys[MAX_PEER][KEY_LEN];

uint64_t reconcile[KEY_LEN];

void poly_init(int num_peer);
//void calculate_reconcile(void);
int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx);
void run_server(int num_peer, int server_port);

void poly_init(int num_peer)
{
    if (num_peer > MAX_PEER)
    {
        printf("Maximum peer number is %d\n", MAX_PEER);
        return;
    }

    RAND_CTX rand_ctx;
    for (int i = 0; i < num_peer; i++)
    {
        RAND_CHOICE_init(&rand_ctx);
#if CONSTANT_TIME
        rlwe_sample_ct(pub_keys[i], &rand_ctx);
#else
        rlwe_sample(pub_keys[i], &rand_ctx);
#endif
        RAND_CHOICE_cleanup(&rand_ctx);
    }
}
/*
void calculate_reconcile(void)
{
    RAND_CTX rand_ctx;
    RAND_CHOICE_init(&rand_ctx);
#if CONSTANT_TIME
    rlwe_sample_ct(reconcile, &rand_ctx);
#else
    rlwe_sample(reconcile, &rand_ctx);
#endif
    RAND_CHOICE_cleanup(&rand_ctx);
}
*/
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


void run_server(int num_peer, int server_port)
{
    int server_socket;
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        printf("socket() error!\n");
        exit(1);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("bind() error!\n");
        exit(1);
    }

    if (listen(server_socket, 5) == -1)
    {
        printf("listen() error!\n");
        exit(1);
    }

    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_size;
    
    uint32_t result[POLY_LEN];
    int option_and_peer;

    memset(check_augmented_pub_keys, false, sizeof(check_augmented_pub_keys));
    bool reconcile_calculated = false;

    FFT_CTX ctx;
    FFT_CTX_init(&ctx);
    
    while (true)
    {
        client_addr_size = sizeof(client_addr);
        client_socket    = accept(server_socket, (struct sockaddr *)&client_addr,
                                  &client_addr_size);

        printf("connection success!\n");

        recv(client_socket, &option_and_peer, sizeof(option_and_peer), 0);
        int peer = option_and_peer >> 16;
        if (!(0 <= peer && peer < num_peer))
        {
            printf("peer number error\n");
            close(client_socket);
            continue;
        }

        if (!reconcile_calculated)
        {
            bool all_augmented_pub_keys = true;

            for (int i = 0; i < num_peer; i++)
            {
                if (!check_augmented_pub_keys[i])
                {
                    all_augmented_pub_keys = false;
                    break;
                }
            }

            if (all_augmented_pub_keys)
            {
                calculate_reconcile(num_peer, sec_keys[num_peer - 1], reconcile, session_keys[num_peer - 1], &ctx);
                reconcile_calculated = true;
            }
        }

        switch (option_and_peer & 0xffff)
        {
            case 0:
            {
                recv(client_socket, pub_keys[peer], POLY_LEN * sizeof(uint32_t), 0);
                recv(client_socket, sec_keys[peer], POLY_LEN * sizeof(uint32_t), 0);
                break;
            }
            case 1:
            {
                send(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                send(client_socket, sec_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                recv(client_socket, result, sizeof(result), 0);
                memcpy(augmented_pub_keys[peer], result, sizeof(augmented_pub_keys[peer]));
                check_augmented_pub_keys[peer] = true;
                printf("got new public key fine!!!\n");
                break;
            }
            case 2:
            {
                send(client_socket, augmented_pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                break;
            }
            case 3:
            {
                send(client_socket, reconcile, sizeof(reconcile), 0);
                printf("Reconcile       ");
                for (int i = 0; i < 3; i++)
                {
                    printf("%15lu", reconcile[i]);
                }
                printf("\n\n");

                send(client_socket, sec_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

                send(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                send(client_socket, augmented_pub_keys, sizeof(uint64_t) * num_peer * POLY_LEN, 0);

                recv(client_socket, session_keys[peer], sizeof(session_keys[peer]), 0);
                break;
            }
        }
        for (int i = 0; i < num_peer; i++)
        {
            printf("Sec key       %d", i);
            for (int j = 0; j < 3; j++)
                printf("%15u", sec_keys[i][j]);
            printf("\n");
        }
        printf("\n");
        for (int i = 0; i < num_peer; i++)
        {
            printf("Pub key       %d", i);
            for (int j = 0; j < 3; j++)
                printf("%15u", pub_keys[i][j]);
            printf("\n");
        }
        printf("\n");
        for (int i = 0; i < num_peer; i++)
        {
            printf("Pub key prime %d", i);
            for (int j = 0; j < 3; j++)
                printf("%15u", augmented_pub_keys[i][j]);
            printf("\n");
        }
        printf("\n");
        for (int i = 0; i < num_peer; i++)
        {
            printf("Session key   %d", i);
            for (int j = 0; j < 3; j++)
                printf("%30lu", session_keys[i][j]);
            printf("\n");
        }

        close(client_socket);
    }
}

int main(int argc, char *argv[])
{
    int num_peer = 3;
    //poly_init(num_peer);

    int server_port = 4000;
    char op;
    while ((op = getopt(argc, argv, "p:")) != -1)
    {
        switch (op)
        {
            case 'p':
                server_port = atoi(optarg);
                break;
        }
    }
    run_server(num_peer, server_port);
    return 0;
}