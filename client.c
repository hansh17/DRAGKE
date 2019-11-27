#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "fft.h"
#include "rlwe.h"
#include "rlwe_a.h"
#include "rlwe_rand.h"

#define MAX_PEER 10
#define POLY_LEN 1024
#define KEY_LEN  16

uint32_t sec_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];
uint64_t session_keys[MAX_PEER][KEY_LEN];

uint64_t reconcile[KEY_LEN];

void poly_init(int peer);
int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx);
int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx);
int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx);
void calculate_pub_key_prime(uint32_t result[POLY_LEN], int peer, int num_peer);

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

int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx){
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 
	
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[(peer+num_peer-1)%num_peer][t]; // tmp=z[peer-1]
		tmp2[t]=augmented_pub_keys[peer][t]; // tmp2=X[peer]
	}	
	
	FFT_mul(tmp, tmp, s, ctx); // tmp=z_i-1*s_i 
	FFT_add(tmp, tmp2, tmp); // tmp=X_i+tmp

	for(int t=0; t<1024; t++){
		Y[peer][t]=tmp[t]; // Y[i] 저장 (tmp)
		tmp2[t]=augmented_pub_keys[(peer+1)%num_peer][t]; // tmp2=X[peer+1]
	}
	
	for (int j=1; j<num_peer; j++){
		FFT_add(tmp, tmp, tmp2); // Y[i]=Y[i-1]+X[i]
		for(int t=0; t<1024; t++){
			Y[(peer+j)%num_peer][t]=tmp[t]; // Y[peer+j] 저장 (tmp)
			tmp2[t]=augmented_pub_keys[(peer+j+1)%num_peer][t]; // tmp2=X[peer+j+1]
		}
	}
	
	uint32_t result[1024]={0,};
    for (int i = 0; i < num_peer; i++) // calculate b
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

void poly_init(int peer)
{
    if (peer < 0 || peer > MAX_PEER)
    {
        printf("peer range error!\n");
        return;
    }

    RAND_CTX rand_ctx;
    RAND_CHOICE_init(&rand_ctx);
#if CONSTANT_TIME
    rlwe_sample_ct(pub_keys[peer], &rand_ctx);
#else
    rlwe_sample(pub_keys[peer], &rand_ctx);
#endif
    RAND_CHOICE_cleanup(&rand_ctx);
}

void calculate_pub_key_prime(uint32_t result[POLY_LEN], int peer, int num_peer)
{
    memset(result, 0, sizeof(uint32_t) * POLY_LEN);

    for (int i = 0; i < num_peer; i++)
    {
        if (i == peer)
            continue;
        FFT_add(result, result, pub_keys[i]);
    }
}

int main(int argc, char *argv[])
{
    int client_socket;
    client_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (client_socket == -1)
    {
        printf("socket() error!\n");
        exit(1);
    }

    struct sockaddr_in server_addr;
    char *server_ip = "127.0.0.1";
    int server_port = 4000;
    char op;
    int option = -1;
    int peer = -1;

    int num_peer = 3;
    while ((op = getopt(argc, argv, "h:p:o:w:")) != -1)
    {
        switch (op)
        {
            case 'h':
                server_ip   = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'o':
                option      = atoi(optarg);
                break;
            case 'w':
                peer        = atoi(optarg);
                break;
        }
    }
    if (!(0 <= option && option <= 3))
    {
        printf("option shoud be 0 <= option <= 2!\n");
        exit(1);
    }

    FFT_CTX ctx;
    FFT_CTX_init(&ctx);
    uint32_t sec_key[POLY_LEN];
    calculate_pubkey(peer, rlwe_a, sec_key, &ctx);
    //poly_init(peer);

    int option_and_peer = (peer << 16) | option;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("connect() error!\n");
        exit(1);
    }

    send(client_socket, &option_and_peer, sizeof(option_and_peer), 0);
    
    switch (option)
    {
        case 0:
        {
            send(client_socket, pub_keys[peer], sizeof(pub_keys[peer]), 0);
            send(client_socket, sec_key, sizeof(sec_key), 0);
            break;
        }
        case 1:
        {
            recv(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

            recv(client_socket, sec_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

            //uint32_t result[POLY_LEN];
            calculate_augmented_pubkey(peer, num_peer, sec_keys[peer], &ctx);

            send(client_socket, augmented_pub_keys[peer], sizeof(augmented_pub_keys[peer]), 0);
            break;
        }
        case 2:
        {
            recv(client_socket, augmented_pub_keys, sizeof(augmented_pub_keys), 0);

            for (int i = 0; i < num_peer; i++)
            {
                for (int j = 0; j < 3; j++)
                    printf("%15u", augmented_pub_keys[i][j]);
                printf("\n");
            }

            break;
        }
        case 3:
        {
            recv(client_socket, reconcile, sizeof(reconcile), 0);
            printf("Reconcile       ");
            for (int i = 0; i < 3; i++)
            {
                printf("%15lu", reconcile[i]);
            }
            printf("\n");

            recv(client_socket, sec_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

            recv(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
            recv(client_socket, augmented_pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

            uint64_t result[KEY_LEN];
            calculate_session_key(peer, num_peer, sec_keys[peer], reconcile, result, &ctx);
            send(client_socket, result, sizeof(result), 0);
            break;
        }
        default:
        {
            printf("unkonwn option!\n");
            break;
        }
    }

    close(client_socket);
    return 0;
}