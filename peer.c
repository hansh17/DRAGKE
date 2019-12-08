#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdint.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "fft.h"
#include "rlwe.h"
#include "rlwe_a.h"
#include "rlwe_rand.h"

#define MAX_PEER 10
#define POLY_LEN 1024
#define KEY_LEN  16
#define HASH_LEN 129

uint32_t sec_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];
uint64_t session_keys[MAX_PEER][KEY_LEN];
unsigned char hashed_keys[MAX_PEER][HASH_LEN];

uint64_t reconcile[KEY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx);
int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx);
int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);

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
		rlwe_sample2_ct(e, &rand_ctx); // sample from sigma2
#else
		rlwe_sample2(e, &rand_ctx); // sample from sigma2
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

void sha512_session_key(uint64_t *in, char outputBuffer[129])
{
    unsigned char hash[SHA512_DIGEST_LENGTH]; // 64
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, in, 8*16);
    SHA512_Final(hash, &sha512);
    int i = 0;
    for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[128]=0;
}


int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){
		
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
	sha512_session_key(k, hk);

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	return 1;
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

    int num_peer = 5;
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
    /*
    if (!(0 <= option && option <= 3))
    {
        printf("option shoud be 0 <= option <= 2!\n");
        exit(1);
    }
    */

    FFT_CTX ctx;
    FFT_CTX_init(&ctx);

    //int option_and_peer = (peer << 16) | option;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("connect() error!\n");
        exit(1);
    }

    //send(client_socket, &option_and_peer, sizeof(option_and_peer), 0);
    while (true)
    {
        send(client_socket, &peer, sizeof(peer), 0);
        recv(client_socket, &option, sizeof(option), 0);

        if (option > 3)
            break;

        switch (option)
        {
            case 0:
            {
                calculate_pubkey(peer, rlwe_a, sec_keys[peer], &ctx);
                send(client_socket, pub_keys[peer], sizeof(pub_keys[peer]), 0);
                break;
            }
            case 1:
            {
                recv(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

                calculate_augmented_pubkey(peer, num_peer, sec_keys[peer], &ctx);

                send(client_socket, augmented_pub_keys[peer], sizeof(augmented_pub_keys[peer]), 0);
                break;
            }
            case 2:
            {
                recv(client_socket, augmented_pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                break;
            }
            case 3:
            {
                recv(client_socket, reconcile, sizeof(reconcile), 0);

                uint64_t result[KEY_LEN];
		unsigned char hashed_result[HASH_LEN];
                calculate_session_key(peer, num_peer, sec_keys[peer], reconcile, result, hashed_result, &ctx);
                //send(client_socket, result, sizeof(result), 0);
		send(client_socket, hashed_result, sizeof(hashed_result), 0);
                /*for (int i = 0; i < 3; i++)
                    printf("%30lu", result[i]);
                printf("\n");*/
		for (int i = 0; i < 129; i++)
                    printf("%c", hashed_result[i]);
                printf("\n");
                break;
            }
            default:
            {
                printf("unknown option!\n");
                break;
            }
        }
    }

    close(client_socket);
    return 0;
}
