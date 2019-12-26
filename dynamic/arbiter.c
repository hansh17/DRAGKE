#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
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

#define MAX_PEER 6
#define POLY_LEN 1024
#define KEY_LEN  16
#define HASH_LEN 129

bool check_augmented_pub_keys[MAX_PEER];

bool option_check[4][MAX_PEER];

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];
uint64_t session_keys[MAX_PEER][KEY_LEN];
unsigned char hashed_keys[MAX_PEER][HASH_LEN];

uint64_t reconcile[KEY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx);
int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx);
int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);
void run_server(int num_peer2, int num_peer, int server_port, int mode);

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

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024], FFT_CTX *ctx){ 
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

int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){
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
	sha512_session_key(k, hk);

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int next_option(int option, int num_peer)
{
    bool check = true;
    for (int i = 0; i < num_peer - 1; i++)
    {
        check = check && option_check[option][i];
    }
    if (check)
        return option + 1;
    return option;
}

void run_server(int num_peer2, int num_peer, int server_port, int mode) // num_peer2 = N+M, num_peer = N, mode=join, leave, static
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

    int new_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_size;
    
    uint32_t result[POLY_LEN];
    int peer;

    memset(check_augmented_pub_keys, false, sizeof(check_augmented_pub_keys));
    memset(option_check, false, sizeof(option_check));
    bool reconcile_calculated = false;

    FFT_CTX ctx;
    FFT_CTX_init(&ctx);

    uint32_t sec_key[POLY_LEN];

    int index[num_peer2];
    int stug_index;   // stug를 돌리는 사람 수

    if (mode==1){ //join
    	stug_index=num_peer2-num_peer+3; // 총 멤버 - 기존 멤버 + 3
	// save index who participate in STUG
    	index[0]=0;
    	index[1]=1;
    	index[num_peer-1]=2;
    	for(int i=0; i<num_peer2-num_peer; i++)
	{
    		index[num_peer+i]=3+i;     
    	}
	for(int j=2; j<num_peer-1; j++)
	{
		index[j]=-1;
	}
    }
    else{
    	stug_index=num_peer2;
    	// save index who participate in STUG
    	for(int i=0; i<num_peer2; i++)
    	{
		index[i]=i;
    	}
    }

    calculate_pubkey(stug_index - 1, rlwe_a, sec_key, &ctx);


    int client_socket[MAX_PEER];
    for (int i = 0; i < num_peer2; i++)
    {
        client_socket[i] = 0;
    }

    client_addr_size = sizeof(client_addr);

    fd_set readfds;
    int sd, max_sd;
    int activity; // activity는 실제로 사용되지 않음.

    int option = 0;

    bool first_process;
    while (option < 4) // option이 4로 넘어가면 종료.
    {
        FD_ZERO(&readfds); // while문 시작할때마다 (fd_set으로 선언된) readfds를 0으로 initialize

        FD_SET(server_socket, &readfds); // readfds에 server_socket을 1로 설정. 
        max_sd = server_socket; // 가장 큰 sd가 현재는 server_socket

        for (int i = 0; i < num_peer2; i++) 
        {
            sd = client_socket[i];

            if (sd > 0) 
                FD_SET(sd, &readfds); // client_socket[i]에 값이 있을 시 그 sd값을 1로 설정

            if (sd > max_sd) // 제일 큰 fd값 지정 -> max_sd까지 검사하기 위해서.
                max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL); // max_sd+1 '미만'의 값에 대해 sd이 1인 것들에 대해 이벤트가 발생할 때까지 대기함.

        if (FD_ISSET(server_socket, &readfds)) // ***server_socket에 이벤트가 발생해야함, 왜 peer 하나만 접속한 상태일 때 이 조건을 통과하지? (일단 pass)
        {
            new_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);

            for (int i = 0; i < num_peer2; i++)
            {
                if (client_socket[i] == 0) // 순서대로 new_socket값 배정, i를 증가시켜가면서 검사
                {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }
	// peer 0~N-1까지 '차례'대로 소켓으로 data 주고 받기. 끝나면 while문으로 이동.
        for (int p = 0; p < num_peer2; p++)
        {
            sd = client_socket[p];
            if (FD_ISSET(sd, &readfds)) // sd 소켓에 이벤트가 발생해야함 (통신), 읽기값이 들어오면 활성화됨.
            {
                recv(sd, &peer, sizeof(peer), 0);

                if (!(0 <= peer && peer < num_peer2))
                {
                    printf("peer number error\n");
                    close(sd);
                    continue;
                }

                if (!reconcile_calculated)
                {
                    bool all_augmented_pub_keys = true;

                    for (int i = 0; i < stug_index; i++)
                    {
                        if (!check_augmented_pub_keys[i])
                        {
                            all_augmented_pub_keys = false;
                            break;
                        }
                    }

                    if (all_augmented_pub_keys)
                    {
                        calculate_reconcile(stug_index, sec_key, reconcile, session_keys[num_peer2 - 1], hashed_keys[num_peer2-1], &ctx);
                        reconcile_calculated = true;
                    }
                }

                send(sd, &option, sizeof(option), 0); // option을 먼저 보내줌.

                if (option == 1) // peer N-2까지 모든 값을 다 받으면 arbiter는 그제서야 aug pub key 계산.
                {
                    calculate_augmented_pubkey(stug_index - 1, stug_index, sec_key, &ctx);
                    check_augmented_pub_keys[stug_index - 1] = true;
                }

                first_process = !option_check[option][peer];
                send(sd, &first_process, sizeof(first_process), 0);

                if (!first_process) // first process가 아니면 for문 빠져나옴, 즉 한 번 주고 받은 이상 밑의 프로세스 진행 X
                    continue;

                switch (option)
                {
                    case 0:
                    {
			if (index[peer]==-1)
			{
				printf("option 0 clear with peer %d!\n", peer);
				break;
			}
                        recv(sd, pub_keys[index[peer]], POLY_LEN * sizeof(uint32_t), 0);
                        printf("option 0 clear with peer %d!\n", peer);
                        break;
                    }
                    case 1:
                    {
                        send(sd, pub_keys, sizeof(uint32_t) * stug_index * POLY_LEN, 0); // send z_i
			if (index[peer]==-1)
			{
				printf("option 1 clear with peer %d!\n", peer);
				break;
			}
                        recv(sd, result, sizeof(result), 0);
                        memcpy(augmented_pub_keys[index[peer]], result, sizeof(augmented_pub_keys[index[peer]]));
                        check_augmented_pub_keys[index[peer]] = true;
                        printf("option 1 clear with peer %d!\n", peer);
                        break;
                    }
                    case 2:
                    {
                        send(sd, augmented_pub_keys, sizeof(uint32_t) * stug_index * POLY_LEN, 0);
                        printf("option 2 clear with peer %d!\n", peer);
                        break;
                    }
                    case 3:
                    {
                        send(sd, reconcile, sizeof(reconcile), 0);
			recv(sd, hashed_keys[peer], sizeof(hashed_keys[peer]), 0);
                        printf("option 3 clear with peer %d!\n", peer);
     		    }
		}
                option_check[option][peer] = true;
                option = next_option(option, num_peer2);
            }
        } // 정상적으로 for문에서 데이터 통신이 되었다면 option+1 상태로 while문 종료
    }
    printf("Arbiter hased key : ");
    for (int i = 0; i < 129; i++)
        printf("%c", hashed_keys[num_peer2 - 1][i]);
    printf("\n");
    //close(client_socket);
}

int main(int argc, char *argv[])
{
    int num_peer = 4;
    int num_peer2 = 5;
    int mode = 1;

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
    run_server(num_peer2, num_peer, server_port, mode);
    return 0;
}
