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

bool check_pub_keys_prime[MAX_PEER];

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys_prime[MAX_PEER][POLY_LEN];

uint32_t reconcile[POLY_LEN];

void poly_init(int num_peer);
void calculate_reconcile(void);
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

    memset(check_pub_keys_prime, false, sizeof(check_pub_keys_prime));
    bool reconcile_calculated = false;
    
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
            bool all_pub_keys_prime = true;

            for (int i = 0; i < num_peer; i++)
            {
                if (!check_pub_keys_prime[i])
                {
                    all_pub_keys_prime = false;
                    break;
                }
            }

            if (all_pub_keys_prime)
            {
                calculate_reconcile();
                reconcile_calculated = true;
            }
        }

        switch (option_and_peer & 0xffff)
        {
            case 0:
            {
                recv(client_socket, pub_keys[peer], POLY_LEN * sizeof(uint32_t), 0);
                break;
            }
            case 1:
            {
                send(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                recv(client_socket, result, sizeof(result), 0);
                memcpy(pub_keys_prime[peer], result, sizeof(pub_keys_prime[peer]));
                check_pub_keys_prime[peer] = true;
                printf("got new public key fine!!!\n");
                break;
            }
            case 2:
            {
                send(client_socket, pub_keys_prime, sizeof(uint32_t) * num_peer * POLY_LEN, 0);
                break;
            }
            case 3:
            {
                send(client_socket, reconcile, sizeof(reconcile), 0);
                printf("Reconcile       ");
                for (int i = 0; i < 3; i++)
                {
                    printf("%15u", reconcile[i]);
                }
                printf("\n\n");
                break;
            }
        }
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
                printf("%15u", pub_keys_prime[i][j]);
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