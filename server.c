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

uint32_t pub_keys[MAX_PEER][POLY_LEN];

void poly_init(int n);
void run_server(int num_peer, int server_port);

void poly_init(int n)
{
    if (n > MAX_PEER)
    {
        printf("Maximum peer number is %d\n", MAX_PEER);
        return;
    }

    RAND_CTX rand_ctx;
    for (int i = 0; i < n; i++)
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
    while (true)
    {
        client_addr_size = sizeof(client_addr);
        client_socket    = accept(server_socket, (struct sockaddr *)&client_addr,
                                  &client_addr_size);

        printf("connection success!\n");

        send(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0);

        recv(client_socket, result, sizeof(result), 0);

        printf("got new public key fine!!!\n");

        close(client_socket);
    }
}

int main(int argc, char *argv[])
{
    int num_peer = 5;
    poly_init(num_peer);

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