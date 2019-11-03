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
#include "rlwe_rand.h"

#define MAX_PEER 10
#define POLY_LEN 1024

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys_prime[MAX_PEER][POLY_LEN];

void calculate_pub_key_prime(uint32_t result[POLY_LEN], int peer, int num_peer);

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
    if (!(0 <= option && option <= 2))
    {
        printf("option shoud be 0 <= option <= 2!\n");
        exit(1);
    }

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
        case 1:
        {
            int recv_size = recv(client_socket, pub_keys, sizeof(pub_keys), 0);
            int num_peer = recv_size / (sizeof(uint32_t) * POLY_LEN);

            uint32_t result[POLY_LEN];
            calculate_pub_key_prime(result, peer, num_peer);

            send(client_socket, result, sizeof(result), 0);
            break;
        }
        case 2:
        {
            int recv_size = recv(client_socket, pub_keys_prime, sizeof(pub_keys_prime), 0);
            int num_peer = recv_size / (sizeof(uint32_t) * POLY_LEN);

            for (int i = 0; i < num_peer; i++)
            {
                for (int j = 0; j < 10; j++)
                    printf("%15u", pub_keys_prime[i][j]);
                printf("\n");
            }

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