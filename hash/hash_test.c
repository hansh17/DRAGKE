#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
    outputBuffer[129] = 0;
}

int main(){
	static unsigned char buffer[129];
	static unsigned char buffer2[129];
	uint64_t k[16]={0,};
	uint64_t t[16]={0,};
	
	for(int j=0; j<15; j++){
		k[j]=j;
		t[j]=j;
	}
	
	sha512_session_key(k, buffer);
	sha512_session_key(t, buffer2);
	
	printf("%d\n", sizeof(uint64_t));
	int ret=1;
	for(int i=0; i<129; i++){
		ret&= (buffer[i]==buffer2[i]);
	}
	for(int i=0; i<129; i++){
		printf("%02x", buffer[i]);
	}
	printf("\n");
	for(int i=0; i<129; i++){
		printf("%02x", buffer2[i]);
	}
	printf("\n");
	printf("%d\n", ret);

}
