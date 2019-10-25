#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <arpa/inet.h> /* For htonl() */
#define BUFF_SIZE 1024

char *get_pubkeyID(char *githubId); // 원형선언을 안해놓으면 지멋대로 왜 함수 리턴타입을 integer 로 게싱을 하지?
char *escapeshell(char * str);


int msgfile_encrypt(char *filename, char *githubId){
    char cmd[256];
	char* keyID;
	char *filename_s = escapeshell(filename);
	char *githubId_s = escapeshell(githubId);
	
	if(!to_exist_publickey(githubId_s)) {
		printf("error! cannot get %s.pub...\n",githubId_s); 
		exit(202);
	}
	keyID = get_pubkeyID(githubId_s);
    snprintf(cmd, 256, "gpg --trust-model always --armor --encrypt --recipient %s %s 2>/dev/null", keyID, filename_s); system(cmd);
	snprintf(cmd, 256, "mv %s.asc %s", filename_s, filename_s); system(cmd); 
	free(filename_s);
	free(githubId_s);
    return 0;
}

int msgfile_decrypt(char *filename, char *passphrase){
	char cmd[256];
	char *filename_s = escapeshell(filename);
	char *passphrase_s = escapeshell(passphrase);
	
	snprintf(cmd, 256, "gpg --batch --output %s.tmp --passphrase %s --decrypt %s 2>/dev/null", filename_s, passphrase_s, filename_s); //output : filename.tmp
	system(cmd);
	snprintf(cmd, 256, "mv %s.tmp %s", filename_s, filename_s);
	system(cmd);
	
	free(filename_s);
	free(passphrase_s);
	return 0;

}

int msgfile_sign(char *filename, char *passphrase){ 
	char cmd[256];
	char *filename_s = escapeshell(filename);
	char *passphrase_s = escapeshell(passphrase);
	
	snprintf(cmd, 256, "gpg --batch --trust-model always --armor --output %s.sig --passphrase %s --sign onion 2>/dev/null", filename_s, passphrase_s); system(cmd);
	snprintf(cmd, 256, "mv %s.sig %s", filename_s, filename_s); system(cmd);
	
	free(filename_s);
	free(passphrase_s);
} 

// decrypt and verify
int msgfile_sign_verify(char *filename, char *githubId, char *passphrase){
	char cmd[256];
	char buf[256];
	char *pkey = NULL;
	char *skey = NULL;
	FILE *fp;
	
	char *filename_s = escapeshell(filename);
	char *githubId_s = escapeshell(githubId);
	char *passphrase_s = escapeshell(passphrase);
	
	pkey = get_pubkeyID(githubId_s);
	
	if(!pkey) return 0; // cannot get keyid
	
	
	// debug
	snprintf(cmd, 256, "echo ----------------------- >> log"); system(cmd);
	snprintf(cmd, 256, "echo filename_s is %s >> log",filename_s); system(cmd);
	snprintf(cmd, 256, "echo githubId_s is %s >> log",githubId_s); system(cmd);
	snprintf(cmd, 256, "echo passphrase_s is %s >> log",passphrase_s); system(cmd);
	snprintf(cmd, 256, "cp %s %s.debug",filename_s, filename_s); system(cmd);
	
	// get keyid of sign
	snprintf(cmd, 256, "gpg --verify %s 2> signature.tmp", filename_s); system(cmd);
	
	fp = fopen("signature.tmp", "r"); //read write and create
	
	while(fgets(buf, 256, fp)){
		skey = strstr(buf, "key ID ");
		if(skey) break;
	}
	fclose(fp);
	
	if(!skey) return 0; // file isn't signed
	
	skey += strlen("key ID ");
	
	if(!strncmp(pkey,skey,8)){ // sign verified
		snprintf(cmd, 256, "gpg --output %s.tmp --decrypt %s 2>/dev/null", filename_s, filename_s); system(cmd);
		snprintf(cmd, 256, "mv %s.tmp %s", filename_s, filename_s); system(cmd);
		system("rm signature.tmp");
		return 1;
	}
	else {
		system("rm signature.tmp");
		return 0;
	}
	
	// no free.. memory leak :(
}
