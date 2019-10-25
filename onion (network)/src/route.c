#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

// TODO escapeshell

extern char g_passphrase[256];
typedef struct __token{
    char* word;
    struct __token* next;
}token, *ptoken;

typedef struct __record{
    unsigned int no;
    char* ip;
    char* port;
    char* id;
    struct __record* next;
}record, *precord;
precord g_records;

void print_list(ptoken head){
    ptoken cur = head;
    printf("traversing list...\n");
    while(cur){
        printf("[%s]\n", cur->word);
        cur = cur->next;
    }
}

char *escapeshell(char* str); 

unsigned int fsize(const char *filename);
void trim(char* s);
ptoken split(const char* str, char deli){
    ptoken head = 0;
    ptoken res = 0;
    unsigned int base = 0;
    unsigned int pos = 0;
    unsigned int len = strlen(str);
    while(pos < len){
        if(str[pos++] == deli || pos==len){ // end of token
            // make token
            if(!head){
                res = (ptoken)malloc(sizeof(token));
                res->word = malloc(pos-base);
                strncpy(res->word, &str[base], pos-base);
                trim(res->word);
                head = res;
            }
            else{
                res->next = (ptoken)malloc(sizeof(token));
                res->next->word = malloc(pos-base);
                strncpy(res->next->word, &str[base], pos-base);
                trim(res->next->word);
                res = res->next;
            }
            base = pos;
        }
    }
    return head;
}

void print_records(precord p){
    precord cur = p;
    printf("parsing result...\n");
    while(cur){
        printf("NO[%d] ", cur->no);
        printf("IP[%s] ", cur->ip);
        printf("PORT[%s] ", cur->port);
        printf("ID[%s]\n", cur->id);
        cur = cur->next;
    }
}

unsigned int record_count(precord p){
    unsigned int res=0;
    precord cur = p;
    while(cur){
        cur = cur->next;
        res++;
    }
    return res;
}

precord* arrayfy(){
    unsigned int N = record_count(g_records);
    precord* res = (precord*)malloc(sizeof(precord)*N);
    precord cur = g_records;
    int i=0;
    while(cur){
        res[i++] = cur;
        cur = cur->next;
    }
    return res;
}

precord ptr_by_id(precord p, const char* id){
    precord cur = p;
    while(cur){
        if(!strcmp(cur->id, id)) return cur;
        cur = cur->next;
    }
}

unsigned int idx_by_id(precord p, const char* id){
    precord cur = p;
    unsigned int r = 0;
    while(cur){
        if(!strcmp(cur->id, id)) return r;
        cur = cur->next;
        r++;
    }
}

void parse_db(const char* fname){
    FILE* fp = fopen(fname, "r+");
    unsigned int len = fsize(fname);
    char* buf = malloc(len);
    fread(buf, len, 1, fp);

    precord tmp;
    ptoken R;
    ptoken records = split(buf, '\n');
	g_records = NULL;
    unsigned int n=1;
    while(records){
        R = split(records->word, ' ');
        if(R->word[0] == '-') break;    // end record.
        
        // insert a record.
        tmp = (precord)malloc(sizeof(record));
        tmp->ip = R->word;
        tmp->port = R->next->word;
        tmp->id = R->next->next->word;
        tmp->no = n;
        tmp->next = g_records;
        g_records = tmp; 
        
        records = records->next;
        n++;
    }
    fclose(fp);
}

unsigned int randpick(precord* p, unsigned int s, unsigned int e, unsigned int len){
    unsigned int r;
    while(1){
        r = ((39133*33311*rand()) % len);
        if(r==s) continue;
        if(r==e) continue;
        if(p[r]==0) continue;
        return r;
    }
}

//gpg --gen-key; gpg --export -a "user2" > user2.pub; gpg --import user1.pub; 
//gpg --trust-model always --recipient bob --encrypt filename;
//gpg --passphrase %s --decrypt %s > info.txt 2>/dev/null
#define MAXCIRCUIT 5 
// fileoutput: onion. input: msg, from, to
// return: ip/port(precord) of first target node.
precord onion_route_msg(const char* from, const char* to, const char* msg){
    char* cmd = malloc(4096);
    precord* arr = arrayfy(g_records);
    unsigned int len = record_count(g_records);
    unsigned int itercount = (MAXCIRCUIT < len-1) ? MAXCIRCUIT : len-1;
    unsigned int start = idx_by_id(g_records, from);
    unsigned int end = idx_by_id(g_records, to);
    precord init = arr[end];        // initial reciever of the onion
	precord initminus1 = arr[end];
	
	// header
    FILE* fp = fopen("onion_header", "w");
    fprintf(fp, "final\n");
    fprintf(fp, "text\n");
    fprintf(fp, "%s\n", from);
    fprintf(fp, "dummy\n");
    fclose(fp);
	
	char *msg_s = escapeshell(msg);
	
	// message
	snprintf(cmd, 256, "echo %s > onion", msg_s); system(cmd);
	
	// header + [signed message]
	msgfile_sign("onion", g_passphrase); // [TODO][VER]
	// [debug] 
	snprintf(cmd, 256, "cp onion onion.sign"); system(cmd);
	snprintf(cmd, 256, "cat onion >> onion_header; mv onion_header onion"); system(cmd);

	
    // start onioning... we use maximum MAXCIRCUIT circuits
    unsigned int i = 0;
    unsigned int r;
	
    for(i=0; i<itercount; i++){
		init = initminus1;   // update the initial reciever.
		msgfile_encrypt("onion", init->id); // [ENC] encrypt
		snprintf(cmd, 256, "cp onion onion_enc%d", i); system(cmd); // [DBG]
		
		snprintf(cmd, 4096, "echo '%s' > onion.tmp", escapeshell(init->ip)); system(cmd);
        snprintf(cmd, 4096, "echo '%s' >> onion.tmp", escapeshell(init->port)); system(cmd);
		system("cat onion >> onion.tmp; mv onion.tmp onion");
		
		 // pick a random node..
		if(i == itercount-1) continue;
		r = randpick(arr, start, end, len);
		initminus1 = arr[r]; // set initminus1 node
		arr[r] = 0;          // now, this node is no more candidate.
    }
	free(msg_s);
    return init; // right next node
}

// output : onion
precord onion_route_file(const char* from, const char* to, const char* filename){
    char* cmd = malloc(4096);
    precord* arr = arrayfy(g_records);
    unsigned int len = record_count(g_records);
    unsigned int itercount = (MAXCIRCUIT < len-1) ? MAXCIRCUIT : len-1;
    unsigned int start = idx_by_id(g_records, from);
    unsigned int end = idx_by_id(g_records, to);
    precord init = arr[end];        // initial reciever of the onion
	precord initminus1 = arr[end];

    FILE* fp = fopen("onion_header", "w");
    fprintf(fp, "final\n");
    fprintf(fp, "file\n"); //file
    fprintf(fp, "%s\n", from);
    fprintf(fp, "%s\n", filename);
    fclose(fp);
	
	char *filename_s = escapeshell(filename);
	
	// header + [signed message]
	msgfile_sign(filename_s, g_passphrase); // [TODO][VER] sign to file
	// [debug] 
	snprintf(cmd, 256, "cp onion onion.sign"); system(cmd);
	snprintf(cmd, 256, "cat %s >> onion_header; mv onion_header onion", filename_s); system(cmd);

    unsigned int i = 0;
    unsigned int r;
	
    for(i=0; i<itercount; i++){ // end -> randpick -> randpick -> ...
		init = initminus1;   // update the initial reciever.
		msgfile_encrypt("onion", init->id); // [ENC]
		
		snprintf(cmd, 4096, "echo '%s' > onion.tmp", escapeshell(init->ip)); system(cmd);
        snprintf(cmd, 4096, "echo '%s' >> onion.tmp", escapeshell(init->port)); system(cmd);
		system("cat onion >> onion.tmp; mv onion.tmp onion");
		
		if(i == itercount-1) continue;
		r = randpick(arr, start, end, len);
		initminus1 = arr[r]; // set initminus1 node
		arr[r] = 0;          // now, this node is no more candidate.
    }
	free(filename_s);
    return init; // right next node
}

/*
void trim(char* s){
    while(s[strlen(s)-1]=='\n' || s[strlen(s)-1]==' '){
        s[strlen(s)-1]=0;
    }
}

unsigned int fsize(const char *filename) {
    struct stat st;
    if (stat(filename, &st) == 0)
        return st.st_size;
    return -1;
}

void main(){
    srand(time(0));
    parse_db("OnionUser.db.tmp");
    precord t = onion_route_msg("sender", "receiver", "I love you!");    
    printf("ip:%s, port%s\n", t->ip, t->port);
}
*/
