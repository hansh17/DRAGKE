// @userlist
// @adduser "192.168.0.1 2222 eternalklaus"
// @deleteuser eternlaklaus
// 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#define  BUFF_SIZE   1024

#define _CRT_SECURE_NO_WARNINGS    // strtok 보안 경고로 인한 컴파일 에러 방지

//TODO
char *escapeshell(char* str); 

// developer : eternalklaus
// contributer : MincheolSon, Dauren
int isClientAlive(char *ClientIP, int ClientPort){
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
	char   buff_snd[BUFF_SIZE+5];
 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }
	memset( &serv_addr, 0, sizeof( serv_addr));
	serv_addr.sin_family      = AF_INET;
    serv_addr.sin_port        = htons(ClientPort);
    serv_addr.sin_addr.s_addr = inet_addr(ClientIP);
	
	int isalive=connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
	
	strncpy(buff_snd, "alive?", strlen("alive?"));
	write(sockfd, buff_snd, strlen(buff_snd)+1);  
    close(sockfd);
	printf("%s:%d is still alive...\n", ClientIP,ClientPort);
	if (isalive < 0) return 0;
    return 1;
}

// @userlist
char *Userlist(){ // User should download result as OnionUser.db.tmp
	   int fd;
	   char *buff = (char*)malloc(BUFF_SIZE); 
	   fd=open("OnionUser.db",O_RDONLY);
	   read(fd,buff,BUFF_SIZE-1);
	   close(fd);
	   return buff;
}

// @adduser
int addUser(char *IpPortGithubId) { // char userIp, int userPort, char *githubID
	char cmd[256];
	char *IpPortGithubId_s = escapeshell(IpPortGithubId);
	printf("[*] IpPortGithubId   : %s\n\n",IpPortGithubId);
	printf("[*] IpPortGithubId_s : %s\n\n",IpPortGithubId_s);
	
	snprintf(cmd, 256, "sed -i '1i%s ' %s", IpPortGithubId_s ,"OnionUser.db");
	printf("[*] cmd : %s\n\n",cmd);
	system(cmd);free(IpPortGithubId_s);
	
	return 1; 
}

// @deleteuser
int deleteUser(char *githubID){
	char cmd[256];
	char *githubID_s = escapeshell(githubID);
	snprintf(cmd, 256, "sed -i '/ %s/d' %s", githubID_s ,"OnionUser.db"); system(cmd);
	
	return 1;
}

int run_dbserver(int dbserver_port){
   int   server_socket;
   int   client_socket;
   int   client_addr_size;

   struct sockaddr_in   server_addr;
   struct sockaddr_in   client_addr;

   char   buff_rcv[BUFF_SIZE+5];
   char   buff_snd[BUFF_SIZE+5];

   server_socket  = socket( PF_INET, SOCK_STREAM, 0);
   if( -1 == server_socket)
   {
      printf( "[DBSERVER] server socket error\n");
      exit( 1);
   }

   memset( &server_addr, 0, sizeof( server_addr));
   server_addr.sin_family     = AF_INET;
   server_addr.sin_port       = htons(dbserver_port);           
   server_addr.sin_addr.s_addr= htonl(INADDR_ANY);

   if( -1 == bind( server_socket, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
   {
      printf( "[DBSERVER] bind() error\n");
      exit( 1);
   }

   if( -1 == listen(server_socket, 5))
   {
      printf( "[DBSERVER] listen() error\n");
      exit(1);
   }

   char* ipstr = malloc(100);
   char* param = malloc(512);
   
   memset(ipstr, 0, 100);
   memset(param, 0, 512);
   while(1)
   {
      client_addr_size  = sizeof( client_addr);
      client_socket     = accept( server_socket, (struct sockaddr*)&client_addr, &client_addr_size);

	  struct sockaddr_in *s = (struct sockaddr_in *)&client_addr;
      memset(ipstr, 0, 100);
      inet_ntop(AF_INET, &s->sin_addr, ipstr, 100);
      printf("Peer IP address: %s\n", ipstr);

	  
	  
      if ( -1 == client_socket)
      {
         printf( "[DBSERVER] Client connection failed\n");
         exit(1);
      }

      read(client_socket, buff_rcv, BUFF_SIZE);
      
	  // server command : @adduser, @deleteuser, @userlist
	  if (!strncmp(buff_rcv,"@adduser",strlen("@adduser"))){ 
		strcpy(param, ipstr);
        strcat(param, " ");
        // bug fixed - one byte overflow
        strncat(param, buff_rcv+strlen("@adduser")+1, 512-strlen(ipstr)-2);
		addUser(param);                 
		printf("[DBSERVER] User login : %s\n\n",buff_rcv+strlen("@adduser")+1); 
	  }
	  
	  if (!strncmp(buff_rcv,"@deleteuser",strlen("@deleteuser"))){ 
          deleteUser(buff_rcv+strlen("@deleteuser")+1);
		  printf("[DBSERVER] User logout : %s\n",buff_rcv+sizeof("@deleteuser"));  // 서버 프린트  (buff_rcv+sizeof("@deleteuser")+1 하면 왜 짤리지?)
	  }
	  
	  if (!strncmp(buff_rcv,"@userlist",strlen("@userlist"))){
         snprintf(buff_snd, BUFF_SIZE, "%s", Userlist());  // user can download [buff_snd] buffer as a file. 
	  }
	  write(client_socket, buff_snd, strlen(buff_snd)+1);  
      close(client_socket);
   }
   // [TODO] 다른 프로세스에서는 OnionUser.db 한줄씩 돌면서
   // isClientAlive 실행하기. 
}

int main()
{
	run_dbserver(4000); // 4000번포트사용
}

