#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char portion_buffer(char s[20]){
	return s[2];
}

int main(){

	FILE* fp;
	char buffer[20];
	char* tmp;

	fp = fopen("tmp.txt", "r");

	while(fgets(buffer, sizeof(buffer), (FILE*) fp)) {
	    printf("%s", buffer);
	    strncpy(tmp, buffer, strlen(buffer)+1);
	    printf("%s", tmp[2]);
	}

	fclose(fp);

        return 0;


}
