#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "hide_file.h"

typedef struct list
{
	char line[MAX_LEN];
	struct list* next;
}LIST;
        
void help(char* pro)
{
	printf("Usage: %s {h,u,} [file]\n\n"
			"       h hide file\n"
			"       u unhide file\n", pro);
}
void init_list(LIST** L)
{
	*L = (LIST*)malloc(sizeof(LIST));
	(*L)->next = NULL;
}
void add_list(LIST* L, char* line)        
{
	LIST* p = (LIST*)malloc(sizeof(LIST));
	sprintf(p->line, line);
	p->next = L->next;
	L->next = p;        
}
void print_list(LIST* L)
{
	LIST* p = L->next;
	while(p != NULL) {
		printf("%s", p->line);
		p = p->next;
	}
}     
int hidefile(char *path)
{
	struct stat buf;
	int ret = 0;
	FILE* fp = NULL;

	OWN* file = (OWN*)malloc(sizeof(OWN));
	if(file == NULL) {
		printf("%s\n", "malloc error");
		return -1;
	}

	if(lstat(path, &buf)==-1)
		return  -1;

	file->uid = buf.st_uid;
	file->gid = buf.st_gid;
	file->filename = path;

	ret = lchown(path, ELITE_UID, ELITE_GID);
	if(ret==0) {
		fp = fopen(ID_FILE, "a+");
		if(fp == NULL) {
			printf("%s\n", "fopen() error");
			return -1;
		}          
		fprintf(fp , "%s\t%d\t%d\n", file->filename, file->uid, file->gid);
		fclose(fp);         
	}
	free(file);
	file = NULL;
	return ret;
}
int unhidefile(char *path)
{
	int ret = -1;
	OWN* file = NULL;
	FILE* fp = NULL;
	LIST* L = NULL;
	LIST* p = NULL;
	LIST* q = NULL;

	char buf[MAX_LEN];

	fp = fopen(ID_FILE, "r");
	if(fp == NULL) {
		printf("%s\n", "fopen() error");
		goto out;
	}          
	init_list(&L);


	while(fgets(buf, MAX_LEN, fp)!=NULL)
		add_list(L, buf);

	print_list(L); 
	p = L; 
	q = p->next;         

	file = (OWN*)malloc(sizeof(OWN));
	if(file == NULL) {
		printf("%s\n", "malloc error");
		goto out;
	}
	file->filename = (char*)malloc(MAX_LEN);
	while(q!=NULL) {
		sscanf(q->line, "%s\t%d\t%d\n", file->filename, &(file->uid), &(file->gid));
		if(strcmp(path ,file->filename)==0)
		{
			printf("find %s\n", file->filename);
			break;
		}         
		p = q;
		q = q->next;
	}          

	if(q == NULL) {
		printf("%s is not by me\n", path);
		ret = -1;
		goto out;
	}
	else {
		p->next = q->next;
	}         

	printf("%s\n", "after");
	print_list(L);
	fclose(fp);
	  
	ret = lchown(file->filename, file->uid, file->gid);

	printf("%s\n", "begin write");
	fp = fopen(ID_FILE, "w"); 
	p = L->next;
	while(p != NULL) {
		q = p;
		printf("%s", p->line);
		fprintf(fp, "%s", p->line);
		p = p->next;
		free(q);
	}  
	free(L);        
out: 
	free(file);
	file = NULL;
	fclose(fp);
	return ret;
}

int main(int argc, char* argv[])
{
	if (argc != 3 ) {
		help(argv[0]);    
		return -1;
	}
	if(*argv[1]=='h')
		hidefile(argv[2]);
	else if(*argv[1]=='u')
		unhidefile(argv[2]);	   
	return 0;     
}