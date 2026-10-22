#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
int main(int argc,char **argv){
 if(argc!=2)return 90;
 if(!strcmp(argv[1],"true"))return 0;
 if(!strcmp(argv[1],"pid")){return getpid()==2&&getppid()==1&&getuid()==65534?0:91;}
 if(!strcmp(argv[1],"fds")){for(int fd=3;fd<1024;fd++){if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF)return 92;}return 0;}
 if(!strcmp(argv[1],"fork")){for(;;){pid_t p=fork();if(p==0){for(;;)pause();}if(p<0){if(errno!=EAGAIN)return 93;puts("pids-max-reached");fflush(stdout);for(;;)pause();}}}
 if(!strcmp(argv[1],"oom")){for(;;){volatile char *p=malloc(1024*1024);if(!p)return 94;for(int i=0;i<1024*1024;i+=4096)p[i]=1;}}
 if(!strcmp(argv[1],"ptrace")){errno=0;long r=syscall(SYS_ptrace,PTRACE_TRACEME,0,0,0);return r==-1&&errno==EPERM?0:95;}
 if(!strcmp(argv[1],"unshare")){errno=0;long r=syscall(SYS_unshare,CLONE_NEWUSER);return r==-1&&errno==EPERM?0:96;}
 if(!strcmp(argv[1],"net")){int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return 97;struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(443)};inet_pton(AF_INET,"192.0.2.1",&a.sin_addr);int r=connect(fd,(void*)&a,sizeof(a));int e=errno;close(fd);return r==-1&&(e==ENETUNREACH||e==EHOSTUNREACH)?0:98;}
 if(!strcmp(argv[1],"fs")){char *p[]={"/etc/nope","/bin/nope","/.microbox-old/nope","/../nope"};for(int i=0;i<4;i++){errno=0;int fd=open(p[i],O_WRONLY|O_CREAT,0600);if(fd>=0||errno!=EROFS)return 99;}int fd=open("/tmp/allowed",O_CREAT|O_WRONLY,0600);if(fd<0)return 100;close(fd);return 0;}
 if(!strcmp(argv[1],"tmp")){int fd=open("/tmp/fill",O_CREAT|O_WRONLY,0600);if(fd<0)return 101;char buf[4096]={0};for(int i=0;i<4096;i++){if(write(fd,buf,sizeof(buf))<0){int e=errno;close(fd);return e==ENOSPC?0:102;}}return 103;}
 if(!strcmp(argv[1],"output")){char b[4096];memset(b,'X',sizeof(b));for(;;)if(write(1,b,sizeof(b))<0)return 0;}
 if(!strcmp(argv[1],"sleep")){for(;;)pause();}
 return 104;
}
