
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <time.h>
using namespace std;
#define PORT 1111
#define SERVER_IP "127.0.0.1"
char * sock_ntop(const struct sockaddr* sa,socklen_t salen) {
	char portstr[8];
	static char str[128];
	struct sockaddr_in *sin=(struct sockaddr_in*)sa;
	if(inet_ntop(AF_INET,&sin->sin_addr,str,sizeof(str))==NULL) return NULL;
	if(ntohs(sin->sin_port)!=0) {
		snprintf(portstr,sizeof(portstr),":%d",ntohs(sin->sin_port));
		strcat(str,portstr);
	}
	return str;
}
int main(int argc,char *argv[])
{
	int s,len;
	struct sockaddr_in addr;
	socklen_t addr_len =sizeof(struct sockaddr_in);
	char buffer[2000];
	/* 建立socket*/
	if((s = socket(AF_INET,SOCK_DGRAM,0))<0){
		perror("socket");
		exit(1);
	}
	/* 填写 sockaddr_in*/
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	int num=atoi(argv[2]);
	int byte=atoi(argv[3]);
srand((unsigned int)time(NULL));
for(int j=0;j<2;++j){
		bzero(buffer,sizeof(buffer));
		/* 从标准输入设备取得字符串*/
		//len =read(STDIN_FILENO,buffer,sizeof(buffer));
		for(int i=0;i<11;++i) {
			buffer[i]='1';
		}
		
		/* 将字符串传送给server端*/
		sendto(s,buffer,11,0,(struct sockaddr *)&addr,addr_len);
		//printf("send 同步\n");
		/* 接收server端返回的字符串*/
		//len = recvfrom(s,buffer,sizeof(buffer),0,(struct sockaddr *)&addr,&addr_len);
		sleep(1);
		//printf("receive %s: %d:%s\n",sock_ntop((struct sockaddr *)&addr,addr_len),len,buffer);
	}
	for(int j=0;j<num;++j){
		bzero(buffer,sizeof(buffer));
		/* 从标准输入设备取得字符串*/
		//len =read(STDIN_FILENO,buffer,sizeof(buffer));
		for(int i=0;i<byte;++i) {
			buffer[i]='a'+(int)(rand()%26);
		}
		buffer[byte]=0;
		
		/* 将字符串传送给server端*/
		sendto(s,buffer,byte,0,(struct sockaddr *)&addr,addr_len);
		/* 接收server端返回的字符串*/
		//len = recvfrom(s,buffer,sizeof(buffer),0,(struct sockaddr *)&addr,&addr_len);
		printf("send %d bytes：%s\n",byte,buffer);
		sleep(1);
		//printf("receive %s: %d:%s\n",sock_ntop((struct sockaddr *)&addr,addr_len),len,buffer);
	}
	return 0;
}
