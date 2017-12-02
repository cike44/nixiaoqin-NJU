
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <iostream>
using namespace std;
#define PORT 9090
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
	int sockfd2=0;
	struct sockaddr_in servaddr2;
	sockfd2=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr2,sizeof(servaddr2));
	servaddr2.sin_family=AF_INET;
	servaddr2.sin_port=htons(1111);
	servaddr2.sin_addr.s_addr=htonl(INADDR_ANY) ;
	bind(sockfd2, (struct sockaddr *)&servaddr2, sizeof(servaddr2));

	unsigned char buffer[5000];
	
	
	//writen(sockfd1,idle,sizeof(idle));

	

	//auto t=std::thread(receiveTele,argv[1]);
	//t.detach();

	struct sockaddr_in servaddr;
	socklen_t addr_len =sizeof(struct sockaddr_in);
	int len=0;
	int num=0,byte=0;
	while(1){
		bzero(buffer,sizeof(buffer));
		len = recvfrom(sockfd2,buffer,sizeof(buffer), 0 , (struct sockaddr *)&servaddr ,&addr_len);
		if(len==11 && buffer[0]=='1') ;//cout<<"同步"<<std::endl;
		else {
		++num;
		byte+=len;
		printf("receive %s	len:%d	\n%s\n",sock_ntop((struct sockaddr *)&servaddr,addr_len),len,buffer);
	}
		cout<<"total package:"<<num<<" total bytes:"<<byte<<endl<<endl;
	}
	
	return 0;
}
