#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <iostream>
#include <memory>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <unistd.h>
#include <chrono>
#include <iomanip>
#include <fstream>
using namespace std;
constexpr int MAXLINE=6000;
constexpr int port2=3070;
//第16个字节代表不同的通道
unsigned char requst[]={0x49,0x96,0x02,0xD2,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB6,0x69,0xFD,0x2E};
unsigned char tongbu[]={0xFA,0xF3,0x20,0x00,0x00,0x00,0x00};
unsigned char bufferSend[MAXLINE*2]={0};
unsigned char bufferSend2[MAXLINE]={0};
ssize_t writen(int fd,const unsigned char *ptr,int n) {
	size_t nleft;
	ssize_t nwritten;
	nleft=n;
	while(nleft>0) {
		if((nwritten=write(fd,ptr,nleft))<=0) {
			if(nwritten<0 && errno==EINTR) nwritten=0;
			else return -1;
		}
		nleft-=nwritten;
		ptr+=nwritten;
	}
	return n;
}

bool removeHead(const unsigned char* buffer,int len) {
	bool result=false;
	int cur=0;
	std::copy(buffer+64,buffer+356,bufferSend2+cur);
	cur+=292;
	cur+=4;
	if(cur==len-64-4) result=true;
	return result;
}

class SockFD {
public:
	SockFD(int port,const char *argv) {
		sockfd=socket(AF_INET,SOCK_STREAM,0);
		bzero(&servaddr,sizeof(servaddr));
		servaddr.sin_family=AF_INET;
		servaddr.sin_port=htons(port);
		inet_pton(AF_INET,argv,&servaddr.sin_addr);
		connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
		std::cout<<"connect sucess,port:"<<port<<std::endl;
	}
	~SockFD() {
		close(sockfd);
		std::cout<<"close"<<std::endl;
	}
	int sockfd=0;
	struct sockaddr_in servaddr;
	
};

int main(int argc, char const *argv[])
{
	//建立本地5002udp端口 准备往下游发数据
	int sockfd4=0;
	struct sockaddr_in servaddr4;
	sockfd4=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr4,sizeof(servaddr4));
	servaddr4.sin_family=AF_INET;
	servaddr4.sin_port=htons(5002);
	inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);
	unsigned char buffer[MAXLINE];
	//ofstream ofile;
	//ofile.open("1024receive.txt");
	struct sockaddr_in servaddr;
	socklen_t addr_len =sizeof(struct sockaddr_in);
	int len=0;
	int totalcount=0;
	//建立到crt的tcp连接 接收数据
	SockFD sockf2(port2,argv[1]);
	fd_set rset,allset;
	FD_ZERO(&allset);
	int maxfdp1;
	maxfdp1=std::max(sockf2.sockfd,0)+1;
	FD_SET(sockf2.sockfd,&allset);
	//发送请求数据命令
	writen(sockf2.sockfd,requst,sizeof(requst));
	int left = 0;
	int start = 0;
	while(1) {
		rset=allset;
		select(maxfdp1,&rset,nullptr,nullptr,nullptr);
		if(FD_ISSET(sockf2.sockfd,&rset)) {
			if((len=read(sockf2.sockfd,buffer,MAXLINE))==0) {
				cout<<"receive nothing"<<endl;
			} 
			else {
				//同样可能出现tcp粘包现象 需要处理
				std::cout<<std::dec<<std::endl;
				std::cout<<"receive len = "<<len<<std::endl;
				/*for(int i=0;i<len;++i) {
					if(i%16==0) std::cout<<std::endl;
					std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)buffer[i]<<" ";
				}*/
				std::cout<<"left before= "<<left<<std::endl;
				if(left != 0) {
					std::cout<<"left before= "<<left<<std::endl;
					std::copy(buffer,buffer+1092-left,bufferSend+left);
					if(bufferSend[68]==0xaa && bufferSend[69]==0xaa && bufferSend[70]==0xaa && bufferSend[71]==0xaa)
						cout<<"receive idle"<<endl;
					else {
						for(int j=64;j<1087;++j) {
							if(j%16==0) {
								std::cout<<std::endl;
								//ofile<<std::endl;
							}
								std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)bufferSend[j]<<" ";
								//ofile<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)bufferSend[j]<<" ";
						}
						std::cout<<std::dec<<std::endl;
						sendto(sockfd4,bufferSend+64,1023,0,(struct sockaddr *)&servaddr4,addr_len);
						printf("totalcount=%d\n",totalcount++);
					}
					std::cout<<std::dec<<std::endl;
					std::cout<<"left before= "<<left<<std::endl;
					start= 1092 - left;
					std::cout<<"start= "<<start<<std::endl;
				}
				else
					start=0;

				int count=(len-start) / 1092;
				left = (len-start) % 1092;
				std::cout<<"count= "<<count<<std::endl;
				std::cout<<"left now= "<<left<<std::endl;
				for(int k=0;k<count;k++){
					std::cout<<"k= "<<k<<std::endl;
					std::copy(buffer+64+1092*k+start,buffer+1023+64+1092*k+start,bufferSend2);
					std::cout<<"remove"<<std::endl;
					//判断接收到的是不是idle包
					if(bufferSend2[4]==0xaa && bufferSend2[5]==0xaa && bufferSend2[6]==0xaa && bufferSend2[7]==0xaa)
						cout<<"receive idle"<<endl;
					else {
						for(int j=0;j<1023;++j) {
							if(j%16==0) {
								std::cout<<std::endl;
								//ofile<<std::endl;
							}
								std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)bufferSend2[j]<<" ";
								//ofile<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)bufferSend2[j]<<" ";
						}
						std::cout<<std::dec<<std::endl;
						sendto(sockfd4,bufferSend2,1023,0,(struct sockaddr *)&servaddr4,addr_len);
						printf("totalcount=%d\n",totalcount++);
					}
				}	
		    std::copy(buffer+1092*count+start,buffer+left+1092*count+start,bufferSend);										
			}			
		}		
	}
	std::cout<<"receive done"<<std::endl;
	return 0;
}
