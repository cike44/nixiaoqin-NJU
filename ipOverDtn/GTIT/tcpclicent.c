#include "main.h"
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


extern int sockfd;
extern int serialFd;
extern int reset_tcp;


 extern  char g_tcp_host[]	;
 extern  int  g_tcp_port;
//extern config_info config_infomation;

int connectout = 0;

unsigned char recv_server_buff[512];


int set_tcp_keepAlive(int fd, int start, int interval, int count)  
{  
    int keepAlive = 1;  
    if (fd < 0 || start < 0 || interval < 0 || count < 0) return -1;  
    //启用心跳机制，如果您想关闭，将keepAlive置零即可  
    if(setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,(void*)&keepAlive,sizeof(keepAlive)) == -1)  
    {  
        perror("setsockopt");  
        return -1;  
    }  
    //启用心跳机制开始到首次心跳侦测包发送之间的空闲时间  
    if(setsockopt(fd,SOL_TCP,TCP_KEEPIDLE,(void *)&start,sizeof(start)) == -1)  
    {  
        perror("setsockopt");  
        return -1;  
    }  
    //两次心跳侦测包之间的间隔时间  
    if(setsockopt(fd,SOL_TCP,TCP_KEEPINTVL,(void *)&interval,sizeof(interval)) == -1)  
    {  
        perror("setsockopt");  
        return -1;  
    }  
    //探测次数，即将几次探测失败判定为TCP断开  
    if(setsockopt(fd,SOL_TCP,TCP_KEEPCNT,(void *)&count,sizeof(count)) == -1)  
    {  
        perror("setsockopt");  
        return -1;  
    }  
    return 0;  
}

void *starttcp(void *argv)
{
      
       while(1)
       {  
 
                 while(1)
                 { 
                 
	                 printf ("Client: Socket Create... ...\n");
	                 sockfd = socket (AF_INET, SOCK_STREAM,0);
	                 if (sockfd == -1) 
	                 {
		                 perror ("Socket");
	                 }     
	                 printf ("Client: Address Connect... ...\n");
	    
		             set_tcp_keepAlive(sockfd,2,2,2);
		
	                 struct sockaddr_in addr;
	                 addr.sin_family = AF_INET;
	                 addr.sin_port = htons (g_tcp_port);
	                 addr.sin_addr.s_addr = inet_addr(g_tcp_host);
            
	                 if ((reset_tcp = connect (sockfd,(struct sockaddr*)&addr,sizeof (addr)))==-1)
	                 {   
                                       printf("reset_tcp: %d \n",reset_tcp);
	                               perror ("connect");   
                
	                 }
                         if(reset_tcp == 0)
                         {
                               break;
                         }
                         close(sockfd); 
                      sleep(2);						 
                 }
	         printf ("client: send data... ...\n");

	         while(1)
                 {
                             
                         printf("recv server data... ...\n");
                         int readnum = 0;
                         if(reset_tcp == 0)
                         {
		                    readnum = read(sockfd,recv_server_buff,sizeof(recv_server_buff));
		                    printf("readnum: %d \n",readnum);
		                    if((readnum == -1) || (readnum == 0))
		                    {
			                        perror("read");
			                        break;
		                    }
                         }
                         else
                         {
                                    break;
                         }
                         printf("recv server data end !!! !!!\n");        
                         printf("send server data to serial ... ...\n");
                         int n = write (serialFd,recv_server_buff,readnum);
                         if(n == -1)
                         {
                                perror("write");
                                break;
                         }
                         printf("send server datai to serial end !!! !!! \n");
                         int num = 0;
                         for(num = 0;num < readnum; num++)
                         {
                                    printf("%hhx ",recv_server_buff[num]);
                         }
                         printf("\n");
                 }
        close(sockfd);
    }

}





