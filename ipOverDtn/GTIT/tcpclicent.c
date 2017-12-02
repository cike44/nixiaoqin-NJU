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

 extern struct sockaddr_in addr;
 extern struct sockaddr_in serverGet;

//extern config_info config_infomation;

int connectout = 0;

unsigned char recv_server_buff[512];




void *starttcp(void *argv)
{
    int addr_len=sizeof(addr);  
    int getlen=sizeof(serverGet);
      
     //  while(1)
      // {  
 
                 
	                 printf ("Client: Socket Create... ...\n");
	                 sockfd = socket (AF_INET, SOCK_DGRAM,0);
	                 if (sockfd == -1) 
	                 {
		                 perror ("Socket");
	                 }     
                        bind(sockfd,(struct sockaddr*)&serverGet,getlen);
	                // printf ("Client: Address Connect... ...\n");

    
	         printf ("client: send data... ...\n");

	         while(1)
                 {
                             
                       //  printf("recv server data... ...\n");
                         int readnum = 0;
                        // if(reset_tcp == 0)
                        // {
		                    readnum = recvfrom(sockfd,recv_server_buff,sizeof(recv_server_buff), 0, (struct sockaddr *)&serverGet, (socklen_t*)&getlen);
		                    printf("readnum: %d \n",readnum);
		                    if((readnum == -1) || (readnum == 0))
		                    {
			                        perror("recvfrom");
			                        break;
		                    }
                        // }
                        // else
                        // {
                        //            break;
                        // }
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
   // }

}





