#include "main.h"

int serialFd; 
int sockfd;
int reset_tcp = 1;

struct sockaddr_in addr;

struct sockaddr_in serverGet;

extern int readnum;


char g_m908_dev_path[32]	 = {};
char g_tcp_host[32]	 = {};//IP
int  g_tcp_port	= 0;
int g_baud = 115200;



int main(int argc, char *argv[]){
   
   int ret = 0;

   
   if ( argc != 5 ){
	printf("Command parameter error !\n");
	printf("For example: ./GTIT /dev/ttyS0 115200 10.10.60.28 5000\n");
	return -1;
   }
   if (strlen( argv[1] ) > 30 )
   {
		printf("m908 device path len must less than 30\n");
		return -1;
   }	
   if (strlen( argv[2] ) > 10 )
   {
		printf("m908 device baud len must less than 10\n");
		return -1;
   }	
   if (strlen( argv[3] ) > 30 )
   {
		printf("transfrom host len must less than 30\n");
		return -1;	
   }
   if (strlen( argv[4] ) > 10 )
   {
		printf("transfrom port len must less than 10\n");
		return -1;	
   }
   strcpy(g_m908_dev_path, argv[1]);
   g_baud = atoi(argv[2]);
   strcpy(g_tcp_host, argv[3]);
   g_tcp_port = atoi(argv[4]);


   addr.sin_family = AF_INET;
   addr.sin_port = htons (g_tcp_port);
   addr.sin_addr.s_addr = inet_addr(g_tcp_host);
   
   serverGet.sin_family=AF_INET;  
   serverGet.sin_port=htons(7089);  
   serverGet.sin_addr.s_addr=INADDR_ANY;

   printf("m908 device path=%s\n", g_m908_dev_path);
   printf("m908 device baud=%d\n", g_baud);
   printf("transfrom host=%s\n",g_tcp_host);
   printf("transfrom port=%d\n",g_tcp_port);

    ret =serial_config();
   if (ret != 0)
	{
	return -1;
	}
   
   pthread_t pthread_start;
   ret = pthread_create(&pthread_start, NULL, (void *)starttcp, NULL);
   if (ret != 0)
   {
      printf("create pthread pthread_start fail\n");
      exit(1);
   }

   while(1)
   {    
     
        int length = 0;
        unsigned char read_buff[512] = {0};
        printf("Read serialFd data begin... ...\n");
        length = read(serialFd, read_buff, sizeof(read_buff));
        printf("recv serial data length: %d \n",length);
        if(length == -1)
        {  
            perror("read");
        }
        printf("recv of data from serial:");
        int num = 0;            
        for(num = 0; num < length; num++)
        {           
           printf("%hhx ",read_buff[num]);
        }
        printf("\n");
        
        printf("read serialFd data end !!! \n");
     
        if((length != 0) && (reset_tcp == 0))
        {
            printf("Send data to server... ...\n");

            int sendnum = sendto (sockfd,&read_buff,length, 0, (struct sockaddr *)&addr, sizeof(addr));
            printf("send data to server length:%d \n",sendnum);
            if ( sendnum == -1 ||sendnum == 0)
            {
                perror ("Sendto");
                close(sockfd);
            }
            printf("Send data to server end !!! \n");
        }
    }
}
