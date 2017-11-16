#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <netinet/ip.h>  
#include <arpa/inet.h>  
#include <unistd.h>  
#include <errno.h>  
#include <pthread.h>  
#define MAXCONN 2  
#define ERRORCODE -1  
#define BUFFSIZE 1024  
int count_connect = 0;  
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;  
struct pthread_socket  
{  
    int socket_d;  
    pthread_t thrd;  
};  
static void *thread_send(void *arg)  
{  
    char buf[BUFFSIZE];  
    int sd = *(int *) arg;  
    memset(buf, 0, sizeof(buf));  
    strcpy(buf, "hello,welcome to you! \n");  
    if (send(sd, buf, strlen(buf), 0) == -1)  
    {  
        printf("send error:%s \n", strerror(errno));  
        return NULL;  
    }  
    while (1)  
    {  
        memset(buf, 0, sizeof(buf));  
        read(STDIN_FILENO, buf, sizeof(buf));  
        if (send(sd, buf, strlen(buf), 0) == -1)  
        {  
            printf("send error:%s \n", strerror(errno));  
            break;  
        }  
    }  
    return NULL;  
}  
static void* thread_recv(void *arg)  
{  
    char buf[BUFFSIZE];  
    struct pthread_socket *pt = (struct pthread_socket *) arg;  
    int sd = pt->socket_d;  
    pthread_t thrd = pt->thrd;  
    while (1)  
    {  
        memset(buf, 0, sizeof(buf));  
        int rv = recv(sd, buf, sizeof(buf), 0); 
        //是阻塞的 
        if (rv < 0)  
        {  
            printf("recv error:%s \n", strerror(errno));  
            break;  
        }  
        // 这种情况说明client已经关闭socket连接  
        if (rv == 0) 
        {  
                break;  
        }  
        printf("%s", buf); 
    }  
    pthread_cancel(thrd);  
    pthread_mutex_lock(&mutex);  
    count_connect--;  
    pthread_mutex_unlock(&mutex);  
    close(sd);  
    return NULL;  
}  
  
static int create_listen(int port)  
{  
  
        int listen_st;  
        struct sockaddr_in sockaddr;  
        int on = 1;  
        listen_st = socket(AF_INET, SOCK_STREAM, 0);  
        if (listen_st == -1)  
        {  
            printf("socket create error:%s \n", strerror(errno));  
            return ERRORCODE;  
        }  
        //设置ip地址可重用  
        if (setsockopt(listen_st, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) 
        {  
            printf("setsockopt error:%s \n", strerror(errno));  
            return ERRORCODE;  
        }  
        //指定一个端口号并将hosts字节型传化成Inet型字节型（大端或或者小端问题）  
        sockaddr.sin_port = htons(port); 
        //设置结构类型为TCP/IP
        sockaddr.sin_family = AF_INET; 
        //服务端是等待别人来连，不需要找谁的ip   
        sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);    
        //这里写一个常量INADDR_ANY表示server上所有ip，这个一个server可能有多个ip地址，因为可能有多块网卡 
        if (bind(listen_st, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1)  
        {  
            printf("bind error:%s \n", strerror(errno));  
            return ERRORCODE;  
        }  
  
        if (listen(listen_st, 5) == -1) 
        {  
            printf("listen error:%s \n", strerror(errno));  
            return ERRORCODE;  
        }  
        return listen_st;  
}  
  
int accept_socket(int listen_st)  
{  
        int accept_st;  
        struct sockaddr_in accept_sockaddr;   
        socklen_t addrlen = sizeof(accept_sockaddr);  
        memset(&accept_sockaddr, 0, addrlen);  
        accept_st = accept(listen_st, (struct sockaddr*) &accept_sockaddr,&addrlen);  
        //accept 会阻塞直到客户端连接连过来 服务端这个socket只负责listen 是不是有客服端连接过来了  
        //是通过accept返回socket通信的  
        if (accept_st == -1)  
        {  
            printf("accept error:%s \n", strerror(errno));  
            return ERRORCODE;  
        }  
        printf("accpet ip:%s \n", inet_ntoa(accept_sockaddr.sin_addr));  
        return accept_st;  
}  
int run_server(int port)  
{  
        int listen_st = create_listen(port);      
        pthread_t send_thrd, recv_thrd;  
        struct pthread_socket ps;  
        int accept_st;  
        if (listen_st == -1)  
        {  
            return ERRORCODE;  
        }  
        printf("server start \n");  
        while (1)  
        {  
            accept_st = accept_socket(listen_st); 
            if (accept_st == -1)  
            {  
                    return ERRORCODE;  
            }  
            if (count_connect >= MAXCONN)  
            {  
                    printf("connect have already be full! \n");  
                    close(accept_st);  
                    continue;  
            }  
            pthread_mutex_lock(&mutex);  
            count_connect++;  
            pthread_mutex_unlock(&mutex);  
            if (pthread_create(&send_thrd, NULL, thread_send, &accept_st) != 0)
            {  
                    printf("create thread error:%s \n", strerror(errno));  
                    break;  
  
            }  
            //设置线程可分离性，这样的话主线程就不用join
            pthread_detach(send_thrd);          
            ps.socket_d = accept_st;  
            ps.thrd = send_thrd;  
            if (pthread_create(&recv_thrd, NULL, thread_recv, &ps) != 0)
            {  
                    printf("create thread error:%s \n", strerror(errno));  
                    break;  
            }  
            pthread_detach(recv_thrd);  
        }  
    close(accept_st);  
    close(listen_st);  
    return 0;  
}  
int main(int argc, char *argv[])  
{  
        if (argc < 2)  
        {  
            printf("Usage:port,example:8080 \n");  
            return -1;  
        }  
        int port = atoi(argv[1]);  
        if (port == 0)  
        {  
            printf("port error! \n");  
        }   
    else  
        {  
            run_server(port);  
        }  
    return 0;  
}  
