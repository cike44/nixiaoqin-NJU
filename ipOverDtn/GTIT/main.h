#ifndef    MAIN_H
#define    MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include <pthread.h>
#include <sched.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  
#include <arpa/inet.h>
#include <signal.h>
#include <ctype.h>

#define EQUIPMENTNUM    96
#define TCP             0
#define UDP             1



extern int    read_config();
extern int serial_config();
extern void  *recvclient(void *argv);
extern void  *tcp_client(void *argv);
extern void  *tcp_client_read(void *argv);
extern void  *starttcp(void *argv);
extern void  *resettcp(void *argv);
extern unsigned char XorSum(unsigned char *data, unsigned char length);



#endif    //MAIN_H

