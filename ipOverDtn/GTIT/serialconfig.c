#include "main.h"

int serialFd;

extern char g_m908_dev_path[];
extern int g_baud;

int serial_config()
{

    struct termios opt; 
	printf("--------------- serial_config :g_m908_dev_path = %s\n", g_m908_dev_path);
    serialFd = open(g_m908_dev_path, O_RDWR | O_NOCTTY);//默认为阻塞读方式
    if(serialFd== -1)
    {
        perror("open serial 0\n");
         return -1;
    }

    tcgetattr(serialFd, &opt);      
    switch( g_baud )
{
	case 9600:
    	cfsetispeed(&opt, B9600);
    	cfsetospeed(&opt, B9600);
	break;

	case 115200:
    	cfsetispeed(&opt, B115200);
    	cfsetospeed(&opt, B115200);
	break;
	
	default:
	printf("baud must 9600 or 115200\n");
	return -1;
	break;
}
    
    if(tcsetattr(serialFd, TCSANOW, &opt) != 0 )
    {     
       perror("tcsetattr error");
       return -1;
    }
    
    opt.c_cflag &= ~CSIZE;  
    opt.c_cflag |= CS8;   
    opt.c_cflag &= ~CSTOPB; 
    opt.c_cflag &= ~PARENB; 
    opt.c_iflag &= ~INPCK;
    opt.c_cflag |=  HUPCL;
    opt.c_cflag |= (CLOCAL | CREAD);
 
    opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG); 
    opt.c_oflag &= ~OPOST;

    opt.c_oflag &= ~(ONLCR | OCRNL); 
 
    opt.c_iflag &= ~(ICRNL | INLCR);
    opt.c_iflag &= ~(IXON | IXOFF | IXANY);  

    opt.c_cc[VTIME] = 1;
    opt.c_cc[VMIN] = 255;
    
    tcflush(serialFd, TCIOFLUSH);
 
    printf("configure complete\n");
    
    if(tcsetattr(serialFd, TCSANOW, &opt) != 0)
    {
        perror("serial error");
        return -1;
    }
    return 0;	
}

