#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>
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
/*以太网头*/
struct sniff_ethernet
{
        u_char ether_dhost[ETHER_ADDR_LEN];
        u_char ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};
/*IP头*/
int id_host = 0;
struct sniff_ip
{
        u_char ip_vhl;
        u_char ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl;
         u_char ip_p;
        u_short ip_sum;
        struct in_addr ip_src,ip_dst;
};
/* TCP header */  
typedef u_int tcp_seq;   
tcp_seq host_seq = 0;
struct sniff_tcp {  
	u_short th_sport;               /* source port */  
	u_short th_dport;               /* destination port */  
	tcp_seq th_seq;                 /* sequence number */  
	tcp_seq th_ack;                 /* acknowledgement number */      
	u_char  th_offx2;               /* data offset, rsvd */  
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)  
	u_char  th_flags;  
	#define TH_FIN  0x01  
	#define TH_SYN  0x02  
	#define TH_RST  0x04  
	#define TH_PUSH 0x08  
	#define TH_ACK  0x10  
	#define TH_URG  0x20  
	#define TH_ECE  0x40  
	#define TH_CWR  0x80  
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)  
	u_short th_win;                 /* window */  
	u_short th_sum;                 /* checksum */  
	u_short th_urp;                 /* urgent pointer */  
}; 
/*UDP报头*/
struct sniff_udp
{
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_len;
  u_short udp_sum;
};
void convertStrToUnChar(char* str, unsigned char* UnChar)  
{  
    int i = strlen(str), j = 0, counter = 0;  
    char c[2];  
    unsigned int bytes[2];  
  
    for (j = 0; j < i; j += 2)   
    {  
        if(0 == j % 2)  
        {  
            c[0] = str[j];  
            c[1] = str[j + 1];  
            sscanf(c, "%02x" , &bytes[0]);  
            UnChar[counter] = bytes[0];  
            counter++;  
        }  
    }  
    return;  
} 
void changeTimestamp(unsigned char* tcp, int len) { 

	FILE *fp1 = NULL;
	unsigned char jiffies[4];
	fp1 = fopen("/proc/jiffies", "r");
	fscanf(fp1,"%s",jiffies);
	printf("jiffies-zifuchuan:%s\n", jiffies);
	u_int timestamp = atoi(jiffies);
    printf("timestamp:%08x\n", timestamp);
    unsigned char temp[8];
	sprintf(temp,"%08x",timestamp);

	FILE *fp2 = NULL;
	unsigned char jiffies_remote[4];
	fp1 = fopen("jiffies.txt", "r");
	fscanf(fp1,"%s",jiffies_remote);
	printf("jiffies_remote-zifuchuan:%s\n", jiffies_remote);
	u_int timestamp_remote = atoi(jiffies_remote);
    printf("timestamp_remote:%08x\n", timestamp_remote);
    unsigned char temp2[8];
	sprintf(temp2,"%08x",timestamp_remote);

	int start = 0;
	if(len == 12) {
		start = 22;
	} else {
		start = 28;
	}
	
    int i,j = 0;
	for(i=0; i<8; i+=2)
	{
		unsigned char temp3[] = {"0x"};
        strncpy(temp3+2,temp+i,2);
		tcp[start+j] = strtoul(temp3,NULL,16);
		if(len == 12) {
	        strncpy(temp3+2,temp2+i,2);	
			tcp[start+j+4] = strtoul(temp3,NULL,16);
		}
        j++;
	}
	fclose(fp1);	
}
int main(int argc, char *argv[])
{
	int sockfd2=0;
	struct sockaddr_in servaddr2;
	sockfd2=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr2,sizeof(servaddr2));
	servaddr2.sin_family=AF_INET;
	servaddr2.sin_port=htons(9090);
	servaddr2.sin_addr.s_addr=htonl(INADDR_ANY) ;
	bind(sockfd2, (struct sockaddr *)&servaddr2, sizeof(servaddr2));

	char errBuf[100];
	libnet_t *lib_net = NULL;
	libnet_ptag_t lib_t0 = 0;
	libnet_ptag_t lib_t1 = 0;
	libnet_ptag_t lib_t2 = 0;
	libnet_ptag_t lib_t3 = 0;

	libnet_t *lib_net_2 = NULL;
	libnet_ptag_t lib_t0_2 = 0;
	libnet_ptag_t lib_t1_2 = 0;
	libnet_ptag_t lib_t2_2 = 0;
	libnet_ptag_t lib_t3_2 = 0;

	libnet_t *lib_net_3 = NULL;
	libnet_ptag_t lib_t0_3 = 0;
	libnet_ptag_t lib_t1_3 = 0;
	libnet_ptag_t lib_t2_3 = 0;
	libnet_ptag_t lib_t3_3 = 0;
	unsigned char src_mac[6] = {0x00,0xe0,0x4c,0x1a,0x02,0x3b};
	unsigned char dst_mac[6] = {0xc8,0x3a,0x35,0xd4,0x08,0x37};//00:e0:4c:1a:02:3b
	lib_net = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);	//初始化
	if(NULL == lib_net)
	{
		perror("libnet_init");
		exit(-1);
	}
	lib_net_2 = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);	//初始化
	if(NULL == lib_net_2)
	{
		perror("libnet_init");
		exit(-1);
	}
	lib_net_3 = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);	//初始化
	if(NULL == lib_net_3)
	{
		perror("libnet_init");
		exit(-1);
	}
	unsigned char buffer[5000];
	struct sockaddr_in addr;
	socklen_t addr_len =sizeof(struct sockaddr_in);
	int len=0;
	while(1){
		bzero(buffer,sizeof(buffer));
		len = recvfrom(sockfd2,buffer,sizeof(buffer), 0 , (struct sockaddr *)&addr ,&addr_len);
		printf("receive %s: len:%d\n",sock_ntop((struct sockaddr *)&addr,addr_len),len);
		struct sniff_ip *ip;
		ip=(struct sniff_ip*)(buffer);
		printf("ip-len:%d\n",ntohs(ip->ip_len));
		printf("ip-id:%x,ip-off:%x\n",ntohs(ip->ip_id),ntohs(ip->ip_off));
		printf("protocol:%d\n",ip->ip_p);
		if(ip->ip_p == 6){
			struct sniff_tcp *tcp;
			u_char *payload;//数据包负载的数据
  			int payload_size;//数据包负载的数据大小
			tcp=(struct sniff_tcp*)(buffer +sizeof(struct sniff_ip));

			printf("flags:%d\n",tcp->th_flags);
			//如果是SYN包，不变
			if(tcp->th_flags == TH_SYN){
				printf("This is SYN,nothing to do.\n");
				u_char *ip_0;
				ip_0=(u_char *)(buffer);
				lib_t0_3 = libnet_build_ethernet(	//构造以太网数据包
					(u_int8_t *)dst_mac,
					(u_int8_t *)src_mac,
					0x800, // 或者，ETHERTYPE_IP
					ip_0,//ip
					ntohs(ip->ip_len),//ip-len
					lib_net_3,
					lib_t0_3
				);
				int res = 0;
				res = libnet_write(lib_net_3);	//发送数据包
				memset(buffer,0,sizeof(buffer));
				if(-1 == res)
				{
					perror("libnet_3_write");
					exit(-1);
				}	
			}
			else {
				if(tcp->th_flags == TH_PUSH | TH_ACK){
					//数据包需要更改ack序列号,更改对端时间戳
					printf("This is DATA.\n");
				}else if(tcp->th_flags == TH_FIN | TH_ACK) {
					printf("This is FIN.\n");
				}else {
					printf("This is ELSE.\n");
				}
				payload=(u_char *)(buffer+sizeof(struct sniff_ip)+sizeof(struct sniff_tcp)+12);
				printf("payload:%s\n",payload);
				payload_size=ntohs(ip->ip_len)-20-20-12;
				printf("payload_size:%d\n",payload_size);
				//从外部读入当前应有的seq
				FILE *fp = NULL;
				char buff[255];
				fp = fopen("seq.txt", "r");
				fscanf(fp, "%s", buff);
				u_int host_seq = atoi(buff);
				printf("host_seq:\n");
				printf("%02x\n",host_seq);
				fclose(fp);
				//从外部读入对端时间戳
				unsigned char tcp_op_data[12];
				u_char *tcp_op;//数据包负载的数据
				tcp_op=(u_char *)(buffer+sizeof(struct sniff_ip)+sizeof(struct sniff_tcp));
				memcpy(tcp_op_data,tcp_op,12);
				FILE *fp1 = NULL;
				fp1 = fopen("timestamp.txt", "r");
				unsigned char temp[5];
				fgets(temp, 5, fp1);
				printf("timestamp:\n");
				int i = 0;
				for(i=0;i<4;++i){
					printf("%02x",temp[i]);
					tcp_op_data[8+i]=temp[i];
				}
				printf("\n");
				fclose(fp1);

				lib_t0 = libnet_build_tcp_options(  
						tcp_op_data,  
						12,  
						lib_net,
						lib_t0
				); 
				lib_t1 = libnet_build_tcp(	//构造tcp数据包
										ntohs(tcp->th_sport),
										ntohs(tcp->th_dport),
										ntohl(tcp->th_seq),//seq
										host_seq,//ack
										tcp->th_flags,//flags
										ntohs(tcp->th_win),//win
			                    		0,//checksum
										0x0,//urp
			                    		32,//length
										payload,//payload
										payload_size,//payload_size
										lib_net,
										lib_t1
				);
				lib_t2 = libnet_build_ipv4(	//构造ip数据包
											20+20+12+payload_size,
											ip->ip_tos,
											ntohs(ip->ip_id),
											ntohs(ip->ip_off),
											ip->ip_ttl,
											ip->ip_p,
											0,
											*(u_int32_t *)&ip->ip_src,
											*(u_int32_t *)&ip->ip_dst,
											NULL,
											0,
											lib_net,
											lib_t2
				);
				lib_t3 = libnet_build_ethernet(	//构造以太网数据包
												(u_int8_t *)dst_mac,
												(u_int8_t *)src_mac,
												0x800, // 或者，ETHERTYPE_IP
												NULL,
												0,
												lib_net,
												lib_t3
				);
				int res = 0;
				res = libnet_write(lib_net);	//发送数据包
				if(-1 == res)
				{
					perror("libnet_write");
					exit(-1);
				}
			}

		} else {
			//非TCP包直传
			u_char *ip_1;
			ip_1=(u_char *)(buffer);
			lib_t0_2 = libnet_build_ethernet(	//构造以太网数据包
				(u_int8_t *)dst_mac,
				(u_int8_t *)src_mac,
				0x800, // 或者，ETHERTYPE_IP
				ip_1,//ip
				ntohs(ip->ip_len),//ip-len
				lib_net_2,
				lib_t0_2
			);
			int res = 0;
			res = libnet_write(lib_net_2);	//发送数据包
			memset(buffer,0,sizeof(buffer));
			if(-1 == res)
			{
				perror("libnet_2_write");
				exit(-1);
			}		
		}
	}	
	libnet_destroy(lib_net);	//销毁资源	
	libnet_destroy(lib_net_2);	//销毁资源		
	printf("----ok-----\n");
	return 0;
 }

