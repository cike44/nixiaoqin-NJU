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
/*UDP报头*/
struct sniff_udp
{
	u_short udp_sport;
	u_short udp_dport;
	u_short udp_len;
	u_short udp_sum;
};
int main(int argc, char *argv[])
{
	int sockfd2=0;
	struct sockaddr_in servaddr2;
	sockfd2=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr2,sizeof(servaddr2));
	servaddr2.sin_family=AF_INET;
	servaddr2.sin_port=htons(5010);
	servaddr2.sin_addr.s_addr=htonl(INADDR_ANY) ;
	bind(sockfd2, (struct sockaddr *)&servaddr2, sizeof(servaddr2));
    int count =0;
	char errBuf[100];
	libnet_t *lib_net = NULL;
	libnet_ptag_t lib_t1 = 0;
    libnet_ptag_t lib_t2 = 0;
    libnet_ptag_t lib_t3 = 0;

	libnet_t *lib_net_1 = NULL;
	libnet_ptag_t lib_t1_1 = 0;
    libnet_ptag_t lib_t2_1 = 0;
    libnet_ptag_t lib_t3_1 = 0;
	//因为要把IP包封在以太帧中发出去 需要知道发送和接收网卡mac地址
	unsigned char src_mac[6] = {0x00,0x07,0x32,0x3f,0xe2,0x23};//发送者网卡地址00:0c:29:97:c7:c1 0x00,0x07,0x32,0x3f,0xe2,0x23
	unsigned char dst_mac[6] = {0xb8,0xae,0xed,0x23,0x8e,0x96};//接收者网卡地址‎b8:ae:ed:23:3a:f0 0xb8,0xae,0xed,0x23,0x3c,0xe3
	lib_net = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);	//初始化
	//因为要根据IP包长度分开处理 需要新建两个
	if(NULL == lib_net)
	{
		perror("libnet_init");
		exit(-1);
	}
	lib_net_1 = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);	//初始化
	if(NULL == lib_net_1)
	{
		perror("libnet_init");
		exit(-1);
	}
	unsigned char buffer[5000];
	unsigned char buffer1[1480];
	unsigned char buffer2[1480];
	struct sockaddr_in addr;
	socklen_t addr_len =sizeof(struct sockaddr_in);
	int len=0;
	while(1)
	{
		bzero(buffer,sizeof(buffer));
		len = recvfrom(sockfd2,buffer,sizeof(buffer), 0 , (struct sockaddr *)&addr ,&addr_len);
		printf("receive %s: len:%d\n",sock_ntop((struct sockaddr *)&addr,addr_len),len);
		
		struct sniff_ip *ip;//ip包头
		struct sniff_udp *udp;//udp包头
		u_char *payload;//负载数据
		int payload_size;//负载数据大小

		ip=(struct sniff_ip*)(buffer);//IP 				
		udp=(struct sniff_udp*)(buffer+sizeof(struct sniff_ip));//udp
		payload=(u_char *)(buffer+sizeof(struct sniff_ip)+sizeof(struct sniff_udp));//payload
		payload_size=ntohs(ip->ip_len)-20-8;//payloadsize

		printf("ip-len:%d\n",ntohs(ip->ip_len));
		printf("ip-id:%x,ip-off:%x\n",ntohs(ip->ip_id),ntohs(ip->ip_off));
		printf("protocol:%d\n",ip->ip_p);
		printf("1\n");
		//可能会收到一个大于1500字节超过MTU的IP包，需要分片
		if(ntohs(ip->ip_len)<=1500)
		{
			printf("2-zhengchang\n");
			u_char *ip_1;
			ip_1=(u_char *)(buffer);
			lib_t1 = libnet_build_ethernet(	//构造以太网数据包
											(u_int8_t *)dst_mac,
											(u_int8_t *)src_mac,
											0x800, // 或者，ETHERTYPE_IP
											ip_1,//ip
											ntohs(ip->ip_len),//ip-len
											lib_net,
											lib_t1
										);
			int res = 0;
			res = libnet_write(lib_net);	//发送数据包
			memset(buffer,0,sizeof(buffer));
			if(-1 == res)
			{
				perror("libnet_write");
				exit(-1);
			}
		}
        else 
		{
			//根据IP协议规则来进行分片
			printf("3-dayu mtu\n");
			printf("ip-len:%d\n",ntohs(ip->ip_len));
			int count=(ntohs(ip->ip_len)-20)/1480+1;
			printf("count=%d\n",count);
			unsigned short offset=0x0000;
			int i=0;
			int last=0;
			for( i=0;i<count;i++)
			{
				printf("i=%d\n",i);
				int leftsize;
				leftsize=ntohs(ip->ip_len)-1480*i-20;
				//printf("size:%d\n",size);
				if(leftsize<=1480) 
					last=1;
				printf("leftsize:%d\n",leftsize);
				printf("last:%d\n",last);
				if(last==0) {
					memcpy(buffer1,buffer+20+1480*i,1480);
					u_char *tp;
					tp=(u_char *)(buffer1);
					printf("4-bushizuihou\n");
					offset=0x00b9*i|0x2000;
					printf("offset:%x\n",offset);
					lib_t1_1 = libnet_build_ipv4(	//构造ip数据包
										1500,
										ip->ip_tos,
										ntohs(ip->ip_id),
										offset,
										ip->ip_ttl,
										ip->ip_p,
										0,
										*(u_int32_t *)&ip->ip_src,
										*(u_int32_t *)&ip->ip_dst,
										tp,
										1480,
										lib_net_1,
										lib_t1_1
									);
					lib_t2_1 = libnet_build_ethernet(	//构造以太网数据包
											(u_int8_t *)dst_mac,
											(u_int8_t *)src_mac,
											0x800, // 或者，ETHERTYPE_IP
											NULL,
											0,
											lib_net_1,
											lib_t2_1
										);
					int res1 = 0;
					res1 = libnet_write(lib_net_1);	//发送数据包
					memset(buffer1,0,sizeof(buffer1));
				}
				else 
				{
					printf("5-shizuihou\n");
					printf("leftsize:%d\n",leftsize);
					memcpy(buffer1,buffer+20+1480*i,leftsize);
					u_char *tp;
					tp=(u_char *)(buffer1);
					offset=0x00b9*i|0x0000;
					printf("offset:%x\n",offset);
					lib_t1_1 = libnet_build_ipv4(	//构造ip数据包
										leftsize+20,
										ip->ip_tos,
										ntohs(ip->ip_id),
										offset,
										ip->ip_ttl,
										ip->ip_p,
										0,
										*(u_int32_t *)&ip->ip_src,
										*(u_int32_t *)&ip->ip_dst,
										tp,
										leftsize,
										lib_net_1,
										lib_t1_1
									);

					lib_t2_1 = libnet_build_ethernet(	//构造以太网数据包
											(u_int8_t *)dst_mac,
											(u_int8_t *)src_mac,
											0x800, // 或者，ETHERTYPE_IP
											NULL,
											0,
											lib_net_1,
											lib_t2_1
										);
					int res1 = 0;
					res1 = libnet_write(lib_net_1);	//发送数据包
					memset(buffer1,0,sizeof(buffer1));
					memset(buffer,0,sizeof(buffer));	
					bzero(buffer,sizeof(buffer));	
					printf("clean\n");	
				}
			}				
	   }
	}
	libnet_destroy(lib_net);	//销毁资源
	libnet_destroy(lib_net_1);	//销毁资源
	printf("----ok-----\n");
	return 0;
 }
