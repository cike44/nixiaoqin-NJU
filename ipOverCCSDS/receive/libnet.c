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

	char errBuf[100];
	libnet_t *lib_net = NULL;
	libnet_ptag_t lib_t1 = 0;
libnet_ptag_t lib_t2 = 0;
libnet_ptag_t lib_t3 = 0;
	unsigned char src_mac[6] = {0xb8,0xae,0xed,0x22,0x6c,0xa4};//发送者网卡地址00:0c:29:97:c7:c1
	unsigned char dst_mac[6] = {0xb8,0xae,0xed,0x23,0x3a,0xf0};//接收者网卡地址‎b8:ae:ed:23:3a:f0
	lib_net = libnet_init(LIBNET_LINK_ADV, argv[1], errBuf);	//初始化
	if(NULL == lib_net)
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
		

		struct sniff_ip *ip;//ip包头

				struct sniff_udp *udp;//udp包头


				u_char *payload;//数据包负载的数据

				int payload_size;//数据包负载的数据大小


				ip=(struct sniff_ip*)(buffer);

				udp=(struct sniff_udp*)(buffer+sizeof(struct sniff_ip));

				payload=(u_char *)(buffer+sizeof(struct sniff_ip)+sizeof(struct sniff_udp));

			payload_size=ntohs(udp->udp_len)-sizeof(struct sniff_udp);
		//printf("len:%d %d %d\n",sizeof(struct sniff_ethernet),sizeof(struct sniff_ip),sizeof(struct sniff_udp));
		printf("len:%d,srcport:%d,dstport:%d\n\n",payload_size,ntohs(udp->udp_sport),ntohs(udp->udp_dport));

		lib_t1 = libnet_build_udp(	//构造udp数据包
								ntohs(udp->udp_sport),
								ntohs(udp->udp_dport),
								8+payload_size,
								0,
								payload,
								payload_size,
								lib_net,
								lib_t1
							);

		lib_t2 = libnet_build_ipv4(	//构造ip数据包
									20+8+payload_size,
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

	

	libnet_destroy(lib_net);	//销毁资源
	
	printf("----ok-----\n");
	return 0;
 }
