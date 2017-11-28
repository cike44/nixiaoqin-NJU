#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <string.h>
#include <unistd.h>
int sockfd4=0;
struct sockaddr_in servaddr4;
socklen_t addr_len =sizeof(struct sockaddr_in);
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

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  int * id = (int *)arg;
  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  int i;
  for(i=0; i<pkthdr->len; ++i)
  {
    printf("%02x", packet[i]);
    if( (i + 1) % 16 == 0 )
    {
      printf("\n");
    }
  }
  printf("\n");

  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;//ip包头
  struct sniff_udp *udp;//udp包头
  struct sniff_tcp *tcp;//tcp包头
  u_char *payload;//数据包负载的数据
  int payload_size;//数据包负载的数据大小
  int canBeSent = 1;
  ethernet=(struct sniff_ethernet*)(packet);
  //取出IP包
  ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
  printf("len:%d\n",ntohs(ip->ip_len));

  //is TCP?
  printf("protocol:%d\n",ip->ip_p);
  if(ip->ip_p == 6) {

	tcp=(struct sniff_tcp*)(packet + sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip));
	payload=(u_char *)(packet+sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip)+sizeof(struct sniff_tcp));

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

	libnet_t *lib_net_4 = NULL;
	libnet_ptag_t lib_t0_4 = 0;
	libnet_ptag_t lib_t1_4 = 0;
	libnet_ptag_t lib_t2_4 = 0;
	libnet_ptag_t lib_t3_4 = 0;
	//因为要把IP包封在以太帧中发出去 需要知道发送和接收网卡mac地址
	unsigned char src_mac[6] = {0x00,0xe0,0x4c,0x1b,0x0b,0x39};
	unsigned char dst_mac[6] = {0xc8,0x3a,0x35,0xd4,0x08,0x37};
	unsigned char tcp_op_ack[] = {0x01,0x01,0x08,0x0a,0x02,0x14,0xbc,0xbd,0x02,0x14,0xbc,0xbd};
	//初始化
	lib_net = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);	
	lib_net_2 = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);	
	lib_net_3 = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);	
	lib_net_4 = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);	
	if(NULL == lib_net)
	{
		perror("libnet_init");
		exit(-1);
	}
	if(NULL == lib_net_2)
	{
		perror("libnet_2_init");
		exit(-1);
	}
	if(NULL == lib_net_3)
	{
		perror("libnet_3_init");
		exit(-1);
	}
	if(NULL == lib_net_4)
	{
		perror("libnet_4_init");
		exit(-1);
	}
	  printf("flags:%d\n",tcp->th_flags);
	  switch(tcp->th_flags) {
		  case TH_SYN: {
		  	printf("This is SYN\n");
			//payload is tcp_op at this time			
			lib_t0 = libnet_build_tcp_options(  
				        payload,  
				        20,  
						lib_net,
						lib_t0
			); 
			lib_t1 = libnet_build_tcp(	//构造tcp数据包
									ntohs(tcp->th_dport),
									ntohs(tcp->th_sport),
									0,//seq
									ntohl(tcp->th_seq)+0x1,//ack
									TH_SYN | TH_ACK,//flags
									tcp->th_win,//win
                                    0,//checksum
									0x0,//urp
                                    40,//length
									NULL,//payload
									0,//payload_size
									lib_net,
									lib_t1
			);
			lib_t2 = libnet_build_ipv4(	//构造ip数据包
										20+20+20,//len
										ip->ip_tos,//tos
										id_host++,//id
										ntohs(ip->ip_off),
										ip->ip_ttl,
										ip->ip_p,
										0,
										*(u_int32_t *)&ip->ip_dst,
										*(u_int32_t *)&ip->ip_src,
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
			break;
		  }	  
		  case TH_PUSH | TH_ACK: {
		  	printf("This is DTAT\n");
			payload_size=ntohs(ip->ip_len)-20-20-12;
			printf("payload_size:%d\n",payload_size);
			lib_t0_2 = libnet_build_tcp_options(  
				        tcp_op_ack,  
				        12,  
						lib_net_2,
						lib_t0_2
			); 
			lib_t1_2 = libnet_build_tcp(	//构造tcp数据包
									ntohs(tcp->th_dport),
									ntohs(tcp->th_sport),
									0x1,//seq
									ntohl(tcp->th_seq)+payload_size,//ack
									TH_ACK,//flags
									tcp->th_win,//win
                                    0,//checksum
									0x0,//urp
                                    32,//length
									NULL,//payload
									0,//payload_size
									lib_net_2,
									lib_t1_2
			);
			lib_t2_2 = libnet_build_ipv4(	//构造ip数据包
										20+20+12,
										ip->ip_tos,
										id_host++,
										ntohs(ip->ip_off),
										ip->ip_ttl,
										ip->ip_p,
										0,
										*(u_int32_t *)&ip->ip_dst,
										*(u_int32_t *)&ip->ip_src,
										NULL,
										0,
										lib_net_2,
										lib_t2_2
			);
			lib_t3_2 = libnet_build_ethernet(	//构造以太网数据包
											(u_int8_t *)dst_mac,
											(u_int8_t *)src_mac,
											0x800, // 或者，ETHERTYPE_IP
											NULL,
											0,
											lib_net_2,
											lib_t3_2
			);
			int res = 0;
			res = libnet_write(lib_net_2);	//发送数据包
			if(-1 == res)
			{
				perror("libnet_2_write");
				exit(-1);
			}
			break;
		  }
		  case TH_FIN | TH_ACK: {
		  	printf("This is FIN.\n");
		  	//回ACK包 待合并
			lib_t0_3 = libnet_build_tcp_options(  
				        tcp_op_ack,  
				        12,  
						lib_net_3,
						lib_t0_3
			); 
			lib_t1_3 = libnet_build_tcp(	//构造tcp数据包
									ntohs(tcp->th_dport),
									ntohs(tcp->th_sport),
									ntohl(tcp->th_ack),//seq
									ntohl(tcp->th_seq)+0x1,//ack
									TH_ACK,//flags
									tcp->th_win,//win
                                    0,//checksum
									0x0,//urp
                                    32,//length
									NULL,//payload
									0,//payload_size
									lib_net_3,
									lib_t1_3
			);
			lib_t2_3 = libnet_build_ipv4(	//构造ip数据包
										20+20+12,
										ip->ip_tos,
										id_host++,
										ntohs(ip->ip_off),
										ip->ip_ttl,
										ip->ip_p,
										0,
										*(u_int32_t *)&ip->ip_dst,
										*(u_int32_t *)&ip->ip_src,
										NULL,
										0,
										lib_net_3,
										lib_t2_3
			);
			lib_t3_3 = libnet_build_ethernet(	//构造以太网数据包
											(u_int8_t *)dst_mac,
											(u_int8_t *)src_mac,
											0x800, // 或者，ETHERTYPE_IP
											NULL,
											0,
											lib_net_3,
											lib_t3_3
			);
			int res = 0;
			res = libnet_write(lib_net_3);	//发送数据包
			if(-1 == res)
			{
				perror("libnet_3_write");
				exit(-1);
			}
			break;
		  }
		  case TH_SYN | TH_ACK: {
		  	printf("This is SYN + ACK\n");
		  	//回ACK包，同时记下对方的seq
			host_seq = ntohl(tcp->th_seq)+0x1;
			FILE *fp = NULL;
			fp = fopen("seq.txt", "w");
			char buf[32];
			sprintf(buf,"%d",host_seq);
			fprintf(fp, buf);
			fclose(fp);
			lib_t0_4 = libnet_build_tcp_options(  
				        tcp_op_ack,  
				        12,  
						lib_net_4,
						lib_t0_4
			); 
			lib_t1_4 = libnet_build_tcp(	//构造tcp数据包
									ntohs(tcp->th_dport),
									ntohs(tcp->th_sport),
									ntohl(tcp->th_ack),//seq
									ntohl(tcp->th_seq)+0x1,//ack
									TH_ACK,//flags
									tcp->th_win,//win
                                    0,//checksum
									0x0,//urp
                                    32,//length
									NULL,//payload
									0,//payload_size
									lib_net_4,
									lib_t1_4
			);
			lib_t2_4 = libnet_build_ipv4(	//构造ip数据包
										20+20+12,
										ip->ip_tos,
										id_host++,
										ntohs(ip->ip_off),
										ip->ip_ttl,
										ip->ip_p,
										0,
										*(u_int32_t *)&ip->ip_dst,
										*(u_int32_t *)&ip->ip_src,
										NULL,
										0,
										lib_net_4,
										lib_t2_4
			);
			lib_t3_4 = libnet_build_ethernet(	//构造以太网数据包
											(u_int8_t *)dst_mac,
											(u_int8_t *)src_mac,
											0x800, // 或者，ETHERTYPE_IP
											NULL,
											0,
											lib_net_4,
											lib_t3_4
			);
			int res = 0;
			res = libnet_write(lib_net_4);	//发送数据包
			if(-1 == res)
			{
				perror("libnet_4_write");
				exit(-1);
			}
			canBeSent = 0;
			break;			
		  }	
		  case TH_ACK: {
			printf("This is ACK");
			canBeSent = 0;
			break;
			
		  }
		  default: {
			printf("This is ELSE.\n");
			printf("flags:%d\n",tcp->th_flags);
		  }
  	  }
	  if(canBeSent) {
		  sendto(sockfd4,ip,ntohs(ip->ip_len),0,(struct sockaddr *)&servaddr4,addr_len);
	  }	  	
  }
}

int main(int argc ,char* argv[])
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(argv[1], BUFSIZ, 1, 0, errBuf);
  if(!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
  /* construct a filter */
  struct bpf_program filter;
  //过滤规则设置
  pcap_compile(device, &filter, "tcp and dst net 192.168.1.102 and not icmp", 1, 0);
  pcap_setfilter(device, &filter);
  //过滤出来发到本地的udp 9090端口
  sockfd4=socket(AF_INET,SOCK_DGRAM,0);
  bzero(&servaddr4,sizeof(servaddr4));
  servaddr4.sin_family=AF_INET;
  servaddr4.sin_port=htons(9090);
  inet_pton(AF_INET,"192.168.10.115",&servaddr4.sin_addr);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  pcap_close(device);
  
  return 0;
}
