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
int id_host = 0;
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
tcp_seq remote_seq = 0;  
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
void fetchTcpOp(unsigned char* dst, unsigned char* src, int len) {
	int start = 0;
	if(len == 12) {
		start = 4;
	} else {
		start = 8;
	}
	memcpy(dst,src,len); 
	FILE *fp1 = NULL;
	unsigned char jiffies[4];
	fp1 = fopen("/proc/jiffies", "r");
	fscanf(fp1,"%s",jiffies);
	//printf("jiffies-zifuchuan:%s\n", jiffies);
	u_int timestamp = atoi(jiffies);
    printf("host_timestamp:%08x\n", timestamp);
    unsigned char temp[8];
	sprintf(temp,"%08x",timestamp);
    int i,j = 0;
	for(i=0; i<8; i+=2)
	{
		unsigned char temp2[] = {"0x"};
        strncpy(temp2+2,temp+i,2);
		dst[start+j+4] = dst[start+j];
		dst[start+j] = strtoul(temp2,NULL,16);
        j++;
	}
	fclose(fp1);	
}
void writeRemoteSeq(tcp_seq seq, int size){
	//记下对方seq
	tcp_seq remote_seq = 0; 
	remote_seq = ntohl(seq)+size;
	FILE *fp = NULL;
	fp = fopen("remote_seq.txt", "w");
	printf("remember remote_seq:\n");
	printf("%08x:\n",remote_seq);
	char buff3[32];
	sprintf(buff3,"%d",remote_seq);
	fprintf(fp, buff3);
	fclose(fp);
}
tcp_seq readRemoteSeq() {
	tcp_seq remote_seq;
	FILE *fp_3 = NULL;
	char buff3[255];
	fp_3 = fopen("remote_seq.txt", "r");
	fscanf(fp_3, "%s", buff3);
	remote_seq = atoi(buff3);
	printf("remote_seq:\n");
	printf("%02x\n",remote_seq);
	fclose(fp_3);
	return remote_seq;
}
void writeRemoteTime(unsigned char* payload, int len){
	//记下对方时间戳
	int start = 0;
	if(len == 20) {
		start = 8;
	} else {
		start = 4;
	}
	FILE *fp2 = NULL;
	fp2 = fopen("timestamp.txt", "w");
	printf("remember remote_timestamp:\n");
	int i = 0;
	for(i=0; i<4; ++i){
		printf("%02x",payload[i+start]);
		fputc(payload[i+start],fp2);
	}
	printf("\n");
	fclose(fp2);
}
tcp_seq readHostSeq(){
	//从外部读入主机seq
	tcp_seq host_seq;
	FILE *fp_1 = NULL;
	char buff1[255];
	fp_1 = fopen("host_seq.txt", "r");
	fscanf(fp_1, "%s", buff1);
	host_seq = atoi(buff1);
	printf("read host_seq:\n");
	printf("%02x\n",host_seq);
	fclose(fp_1);
	return host_seq;
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	int * id = (int *)arg;
	printf("id: %d\n", ++(*id));
	printf("Packet length: %d\n", pkthdr->len);
	printf("Number of bytes: %d\n", pkthdr->caplen);
	printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
	//因为要把IP包封在以太帧中发出去 需要知道发送和接收网卡mac地址
	unsigned char src_mac[6] = {0x00,0xe0,0x4c,0x1b,0x0b,0x2a};
	unsigned char dst_mac[6] = {0x00,0xe0,0x4c,0x1b,0x0b,0x39};
	//unsigned char src_mac[6] = {0x00,0xe0,0x4c,0x1a,0x02,0x3b};
	//unsigned char dst_mac[6] = {0xc8,0x3a,0x35,0xd4,0x08,0x37};
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;//ip包头
	struct sniff_udp *udp;//udp包头
	struct sniff_tcp *tcp;//tcp包头
	u_char *payload;//数据包负载的数据
	int payload_size;//数据包负载的数据大小
	//标志位 不传tcp的ack包
	int canBeSent = 1;
	ethernet=(struct sniff_ethernet*)(packet);
	//取出IP包
	ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
	printf("len:%d\n",ntohs(ip->ip_len));
	printf("protocol:%d\n",ip->ip_p);
	//is TCP?
	if(ip->ip_p == 6) {
		tcp=(struct sniff_tcp*)(packet + sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip));
		printf("flags:%d\n",tcp->th_flags);
		//注意payload包含tcp_op
		payload=(u_char *)(packet+sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip)+sizeof(struct sniff_tcp));
		//记下对端的seq和timestamp
		writeRemoteSeq(tcp->th_seq,0);	
		if(tcp->th_flags == TH_SYN | tcp->th_flags == (TH_SYN|TH_ACK)) {
			//tcp_op length=20
			writeRemoteTime(payload,20);
		} else {
			writeRemoteTime(payload,12);
		}
		//回包的类型有三种 SYN+ACK ACK RST
		char errBuf[100];
		libnet_t *lib_net_1 = NULL;
		libnet_ptag_t lib_t0_1 = 0;
		libnet_ptag_t lib_t1_1 = 0;
		libnet_ptag_t lib_t2_1 = 0;
		libnet_ptag_t lib_t3_1 = 0;

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

		//初始化
		lib_net_1 = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);	
		lib_net_2 = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);	
		lib_net_3 = libnet_init(LIBNET_LINK_ADV, "eth0", errBuf);		
		if(NULL == lib_net_1)
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
		  
		switch(tcp->th_flags) {
		  	case TH_SYN: {
			  	printf("This is SYN.\n");
				//回SYN+ACK包，使用本机seq和时间戳，ack用对方的
				unsigned char tcp_op_syn_and_ack[20];
				//rewrite timestamp
				fetchTcpOp(tcp_op_syn_and_ack,payload,20);			
				lib_t0_1 = libnet_build_tcp_options(  
			        tcp_op_syn_and_ack,  
			        20,  
					lib_net_1,
					lib_t0_1
				); 
				host_seq = readHostSeq();
				lib_t1_1 = libnet_build_tcp(	
					ntohs(tcp->th_dport),
					ntohs(tcp->th_sport),
					host_seq,//本机seq
					ntohl(tcp->th_seq)+0x1,//ack发包的seq+1
					TH_SYN | TH_ACK,//flags
					ntohs(tcp->th_win),//win
		            0,//checksum
					0x0,//urp
		            40,//length
					NULL,//payload
					0,//payload_size
					lib_net_1,
					lib_t1_1
				);
				lib_t2_1 = libnet_build_ipv4(	//构造ip数据包
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
					lib_net_1,
					lib_t2_1
				);
				lib_t3_1 = libnet_build_ethernet(	//构造以太网数据包
					(u_int8_t *)dst_mac,
					(u_int8_t *)src_mac,
					0x800, // 或者，ETHERTYPE_IP
					NULL,
					0,
					lib_net_1,
					lib_t3_1
				);
				int res = 0;
				res = libnet_write(lib_net_1);	//发送数据包
				if(-1 == res)
				{
					perror("libnet_1_write");
					exit(-1);
				}
				break;
		  	}
		  	//以下两种情况均需要回复ack	  
		  	case TH_PUSH | TH_ACK: {			  	
		  	}
		  	case TH_SYN | TH_ACK: {
				//printf("flags:%d\n",tcp->th_flags);
		  		unsigned char tcp_op_ack[12]={0x01,0x01,0x08,0x0a};
		  		if(tcp->th_flags != 24) {
			  		printf("This is SYN + ACK\n");
			  		//payload=tcp_op len=20 回一个len=12
					memcpy(tcp_op_ack+4,payload+8+4,4);
					memcpy(tcp_op_ack+8,payload+8,4);
					writeRemoteSeq(tcp->th_seq,1);
					//不传
					canBeSent = 0;
		  		} else {
					printf("This is DTAT.\n");
					//payload=tcp_op+data
			  		payload_size=ntohs(ip->ip_len)-20-20-12;
					printf("data_size:%d\n",payload_size);
		  			//len=12
					memcpy(tcp_op_ack+4,payload+4+4,4);
					memcpy(tcp_op_ack+8,payload+4,4);
					writeRemoteSeq(tcp->th_seq,payload_size);
		  		}
				lib_t0_2 = libnet_build_tcp_options(  
			        tcp_op_ack,  
			        12,  
					lib_net_2,
					lib_t0_2
				); 
				remote_seq = readRemoteSeq();
				lib_t1_2 = libnet_build_tcp(	//构造tcp数据包
					ntohs(tcp->th_dport),
					ntohs(tcp->th_sport),
					ntohl(tcp->th_ack),//seq
					remote_seq,//ack
					TH_ACK,//flags
					ntohs(tcp->th_win),//win
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
		  	case TH_ACK: {
				printf("This is ACK.\n");
				//不传ACK包
				canBeSent = 0;
				break;			
		  	}
		  	case TH_FIN | TH_ACK: {
			  	printf("This is FIN.\n");
			  	//reply RST
				lib_t0_3 = libnet_build_tcp(	//构造tcp数据包
					ntohs(tcp->th_dport),
					ntohs(tcp->th_sport),
					ntohl(tcp->th_ack),//seq
					0x0,//ack
					TH_RST,//flags
					ntohs(tcp->th_win),//win
					0,//checksum
					0x0,//urp
					20,//length
					NULL,//payload
					0,//payload_size
					lib_net_3,
					lib_t0_3
				);
				lib_t1_3 = libnet_build_ipv4(	//构造ip数据包
					20+20,
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
					lib_t1_3
				);
				lib_t2_3 = libnet_build_ethernet(	//构造以太网数据包
					(u_int8_t *)dst_mac,
					(u_int8_t *)src_mac,
					0x800, // 或者，ETHERTYPE_IP
					NULL,
					0,
					lib_net_3,
					lib_t2_3
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
		  	default: {
				printf("This is ELSE.\n");
				printf("flags:%d\n",tcp->th_flags);
				canBeSent = 0;
				break;
		  	}
		}	  	
	}
  	if(canBeSent) {
	  	sendto(sockfd4,ip,ntohs(ip->ip_len),0,(struct sockaddr *)&servaddr4,addr_len);
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
	pcap_compile(device, &filter, "tcp and dst net 192.168.1.105 and not icmp", 1, 0);
	//pcap_compile(device, &filter, "tcp and dst net 192.168.1.102 and not icmp", 1, 0);
	pcap_setfilter(device, &filter);
	//过滤出来发到本地的udp 9090端口
	sockfd4=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr4,sizeof(servaddr4));
	servaddr4.sin_family=AF_INET;
	servaddr4.sin_port=htons(9090);
	inet_pton(AF_INET,"192.168.10.111",&servaddr4.sin_addr);
	//inet_pton(AF_INET,"192.168.10.115",&servaddr4.sin_addr);
	/* wait loop forever */
	int id = 0;
	pcap_loop(device, -1, getPacket, (u_char*)&id);
	pcap_close(device);

	return 0;
}
