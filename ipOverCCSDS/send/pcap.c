#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libnet.h>

//sudo ip link add ep0 type veth peer name ep1

//libnet_ptag_t lib_t = 0;

unsigned char src_mac[6] = {0x66,0x18,0xe9,0x37,0x6a,0xe2};//发送者网卡地址00:0c:29:97:c7:c1
	unsigned char dst_mac[6] = {0xd0,0x50,0x99,0x2b,0xbe,0x00};//接收者网卡地址‎74-27-EA-B5-FF-D8
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
/*libnet_t *lib_net=NULL;
char errBuf[PCAP_ERRBUF_SIZE];
lib_net = libnet_init(LIBNET_LINK_ADV, "ep0", errBuf);	//初始化
if(NULL == lib_net)
	{
		perror("libnet_init");
		exit(-1);
	}*/

  int * id = (int *)arg;
  
  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  
  int i;
  for(i=0; i<pkthdr->len; ++i)
  {
    printf(" %02x", packet[i]);
    if( (i + 1) % 16 == 0 )
    {
      printf("\n");
    }
  }
  printf("\n");
struct sniff_ethernet *ethernet;
struct sniff_ip *ip;//ip包头

        struct sniff_udp *udp;//udp包头


        u_char *payload;//数据包负载的数据

        int payload_size;//数据包负载的数据大小

        ethernet=(struct sniff_ethernet*)(packet);

        ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));

        udp=(struct sniff_udp*)(packet + sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip));

        payload=(u_char *)(packet+sizeof(struct sniff_ethernet)+sizeof(struct sniff_ip)+sizeof(struct sniff_udp));

	payload_size=ntohs(udp->udp_len)-sizeof(struct sniff_udp);
//printf("len:%d %d %d\n",sizeof(struct sniff_ethernet),sizeof(struct sniff_ip),sizeof(struct sniff_udp));
printf("len:%d,srcport:%d,dstport:%d\n",payload_size,ntohs(udp->udp_sport),ntohs(udp->udp_dport));
//payload_size=payload_size>46?payload_size:46;
sendto(sockfd4,ip,payload_size+sizeof(struct sniff_ip)+sizeof(struct sniff_udp),0,(struct sockaddr *)&servaddr4,addr_len);
/*lib_t = libnet_build_udp(	//构造udp数据包
								ntohs(udp->udp_sport),
								ntohs(udp->udp_dport),
								8+payload_size,
								0,
								payload,
								payload_size,
								lib_net,
								0
							);

	lib_t = libnet_build_ipv4(	//构造ip数据包
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
								0
							);

int etherLen=sizeof(struct sniff_ip)+sizeof(struct sniff_udp)+payload_size;
	lib_t = libnet_build_ethernet(	//构造以太网数据包
									(u_int8_t *)dst_mac,
									(u_int8_t *)src_mac,
									0x800, // 或者，ETHERTYPE_IP
									NULL,
									0,
									lib_net,
									0
								);

	int res = 0;
	res = libnet_write(lib_net);	//发送数据包
	if(-1 == res)
	{
		perror("libnet_write");
		exit(-1);
	}*/
}

int main(int argc ,char* argv[])
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  
  /* get a device */
  /*devStr = pcap_lookupdev(errBuf);
  
  if(devStr)
  {
    printf("success: device: %s\n", devStr);
  }
  else
  {
    printf("error: %s\n", errBuf);
    exit(1);
  }*/
  
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(argv[1], BUFSIZ, 1, 0, errBuf);
  
  if(!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
  
	/* construct a filter */
  struct bpf_program filter;
  pcap_compile(device, &filter, "udp and dst net 192.168.10.0/24", 1, 0);
  pcap_setfilter(device, &filter);



	
	sockfd4=socket(AF_INET,SOCK_DGRAM,0);
	bzero(&servaddr4,sizeof(servaddr4));
	servaddr4.sin_family=AF_INET;
	servaddr4.sin_port=htons(5012);
	inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);
/*char *src_ip_str = "192.168.18.129"; //源主机IP地址
    char *dst_ip_str = "192.168.18.128"; //目的主机IP地址
src_ip = libnet_name2addr4(lib_net,src_ip_str,LIBNET_RESOLVE);	//将字符串类型的ip转换为顺序网络字节流
	dst_ip = libnet_name2addr4(lib_net,dst_ip_str,LIBNET_RESOLVE);
*/
  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  
  pcap_close(device);

  return 0;
}
