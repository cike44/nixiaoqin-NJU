#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libnet.h>
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
  u_char *payload;//数据包负载的数据
  int payload_size;//数据包负载的数据大小

  ethernet=(struct sniff_ethernet*)(packet);
  //取出IP包
  ip=(struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
  printf("len:%d\n",ntohs(ip->ip_len));
  
  sendto(sockfd4,ip,ntohs(ip->ip_len),0,(struct sockaddr *)&servaddr4,addr_len);
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
  pcap_compile(device, &filter, "ip and dst net 192.168.1.108", 1, 0);
  pcap_setfilter(device, &filter);
  //过滤出来发到本地的udp 5012端口
  sockfd4=socket(AF_INET,SOCK_DGRAM,0);
  bzero(&servaddr4,sizeof(servaddr4));
  servaddr4.sin_family=AF_INET;
  servaddr4.sin_port=htons(5012);
  inet_pton(AF_INET,"127.0.0.1",&servaddr4.sin_addr);

  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  pcap_close(device);
  
  return 0;
}
