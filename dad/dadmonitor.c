#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>  
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>  
#include <netinet/ether.h>  
#include <time.h>

#include "myssl.h"
#include "dadmysql.h"
#define MACLEN 6

typedef struct opt {
    uint16_t Type;
    uint16_t Len;
    char Value[];
}__attribute__((packed)) Option;
typedef struct message {
    uint32_t TotalLen;
    Option options[];
}__attribute__((packed)) Packet;

void print_mac(struct ethhdr* eth)
{
	printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	
}
void print_ipv6(struct ip6_hdr *ip6)
{
	char *srcip,*destip;
	//ip6_hdr->ip6_src ip6_dst
	//
	srcip = (char*)malloc(129);
	destip = (char*)malloc(129);
	memset(srcip,0,129);
	memset(destip,0,129);
    inet_ntop(AF_INET6,(void*)(&(ip6->ip6_dst)),destip,128);
    inet_ntop(AF_INET6,(void*)(&(ip6->ip6_src)),srcip,128);
	printf("print ip:%s--->%s\n",srcip,destip);
	free(srcip);
	free(destip);
}

Packet *Tuple(char *user,int user_len,char *ip6,unsigned char *mac,int *pPktLen){
    Packet *pkt=NULL;
    int pkt_len=0;
    char timestr[128]={0};
    time_t t;
    struct tm tmp={0};
    Option *user_option=NULL,*ip6_option=NULL,*mac_option=NULL,*time_option=NULL;

    t = time(NULL);
    localtime_r(&t,&tmp);
    if (strftime(timestr, sizeof(timestr),"%Y-%m-%d %H:%M:%S", &tmp) == 0) {
        fprintf(stderr, "strftime returned 0");
        return NULL;
    }
    /* tuple=(user,ipv6,mac,time) */
    pkt_len=sizeof(Packet)+sizeof(Option)+user_len+sizeof(Option)+16+sizeof(Option)+MACLEN+sizeof(Option)+strlen(timestr);
    *pPktLen=pkt_len;
    pkt=(Packet *)malloc(pkt_len);
    memset(pkt,0,pkt_len);
    pkt->TotalLen=htonl(pkt_len-sizeof(Packet));
    user_option=(Option *)((char *)pkt+sizeof(Packet));
    user_option->Type=htons(0x03);
    user_option->Len=htons(user_len);
    memcpy(user_option->Value,user,user_len);
    ip6_option=(Option *)((char *)pkt+sizeof(Packet)+sizeof(Option)+user_len);
    ip6_option->Type=htons(0x04);
    ip6_option->Len=htons(16);
    memcpy(ip6_option->Value,ip6,16);
    mac_option=(Option *)((char *)pkt+sizeof(Packet)+sizeof(Option)+user_len+sizeof(Option)+16);
    mac_option->Type=htons(0x05);
    mac_option->Len=htons(MACLEN);
    memcpy(mac_option->Value,mac,MACLEN);
    time_option=(Option *)((char *)pkt+sizeof(Packet)+sizeof(Option)+user_len+sizeof(Option)+16+sizeof(Option)+MACLEN);
    time_option->Type=htons(0x06);
    time_option->Len=htons(strlen(timestr));
    memcpy(time_option->Value,timestr,strlen(timestr));
    //printf("%lx\n",(uint64_t)pkt);
    return pkt;

}

/*void send_to_nidadmin(char* username, char* ipv6, unsigned char* mac)
{
	Packet *pkt=NULL;
	int pktlen=0,replylen=0;
	char *reply;
	pkt = Tuple(username,strlen(username),ipv6,mac,&pktlen);
	
	ssl_data(&ssl,(char*)pkt,pktlen,reply,&replylen,1);
}*/
void send_to_nidadmin(char* username, char* ipv6, struct ethhdr *eth)
{
    Packet *pkt=NULL;
    int pktlen=0,replylen=0;
	int res=-1;
    char *reply=NULL;
	int usernamelen = strlen(username);
    pkt = Tuple(username,usernamelen,(char*)ipv6,(unsigned char*)(eth->h_source),&pktlen);
   
	ssl_start("ip",port,&ssl); 
    res = ssl_data(&ssl,(char*)pkt,pktlen,reply,&replylen,1);
	ssl_end(&ssl);
	#if 0
	if(-1==res)
	{
		ssl_end(&ssl);
		ssl_data(&ssl,(char*)pkt,pktlen,reply,&replylen,1);
	}
	#endif
}

//ns_srcip="::"==srcip && destip最后两个字节=targetip最后两个字节  && targetip!=fe80
int is_nsna(int type,char* srcip,char *destip,char* targetip)
{
	char ns_srcip[]="::";
	char broadcastip[]="ff02::1";
	char local_str[]="fe80:";
	char target_str[6]={0};
	//printf("srcip:%s,strlen(srcip)=%d\n",srcip,strlen(srcip));
	//printf("destip:%s,strlen(destip)=%d\n",destip,strlen(destip));
	//printf("targetip:%s,strlen(targetip)=%d\n",targetip,strlen(targetip));
	//if(strcmp(srcip,ns_srcip)==0)
	if(strlen(targetip)<5)
		return -1;
	
	memcpy(target_str,targetip,5);
	if((type==0x87) && (strcmp(srcip,ns_srcip)==0) && (strcmp(local_str,target_str)!=0)) //ns 
	{
		printf("\n\n**********************************\n");
		printf("%s----->%s\n",srcip,destip);
		printf("targetip:%s\n",targetip);
		printf("ns报文 返回0\n");
		return 0;
	}
	else if((type==0x88) && (strcmp(destip,broadcastip)==0) && (strcmp(srcip,targetip)==0) && (strcmp(local_str,target_str)!=0))  //na
	{
		printf("\n\n**********************************\n");
		printf("%s----->%s\n",srcip,destip);
        printf("targetip:%s\n",targetip);
        printf("targetip前两个字节target_str:%s\n",target_str);
		printf("na报文 返回0\n");
		
		return 0;
	}
	else
		return -1;
}

int main(void)
{
	unsigned char buf[2048] = {0}; 
	struct ethhdr *eth;
	struct ip6_hdr *ip6; 
	int eth_type,ip6_type,icmp6_type;
	char *destip,*srcip,*targetip;
	//char ip[]="ff02::1";
	//char ns_srcip[]="::";
	struct icmp6_hdr *icmp6;
	char *icmp6_buf;
	char *username;
	unsigned char mac[20]={0};
	int isNSNA=-1;

	ssl_start("ip",443,&ssl);
	//int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(IPPROTO_ICMPV6));  
	int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
	
	if(sock_raw_fd<0)
	{
		perror("socket");
     	exit(1);
	}
	while(1)
	{
		//获取链路层的数据包  
		int len = recvfrom(sock_raw_fd, buf, 2048, 0, NULL, NULL); 
		//printf("\n\n*****************************\n");
		//printf("read len=%d\n",len);
		eth = (struct ethhdr*)buf;
		//print_mac(eth);
		sprintf(mac,"%02x-%02x-%02x-%02x-%02x-%02x",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		//printf("mac源地址:%s\n",mac);
		eth_type = ntohs(eth->h_proto);
		//printf("eth->h_proto:%x,eth_type:%x,IPPROTO_IPV6:%x,ETH_P_IPV6:%x\n",eth->h_proto,eth_type,IPPROTO_IPV6,ETH_P_IPV6);
		//eth_type = ETH_P_IPV6 = 86dd, IPPROTO_IPV6 = 29
		if(eth_type == ETH_P_IPV6)
		{
			ip6 = (struct ip6_hdr*)(buf+sizeof(struct ethhdr));
			ip6_type = ip6->ip6_nxt;
			//printf("ip6_type:%x,ip6->ip6_nxt:%x,IPPROTO_ICMPV6:%x\n",ip6_type,ip6->ip6_nxt,IPPROTO_ICMPV6);
			//ip6_type = 3a, IPPROTO_ICMPV6 = 3a
			if(ip6_type == IPPROTO_ICMPV6)
			{
				//when des_ip=ff02::1 && type=136 && src_ip=Target Address ---> NA for DAD
				//update
				icmp6 = (struct icmp6_hdr *)(buf+sizeof(struct ethhdr)+sizeof(struct ip6_hdr));
				icmp6_type = icmp6->icmp6_type;//icmp6_type
				#if 1
				if((icmp6_type==0x87)||(icmp6_type==0x88))
				{
					//printf("\n\n*****************************\n");
					//printf("NS packet read len=%d\n",len);
                    icmp6_buf = (char*)(buf+sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+8);
                    srcip = (char*)malloc(129);
                    destip = (char*)malloc(129);
                    targetip = (char*)malloc(129);
                    memset(srcip,0,129);
                    memset(destip,0,129);
                    memset(targetip,0,129);
                    inet_ntop(AF_INET6,(void*)(&(ip6->ip6_src)),srcip,128);
                    inet_ntop(AF_INET6,(void*)(&(ip6->ip6_dst)),destip,128);
                    inet_ntop(AF_INET6,(void*)icmp6_buf,targetip,128);
                    //print_ipv6(ip6);
                    //printf("target_addr:%s\n",targetip);

					isNSNA=is_nsna(icmp6_type,srcip,destip,targetip);
					if(0==isNSNA)
					{
						//printf("\n\n*****************************\n");
	                    //printf("NS packet read len=%d\n",len);
						print_ipv6(ip6);
	                    printf("target_addr:%s\n",targetip);
 
						dad_mysql_login("ip","user", "pwd","sqlname");
						username = dad_mysql_get_user(mac);
						dad_mysql_close();
						if(username != NULL)
							send_to_nidadmin(username,(char*)icmp6_buf,eth);
					}
					free(srcip);
                    free(destip);
                    free(targetip);
				}
			#endif
			#if 0
				//printf("icmp6_type:%x\n",icmp6_type);
				if(icmp6_type==0x87)//0x87=135 即NS报文
				{
					printf("\n\n*****************************\n");
					printf("NS packet read len=%d\n",len);
					icmp6_buf = (char*)(buf+sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+8);
					srcip = (char*)malloc(129);
                    destip = (char*)malloc(129);
                    targetip = (char*)malloc(129);
                    memset(srcip,0,129);
                    memset(destip,0,129);
                    memset(targetip,0,129);
                    inet_ntop(AF_INET6,(void*)(&(ip6->ip6_src)),srcip,128);
                    inet_ntop(AF_INET6,(void*)(&(ip6->ip6_dst)),destip,128);
                    inet_ntop(AF_INET6,(void*)icmp6_buf,targetip,128);
                    print_ipv6(ip6);
                    printf("target_addr:%s\n",targetip);
					//ns_srcip="::"==srcip && destip最后两个字节=targetip最后两个字节  && targetip!=fe80
					if(strcmp(destip,ip)==0 && strcmp(srcip,ns_srcip)==0)
				}
			#endif
			#if 0
				if(icmp6_type==0x88)//0x88=136 即NA报文
				{
					printf("\n\n*****************************\n");
			        printf("NA packet read len=%d\n",len);
					icmp6_buf = (char*)(buf+sizeof(struct ethhdr)+sizeof(struct ip6_hdr)+8);
					char ip[]="ff02::1";
					
					srcip = (char*)malloc(129);
					destip = (char*)malloc(129);
					targetip = (char*)malloc(129);
					memset(srcip,0,129);
        	        memset(destip,0,129);
					memset(targetip,0,129);
    	            inet_ntop(AF_INET6,(void*)(&(ip6->ip6_src)),srcip,128);
	                inet_ntop(AF_INET6,(void*)(&(ip6->ip6_dst)),destip,128);
					inet_ntop(AF_INET6,(void*)icmp6_buf,targetip,128);
                	print_ipv6(ip6);
					printf("target_addr:%s\n",targetip);

            	    if( strcmp(destip,ip)==0 && strcmp(srcip,targetip)==0 )
        	        {
						printf("mac源地址:%s\n",mac);
    	                //printf("destip=ip and srcip=targetip\n");
						//函数
						username = dad_mysql_get_user(mac);
						if(username != NULL)
							//send_to_nidadmin(username,targetip,mac);
							send_to_nidadmin(username,ip6,eth);
						
	                }
					free(srcip);
					free(destip);
                    free(targetip);
				} 
			#endif
				
			}
			else //is ip6 but not icmp6
			{
				
			}
		}
		else //not ipv6
		{
			
		}
	
	}
	//dad_mysql_close();
	ssl_end(&ssl);
	return 0;
}

