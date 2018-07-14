#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>      
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "packaging.h"
#include "admin_mysql.h"

#define ERR_EXIT(m) \
	do { \
		perror(m); \
		exit(EXIT_FAILURE); \
	} while (0)

/*typedef struct srv_tag {
	int conn;
	char ip[16];
} srv_t;*/

void usage()
{
	printf("Usage: ./nidadmin -r rsa_key -c cert\n");
}

void handle_sigchld(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0); 
}
void showpkt(char *Buf,int Buflen);

char * packet_to_buf(char *buf, struct packet *pkt,int *totallen)
{
	char *newbuf=NULL;

	printf("------------pkt------------printf-----------\n");
	showpkt((char*)pkt,ntohs(pkt->len));
	printf("------end------pkt------------printf-----------\n");

	int buflen = ntohs(pkt->len);
	int len=*totallen;
	int newtlen = *totallen+ 4 + buflen;
	uint32_t newtlen_net = htonl(newtlen-4);
		
	printf("1111111111newtlen:%d\n",newtlen);
	newbuf=(char*)malloc(newtlen);
	memset(newbuf,0,newtlen);
	printf("newtlen_net:%x\n",newtlen_net);
	memcpy(newbuf,(char*)&newtlen_net,sizeof(uint32_t));
	memcpy(newbuf,buf+4,*totallen-4);
	memcpy(newbuf+len,(char*)pkt,buflen+4);
	printf("newtlen:%d\n",newtlen);
	printf("--------------newbuf---------------\n");
    showpkt(newbuf,newtlen-4);
    printf("-------------end----newbuf---------------\n");

	//uint32_t oldbuflen = ntohl(buf->len);
	//uint32_t newbuflen = ntohl(buf->len) + 4 + ntohs(pkt->len);

	//printf("ntohs(pkt->len):%d,oldbuflen:%d,newbuflen:%d\n",ntohs(pkt->len),oldbuflen,newbuflen);

	/*newbuf=(char*)malloc(newbuflen);
	memset(newbuf,0,newbuflen);
	memcpy(newbuf,buf->buf,oldbuflen);
	memcpy(newbuf+oldbuflen,(char*)pkt,ntohs(pkt->len)+4);*/
	/*
	buf->len = htonl(newbuflen);
	newbuf=(char*)malloc(newbuflen+4);
	memset(newbuf,0,newbuflen+4);
	memcpy(newbuf,(char*)buf,oldbuflen+4);
	memcpy(newbuf+oldbuflen+4,(char*)pkt,ntohs(pkt->len)+4);

	printf("--------------newbuf---------------\n");
	showpkt(newbuf,newbuflen);
	printf("-------------end----newbuf---------------\n");
	*/
	//buf->buf = newbuf;
	//printf("packet_to_buf newbuf->len:%d\n",ntohl(newbuf->len));
	//freeSendBuf(buf);
	*totallen=newtlen;
	free(buf);
	printf("newtotallen:%d\n",*totallen);
	return newbuf;
}

void packet_print(struct packet *pkt)
{
    printf("------------------show one packet---------------\n");
    printf("ntohs(pkt->type):%d, ntohs(pkt->len):%d\n",ntohs(pkt->type),ntohs(pkt->len));
    if(pkt->buf!=NULL)
        printf("%s\n",pkt->buf);
    printf("------------------end show one packet--------------\n");
}

char *mac_to_str(unsigned char* pMac)
{
	char szFormat[] = "%02X%02X%02X%02X%02X%02X";
	char *szMac = (char*)malloc(33);
	memset(szMac,0,33);  

	sprintf(szMac, szFormat, pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5]);

	return szMac;
}

void read_one_packet(SSL *ssl,struct packet *recvbuf,uint32_t *total_len)
{
	int ret;
	uint32_t len;
	uint32_t tlen = *total_len;

	#if 1
	ret = SSL_readn(ssl, &(recvbuf->type), 2); /* recv the type */
	if (ret == -1)
            ERR_EXIT("SSL_readn");
    else if (ret < 2) {
    	printf("client close\n");
    }
	tlen -= 2;

	printf("read_one_packet recvbuf->type:%x,   ntohs(recvbuf->type):%x\n",recvbuf->type,ntohs(recvbuf->type));
	ret = SSL_readn(ssl, &(recvbuf->len), 2); /* recv the value_len */
	len = ntohs(recvbuf->len);
	if (ret == -1)
            ERR_EXIT("SSL_readn");
    else if (ret < 2) {
        printf("client close\n");
    }
	tlen -= 2;

	if(len>tlen)
		len = tlen;
	ret = SSL_readn(ssl, recvbuf->buf, len); /* recv the value */
	if (ret == -1) 
        ERR_EXIT("SSL_readn");
    else if (ret < len) {
        printf("client close\n");
    }
	tlen -= len;
	*total_len = tlen;
	#endif
	#if 0
	//for test 
	printf("enter read_one_packet\n");
	char *onepkt=NULL;
	printf("tlen:%d\n",tlen);
	ret = SSL_readn(ssl,onepkt, tlen); /* recv the type */
	printf("read_one_packet after read\n");
	if (ret == -1)
            ERR_EXIT("SSL_readn");
    else if (ret < tlen) {
        printf("client close\n");
    }
	*total_len = 0;
	printf("read_one_packet111111111111111\n");
	recvbuf = (struct packet *)(onepkt);
	printf("read_one_packet222222222\n");
	packet_print(recvbuf);
	#endif
}

void showpkt(char *Buf,int Buflen)
{
	int j=0;
    unsigned char *p=(unsigned char *)Buf;
	int BufLen = Buflen+4;
    printf("\n*****************\n");
	printf("Buflen=%d\n",Buflen);
	for(j=0;j<BufLen;j++)
	{
		printf("%02x ",p[j]);
		if((j!=0) && (j%16==15))
			printf("\n");
	}
    /*for(;n<m;n++){
		printf("n=%d\n",n);
        for(;j<16;j++){
            printf("%02x ",p[j]);
        }
        printf("\n");
    }
    for(n=0;n<BufLen%16;n++){
        printf("%02x ",p[++j]);
    }*/
    printf("\n****************\n");
}

void privkey_reply(SSL *ssl)
{
	printf("privkey_reply\n");
	struct packet pkt;
	//struct sendBuf sendbuf;
	char* sendbuf=(char*)malloc(5);
	char* newbuf=NULL;
	//sendbuf.len=0;
	uint16_t type,len;

	printf("privkey_reply11111111\n");
	memset(sendbuf,0,5);
	sendbuf[0]=0x00;
	sendbuf[1]=0x00;
	sendbuf[2]=0x00;
	sendbuf[3]=0x04;
	printf("privkey_reply2222222\n");

	int sendbuflen=4;

	//memset(&pkt,0,sizeof(struct packet));
	//memset(&sendbuf,0,sizeof(struct sendBuf));
	type = 0x02;
	len = 32;
	pkt.type = htons(type);
	pkt.len = htons(len);

	//从数据库中取出密钥
	char prikey[32]={0};
	int prikeylen=0;

	printf("privkey_reply333333333\n");
	//mysql_login_my("211.68.122.23","root","YUIOPPOIUY","cngi");
	mysql_login_my("211.68.122.23","root","YUIOPPOIUY","cngi");
	mysql_query_prikey(prikey,&prikeylen);
	mysql_close_my();
	printf("长度:%d, 密钥:%s\n",prikeylen,prikey);
	
	//char *data = "11111111111111111111111111111111";//32个1
	printf("privkey_reply type:%x,len:%X\n",type,len);
	memset(pkt.buf,0,1024);
	memcpy(pkt.buf,prikey,prikeylen);
	newbuf=packet_to_buf(sendbuf,&pkt,&sendbuflen);
	
	printf("---------------发送的数据----------------\n");
	showpkt(newbuf,sendbuflen-4);
	printf("--------------end-发送的数据----------------\n");  
	
	printf("privkey_reply ntohs(pkt.len):%d\n",ntohs(pkt.len));

	SSL_writen(ssl,newbuf,sendbuflen);

}

void update_tuples(SSL *ssl,struct packet *recvbuf,uint32_t total_len)
{
	printf("update_tuples\n");
	int len=0;
	struct packet recvdata[3];
	char *username,*ipv6_addr,*time;
	unsigned char* mac_addr;
	char *mac_addr_str;

	len = ntohs(recvbuf->len);
	username = (char*)malloc(len+1);
	memset(username,0,len+1);
	memcpy(username,recvbuf->buf,len);
		
	read_one_packet(ssl,&recvdata[0],&total_len);
	read_one_packet(ssl,&recvdata[1],&total_len);
	read_one_packet(ssl,&recvdata[2],&total_len);
	
	printf("111111111username:%s\n",username);
	len = ntohs(recvdata[0].len);
	ipv6_addr = (char*)malloc(129);
	memset(ipv6_addr,0,129);
	//memcpy(ipv6_addr,recvdata[0].buf,len);
	inet_ntop(AF_INET6,(void*)recvdata[0].buf,ipv6_addr,128);
	printf("11111111ipv6 addr:%s\n",ipv6_addr);

	len = ntohs(recvdata[1].len);
	mac_addr = (unsigned char*)malloc(len+1);
	memset(mac_addr,0,len+1);
	memcpy(mac_addr,recvdata[1].buf,len);
	mac_addr_str = mac_to_str(mac_addr);
	printf("111111111mac_addr_str:%s\n",mac_addr_str);
	//printf("11111111mac_addr:%s\n",mac_addr);

	len = ntohs(recvdata[2].len);
	time = (char*)malloc(len+1);
	memset(time,0,len+1);
	memcpy(time,recvdata[2].buf,len);
	printf("1111111time:%s\n",time);

	mysql_login_my("211.68.122.23","root","YUIOPPOIUY","cngi");

	#if 0
	int existres=mysql_query_radpostauth_is_exist(username,ipv6_addr);
	if(existres==0)//exist--->update
	{
		mysql_update_radpostauth(username,ipv6_addr,mac_addr_str,time);
	}
	else //不存在，insert
	{
		mysql_insert_info_to_radpostauth(username,ipv6_addr,mac_addr_str,time);
	}
	#endif
	mysql_insert_info_to_radpostauth(username,ipv6_addr,mac_addr_str,time);
	mysql_close_my();
	//printf("update_tuples关闭mysql_close_my\n");

	return;
}

void do_reply(SSL *ssl,struct packet *recvbuf,uint32_t total_len)
{
	uint16_t type = ntohs(recvbuf->type);
	printf("do_reply type:%x\n",type);
    switch (type)
    {
    case 0x01: privkey_reply(ssl);
        break;
    case 0x03: update_tuples(ssl,recvbuf,total_len);//update mysql
		break;
    default:
        return;
    }
}

void do_service(SSL *ssl, char *cliip)
{
	struct packet recvbuf;
	uint32_t total_len,tlen;
	//for test
	/*int replylen=1024;
	char *reply;
	memset(reply,0,replylen);
	*/

	while(1){
		memset(&recvbuf, 0, sizeof(recvbuf));
		int ret = SSL_readn(ssl, &tlen, 4); /* recv the total length */
		/*int ret = SSL_read(ssl,reply,replylen);
		printf("12345\n");
		printf("reply:%s\n",reply);
		break;*/
		total_len = ntohl(tlen);
		printf("total_len:%d\n",total_len);
		if (ret == -1) 
			ERR_EXIT("SSL_readn");
		else if (ret < 4) { 
			printf("client close\n");
			break;
		}
		//total_len -= 4;
		read_one_packet(ssl,&recvbuf,&total_len);
		//return; //for test
		do_reply(ssl,&recvbuf,total_len);
		
	}//end while(1)

}//end do_service

int main(int argc, char *argv[])
{
	int opt;
	//uint16_t myport=443;
	char *rsa_key, *cert;

	struct sockaddr_in servaddr;
	int listenfd;

	struct sockaddr_in peeraddr;
	socklen_t peerlen = sizeof(peeraddr);

	int conn;
	pid_t pid;
	SSL *ssl;

	if(argc<2)
	{
		usage();
		return EXIT_FAILURE;
	}

	while ((opt = getopt(argc, argv, "r:c:")) != -1) {
		switch (opt) {
		case 'r':
			if (optarg == NULL || *optarg == '-') {
				fprintf(stderr,
					"Please set the RSA secret key.\n");
				return EXIT_FAILURE;
			}
			rsa_key = optarg;
			break;
		case 'c':
			if (optarg == NULL || *optarg == '-') {
				fprintf(stderr,
					"Please set the certificate.\n");
				return EXIT_FAILURE;
			}
			cert = optarg;
			break;
		default:
			printf("Other options: %c\n", opt);
			usage();
		}
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx;
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, rsa_key, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	signal(SIGCHLD, handle_sigchld);//父进程需要等到子进程结束
	
	
	if ( (listenfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) 	
		ERR_EXIT("socket");
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(443);
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 

	int on = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		ERR_EXIT("setsockopt");
	
	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(struct sockaddr)) < 0)
		ERR_EXIT("bind");
	if (listen(listenfd, SOMAXCONN) < 0) 		
		ERR_EXIT("listen");
	
	//connect mysql
	//mysql_login_my("211.68.122.23","root","YUIOPPOIUY","cngi");
	
	while(1){
		if((conn = accept(listenfd,(struct sockaddr*)&peeraddr,&peerlen)) < 0)
			ERR_EXIT("accept");
		struct timeval start, end;
		gettimeofday(&start, NULL);
		printf("Got connect: ip = %s, port = %d\n",
		       inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));
		
		FILE *stream;
		char *line = NULL;
		size_t len = 0;
		ssize_t nread;
		stream = fopen("./ip_writelist.conf", "r");
		if (stream == NULL) {
			perror("fopen");
			exit(EXIT_FAILURE);
		}
		while ((nread = getline(&line, &len, stream)) != -1) {
			if (strncmp(inet_ntoa(peeraddr.sin_addr), line, nread-1) == 0) 
			{
				goto ok;
			}
		}
		printf("Invalid Client IP, Closing...\n");
		close(conn);
    	free(line);
    	fclose(stream);
		continue;
ok:
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, conn);
		if (SSL_accept(ssl) < 0)
			ERR_EXIT("SSL_accept");

		pid = fork();
		if (pid == -1)
			ERR_EXIT("fork");
		if (pid == 0) {
			close(listenfd);
			gettimeofday(&end, NULL);
			printf("connect spend: %f sec\n", (1000000*(end.tv_sec-start.tv_sec) + end.tv_usec-start.tv_usec)/1000000);
			do_service(ssl, inet_ntoa(peeraddr.sin_addr));
			exit(EXIT_SUCCESS);
		} else
			close(conn);

    	free(line);
    	fclose(stream);
	}//end while(1)
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	
	//close mysql
	//mysql_close_my();

	return 0;
}//end main

