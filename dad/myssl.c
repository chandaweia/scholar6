//#include "radius_mysql.h"
#include "myssl.h"
#include <stdio.h>

struct ssl ssl;
void ShowCerts(SSL * ssl){
     X509 *cert;        
     char *line;
     cert = SSL_get_peer_certificate(ssl);
     if (cert != NULL) {
         printf("Digital certificate information:\n");
         line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);                
         printf("Certificate: %s\n", line);
         free(line);                
         line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
         printf("Issuer: %s\n", line);                
         free(line);                
         X509_free(cert);
     }else                
         printf("No certificate information縗n");
}
 
int ssl_start(char *servip,int servport,struct ssl*ssl_st)
  {
       int rv=0;

       if(servip==NULL||ssl_st==NULL)
       {
            printf("servip==NULL||ssl_st==NULL\n");
            return -1;
       }
        /* SSL 库初始化 */
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_st->ctx = SSL_CTX_new(SSLv23_client_method());
        if (ssl_st->ctx == NULL) {
                ERR_print_errors_fp(stdout);
                return 1;
        }
        /* 创建一个 socket 用于 tcp 通信 */
        if ((ssl_st->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                perror("Socket");
                return 1;
        }

        /* 初始化服务器端（对方）的地址和端口信息 */
        bzero(&ssl_st->dest, sizeof(ssl_st->dest));
        ssl_st->dest.sin_family = AF_INET;
        ssl_st->dest.sin_port = htons(servport);
        if(inet_aton(servip,(struct in_addr *)&(ssl_st->dest.sin_addr.s_addr)) == 0) {
                perror(servip);
                return 1;
        }
        /* 连接服务器 */
        if (connect(ssl_st->sockfd, (struct sockaddr *)&(ssl_st->dest), sizeof(ssl_st->dest)) != 0) {
                perror("Connect ");
                exit(-1);
        }
        printf("Tcp connected\n\n");
        /* 基于 ctx 产生一个新的 SSL */
        ssl_st->ssl = SSL_new(ssl_st->ctx);
        SSL_set_fd(ssl_st->ssl, ssl_st->sockfd);
        /* 建立 SSL 连接 */
        rv=SSL_connect(ssl_st->ssl);
        printf("rv of SSL_connect is %d\n",rv);        
        if (rv== -1)
        {
                printf("ssl connect fail!\n");
                ERR_print_errors_fp(stderr);
        }
        else {
                printf("Connected with %s encryption\n", SSL_get_cipher(ssl_st->ssl));
                ShowCerts(ssl_st->ssl);
        } 
        return 0;
  }
  int ssl_data(struct ssl *ssl_st,char *buf,int buflen,char *reply,int *replylen,int f)
  {
        int len=0;
        time_t time1,time2,time3,time4;
        struct timeval tv;
   
        memset(reply,0,*replylen);
        /* send data */
        time(&time1);
        printf("Before SSl_write , time is %s\n",ctime(&time1));
        len = SSL_write(ssl_st->ssl, buf, buflen);
        if (len < buflen)
           printf("'%s'message Send failure ！sent len : %d ,Error code : %d，Error messages : '%s'\n",\
                 buf,len,errno, strerror(errno));
        time(&time2);
        printf("After SSl_write , time is %s\n",ctime(&time2));
        /* read data */
        time(&time3);
     #if 1
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        if(-1==setsockopt(ssl_st->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
             return -1;
     #endif
        if(1==f)
            return len;
        printf("Before SSl_read , time is %s\n",ctime(&time3));
        len = SSL_read(ssl_st->ssl,reply, *replylen);
        time(&time4);
        printf("After SSl_read , time is %s\n",ctime(&time4));
        printf("reply len is %d\n",len);
        if(len<0)
        {
           printf("Failure to receive message from server\n");
           SSL_get_error(ssl_st->ssl,len);
           return -1;
        }
        else if(len>*replylen)
        {
           printf("receieved len : %d too large\n",len);
           return -1;
        }
        else
           *replylen=len; 
        return 0;
  }
  int ssl_end(struct ssl*ssl_st)
  {
        /* 关闭连接 */
        SSL_shutdown(ssl_st->ssl);
        SSL_free(ssl_st->ssl);
        close(ssl_st->sockfd);
        SSL_CTX_free(ssl_st->ctx);
        return 0;
  }
