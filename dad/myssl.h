#ifndef __SSL__
#define __SSL__
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct ssl {    
    int sockfd;    
    int len;    
    struct sockaddr_in dest;    
    SSL_CTX *ctx;    
    SSL *ssl;
};
extern struct ssl ssl;
int ssl_start(char *servip,int servport,struct ssl*ssl_st);
int ssl_data(struct ssl *ssl_st,char *buf,int buflen,char *reply,int *replylen,int f);
int ssl_end(struct ssl*ssl_st);
#endif
