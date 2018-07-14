/*
 * File: packaging.c
 * -----------------
 * Description: This program is a wrapper of read/write. 
 * 	And we packing a packet struct to deal with TCP splicing.
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "packaging.h"


/* Packaging readn() */
ssize_t readn(int fd, void *buf, size_t count)
{   
    size_t nleft = count;   
    ssize_t nread;      
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nread = read(fd, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nread == 0) 
            return count - nleft;
        bufp += nread;
        nleft -= nread;
    }
    return count;
}

/* Packaging writen() */
ssize_t writen(int fd, const void *buf, size_t count)
{   
    size_t nleft = count;  
    ssize_t nwriten;   
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nwriten = write(fd, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nwriten == 0) 
            continue;
        bufp += nwriten;
        nleft -= nwriten;
    }
    return count;
}

ssize_t recv_peek(int sockfd, void *buf, size_t len)
{
    while (1) {
        int ret = recv(sockfd, buf, len, MSG_PEEK);
        if (ret == -1 && errno == EINTR)
            continue;
        return ret;
    }
}

ssize_t readline(int sockfd, void *buf, size_t maxline)
{
    int ret;
    int nread;
    char *bufp = (char *)buf;
    int nleft = maxline;
    while (1) {
        ret = recv_peek(sockfd, bufp, nleft);
        if (ret < 0)
            return ret;
        else if (ret == 0) 
            return ret;
        nread = ret;
        int i;
        for (i = 0; i < nread; i++) {
            if (bufp[i] == '\n') {
                ret = readn(sockfd, bufp, i+1); 
                if (ret != i+1)
                    exit(EXIT_FAILURE);
                return ret;
            }
        }
        if (nread > nleft)
            exit(EXIT_FAILURE);
        nleft -= nread;
        ret = readn(sockfd, bufp, nread);
        if (ret != nread)
            exit(EXIT_FAILURE);
        bufp += nread;
    }
    return -1;
}



/* Packaging SSL_read() */
int SSL_readn(SSL *ssl, void *buf, int count)
{
    int nleft = count;   
    int nread;     
    char *bufp = (char *)buf;
    while (nleft > 0) {
		printf("SSL_readn111111\n");
        if ((nread = SSL_read(ssl, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nread == 0)  /* peer have closed */
            return count - nleft;
        bufp += nread;
        nleft -= nread;
		printf("nread:%d,nleft:%d\n",nread,nleft);
    }
    return count;
}

/* Packaging SSL_write() */
int SSL_writen(SSL *ssl, const void *buf, int count)
{
    int nleft = count;  
    int nwriten; 
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nwriten = SSL_write(ssl, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nwriten == 0)	/* waiting for peer close */
            continue;
        bufp += nwriten;
        nleft -= nwriten;
    }
    return count;
}

