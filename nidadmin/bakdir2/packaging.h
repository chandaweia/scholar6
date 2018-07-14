/*
 * File: packaging.h
 * -----------------
 * Description: Define the packet struct.
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#ifndef PACKAGING_H
#define PACKAGING_H

#include <openssl/ssl.h>
#include <openssl/err.h>

struct packet {
	uint16_t type;
	uint16_t len;		/* header */
    char buf[1024];	/* payload */
}__attribute__((aligned(1)));
struct sendBuf{
    uint32_t len;
    char *buf;
}__attribute__((aligned(1)));

ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
ssize_t readline(int sockfd, void *buf, size_t maxline);
int SSL_readn(SSL *ssl, void *buf, int count);
int SSL_writen(SSL *ssl, const void *buf, int count);

#endif
