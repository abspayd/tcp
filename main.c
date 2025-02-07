#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {

    int testsock = socket(PF_PACKET, );

    int sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_IP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    int hincl = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0) {
        perror("setsocketopt");
        exit(1);
    }

    size_t buflen = IP_MAXPACKET;
    unsigned char *buf = (unsigned char *)malloc(buflen);
    memset(buf, 0, buflen);

    while (1) {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);

        buflen = recvfrom(sockfd, buf, buflen, 0, (struct sockaddr *)&addr, &addrlen);
        if (buflen < 0) {
            printf("Nothing to read.\n");
            exit(1);
        }

        // TODO: does the IP header still exist in the buffer? Or is the TCP header what's left?

        printf("===== Recieved %zu bytes =====\n", buflen);
        for (int i = 0; i < (int)buflen; i++) {
            printf("0x%X ", buf[i]);
        }
        printf("\n==============================\n");
    }

    free(buf);

    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);

    return 0;
}
