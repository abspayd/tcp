// #include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: client port");
        exit(1);
    }

    in_port_t port = atoi(argv[1]);
    printf("Establishing connection to localhost:%hu...\n", port);

    // tcp socket (for testing)
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    socklen_t addr_len = sizeof(addr);
    if (connect(sockfd, (struct sockaddr *)&addr, addr_len) < 0) {
        perror("connect");
        return 1;
    }

    shutdown(sockfd, SHUT_RDWR);

    return 0;

    // int hincl = 1;
    // if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0) {
    //     perror("setsockopt");
    //     exit(1);
    // }

    // size_t length = sizeof(char) * 1024;
    // unsigned char *buffer = malloc(length);
    // memset(buffer, 0, length);
    // buffer[0] = 'a';
    // buffer[1] = 's';
    // buffer[2] = 'd';
    // buffer[3] = 'f';

    // char packet[4096];
    // struct iphdr *ip = (struct iphdr *)packet;

    // struct sockaddr_in addr = {
    //     .sin_family = AF_INET,
    //     .sin_port = htons(port),
    //     .sin_addr.s_addr = INADDR_ANY,
    // };
    // socklen_t addr_len = sizeof(addr);

    // int attempts = 0;
    // ssize_t sent = -1;
    // while (attempts++ < 100) {
    //     sent = sendto(sockfd, buffer, length, 0, (struct sockaddr *)&addr, addr_len);
    //     if (sent > 0) {
    //         break;
    //     }
    //     usleep(1000 * 100);
    // }
    // if (sent < 0) {
    //     perror("send");
    //     exit(1);
    // }

    // shutdown(sockfd, SHUT_RDWR);

    // return 0;
}
