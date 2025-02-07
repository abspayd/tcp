#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("usage: server port");
        exit(1);
    }

    in_port_t port = atoi(argv[1]);

    int sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        exit(1);
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    socklen_t addr_len = sizeof(addr);
    if (bind(sockfd, (struct sockaddr *)&addr, addr_len) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen");
        exit(1);
    }

    printf("Starting server on port %hu.\n", port);

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    if (accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len) < 0) {
        perror("accept");
        exit(1);
    };

    close(sockfd);
    shutdown(sockfd, SHUT_RDWR);

    return 0;
}
