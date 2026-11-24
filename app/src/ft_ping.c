#include "ft_ping.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void clear_targets(TARGET *head) {
    TARGET *node;

    while (head) {
        node = head;
        head = head->next;
        free(node);
    }
}

int resolve_dns(FT_PING *s_ping, TARGET *target) {
    if (s_ping == NULL || target == NULL)
        return -1;

    if (dns_loopback(s_ping, target) == 0)
        return 0;
    struct addrinfo hints;
    struct addrinfo *res;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int ret = getaddrinfo(target->_target_name, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "ping: unknown host\n");
        return -1;
    }

    struct sockaddr_in *sock_addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(sock_addr->sin_addr), target->_target_ip,
              INET_ADDRSTRLEN);

    freeaddrinfo(res);
    return 0;
}

int dns_loopback(FT_PING *s_ping, TARGET *target) {
    if (s_ping == NULL || target == NULL)
        return -1;

    TARGET *tmp = s_ping->_targets;
    while (tmp != s_ping->_current_target) {
        if (strcmp(tmp->_target_name, target->_target_name) == 0 ||
            strcmp(tmp->_target_ip, target->_target_name) == 0) {
            strncpy(target->_target_ip, tmp->_target_ip, INET_ADDRSTRLEN - 1);
            return 0;
        }
        tmp = tmp->next;
    }
    return -1;
}

int create_socket(SOCKET_SETTING *settings) {
    if (settings == NULL)
        return -1;
    int sockfd;

    if (!settings->_root) {
        sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);

    } else {
        sockfd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);

        if (sockfd < 0) {
            perror("ping:");
            return -1;
        }

        // Drop privileges to root user to avoid security issues
        if (setgid(0) == -1 || setuid(0) == -1) {
            perror("ping: setgid/setuid");
            close(sockfd);
            return -1;
        }
    }

    if (settings->_timeout >= 0) {
        struct timeval timeout;
        timeout.tv_sec = settings->_timeout;
        timeout.tv_usec = 0;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) < 0) {
            perror("ping: setsockopt SO_RCVTIMEO");
            close(sockfd);
            return -1;
        }
    }

    if (settings->_linger >= 0) {
        struct linger so_linger;
        so_linger.l_onoff = 1;
        so_linger.l_linger = settings->_linger;
        if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &so_linger,
                       sizeof(so_linger)) < 0) {
            perror("setsockopt SO_LINGER");
            close(sockfd);
            return -1;
        }
    }

    return sockfd;
}
