#include "ft_ping.h"
#include "protocols/ft_icmp.h"
#include "protocols/ft_ip.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void clears_targets(TARGET *head) {
    TARGET *node;

    while (head) {
        node = head;
        head = head->_next;
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
        return 1;
    }

    struct sockaddr_in *sock_addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &(sock_addr->sin_addr), target->_target_ip,
              INET_ADDRSTRLEN);
    memcpy(&target->s_dest, sock_addr, sizeof(struct sockaddr_in));

    freeaddrinfo(res);
    return 0;
}

int dns_loopback(FT_PING *s_ping, TARGET *target) {
    if (s_ping == NULL || target == NULL)
        return -1;

    TARGET *tmp = s_ping->s_targets;
    while (tmp != s_ping->s_current_target) {
        if (strcmp(tmp->_target_name, target->_target_name) == 0 ||
            strcmp(tmp->_target_ip, target->_target_name) == 0) {
            strncpy(target->_target_ip, tmp->_target_ip, INET_ADDRSTRLEN - 1);
            memcpy(&target->s_dest, &tmp->s_dest, sizeof(struct sockaddr_in));
            return 0;
        }
        tmp = tmp->_next;
    }
    return -1;
}

int create_socket(FT_PING *s_ping) {
    int sockfd;

    if (!s_ping->s_settings._root) {
        sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
        if (sockfd < 0) {
#ifdef DEBUG
            perror("socket");
#endif
            return -1;
        }

        if (s_ping->s_packet_settings._tos != DEFAULT_TOS) {
            if (setsockopt(sockfd, IPPROTO_IP, IP_TOS,
                           &s_ping->s_packet_settings._tos,
                           sizeof(s_ping->s_packet_settings._tos)) == -1) {
#ifdef DEBUG
                perror("setsockopt");
#endif
                close(sockfd);
                return -1;
            }
        }
        if (s_ping->s_packet_settings._ttl != DEFAULT_TTL) {
            if (setsockopt(sockfd, IPPROTO_IP, IP_TTL,
                           &s_ping->s_packet_settings._ttl,
                           sizeof(s_ping->s_packet_settings._ttl)) == -1) {
#ifdef DEBUG
                perror("setsockopt");
#endif
                close(sockfd);
                return -1;
            }
        }

        uint8_t opt[40];
        ssize_t opt_len = ip_build_rr_option(opt, sizeof(opt));
        if (opt_len == -1)
            return -1;

        if (setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, opt,
                       (socklen_t)opt_len) == -1) {
            perror("setsockopt IP_OPTIONS");
            return -1;
        }
        int one = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_RECVOPTS, &one, sizeof(one)) ==
            -1) {
            perror("setsockopt IP_RECVOPTS");
            return -1;
        }
        return sockfd;

    } else {
        sockfd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);

        if (sockfd < 0) {
#ifdef DEBUG
            perror("socket");
#endif
            return -1;
        }

        // Drop privileges to root user to avoid security issues
        if (setgid(0) == -1 || setuid(0) == -1) {
#ifdef DEBUG
            perror("setgid/setuid");
#endif
            close(sockfd);
            return -1;
        }
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &(int){1},
                       sizeof(int)) == -1) {
#ifdef DEBUG
            perror("setsockopt");
#endif
            close(sockfd);
            return -1;
        }

        return sockfd;
    }
}

int create_target_packet(FT_PING *s_ping) {
    if (s_ping->s_settings._root) {
        s_ping->_ip_header = s_ping->_packet;
        s_ping->_icmp_header = s_ping->s_settings._route
                                   ? s_ping->_packet + IP_MAX_HDR_LEN
                                   : s_ping->_packet + IP_HDR_LEN;
    } else {
        s_ping->_ip_header = NULL;
        s_ping->_icmp_header = s_ping->_packet;
    }
    size_t icmp_buffer_size =
        IP_MAXPACKET - (size_t)(s_ping->_icmp_header - s_ping->_packet);
    if (init_icmp_packet(s_ping->_icmp_header, icmp_buffer_size,
                         s_ping->s_packet_settings._icmp_type) == -1) {
        return -1;
    }
    if (set_icmp_data(s_ping->_icmp_header, icmp_buffer_size,
                      s_ping->s_packet_settings._payload_size,
                      s_ping->s_packet_settings._pattern,
                      sizeof(s_ping->s_packet_settings._pattern)) == -1) {
        return -1;
    }

    if (s_ping->s_settings._root) {
        struct in_addr dest;
        uint8_t opt[IP_MAX_OPTS_LEN]; /* 40 bytes max */
        ssize_t opt_len = 0;

        if (inet_pton(AF_INET, s_ping->s_current_target->_target_ip, &dest) !=
            1) {
            return -1;
        }
        if (s_ping->s_settings._route) {
            opt_len = ip_build_rr_option(opt, sizeof(opt));
            if (opt_len == -1) {
                return -1;
            }
        }
        if (create_ip_header(
                s_ping->_ip_header,
                IP_MAXPACKET - (size_t)(s_ping->_ip_header - s_ping->_packet),
                s_ping->s_packet_settings._payload_size + ICMP_HDR_LEN,
                s_ping->s_packet_settings._tos, s_ping->s_packet_settings._ttl,
                IPPROTO_ICMP, dest, s_ping->s_settings._route ? opt : NULL,
                (size_t)opt_len) == -1) {
            return -1;
        }
    }
    return 0;
}

int send_packet(int sockfd, FT_PING *s_ping) {
    TARGET *t = s_ping->s_current_target;
    const size_t icmp_len =
        ICMP_HDR_LEN + s_ping->s_packet_settings._payload_size;
    const size_t total_len =
        (size_t)(s_ping->_icmp_header - s_ping->_packet) + icmp_len;

    if (change_icmp_timeval(s_ping->_icmp_header, icmp_len,
                            s_ping->s_packet_settings._payload_size) == -1)
        return -1;
    if (change_icmp_sequence(s_ping->_icmp_header, icmp_len,
                             htons((uint16_t)t->_seq)) == -1)
        return -1;

    ssize_t n = sendto(sockfd, s_ping->_packet, total_len, 0,
                       (struct sockaddr *)&t->s_dest, sizeof(t->s_dest));
    if (n == -1) {
#ifdef DEBUG
        perror("sendto");
#endif
        return -1;
    }
    uint16_t seq = (uint16_t)t->_seq;
    s_ping->_received[seq / 8] &= (uint8_t)~(1u << (seq % 8));
    return 0;
}

