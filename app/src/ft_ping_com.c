#include "ft_ping_com.h"
#include "protocols/ft_ip.h"

#include <string.h>
#include <strings.h>
#include <sys/socket.h>

static uint8_t recv_buf[IP_MAXPACKET];
static uint8_t send_buf[IP_MAXPACKET];

int handle_reply(FT_PING *s_ping, int sockfd) {
    if (s_ping->s_settings._root)
        return handle_root_reply(s_ping, sockfd);
    else
        return handle_user_reply(s_ping, sockfd);
}

int handle_root_reply(FT_PING *s_ping, int sockfd) {
    bzero(recv_buf, sizeof(recv_buf));

    struct sockaddr_in from;
    union {
        char cmsgbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(int)) +
                     CMSG_SPACE(IP_MAX_OPTS_LEN)];
        struct cmsghdr align;
    } u_ctrl;
    int tos = -1, ttl = -1;

    struct iovec iov = {.iov_base = recv_buf, .iov_len = sizeof(recv_buf)};
    struct msghdr msg = {
        .msg_name = &from,
        .msg_namelen = sizeof(from),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = u_ctrl.cmsgbuf,
        .msg_controllen = sizeof(u_ctrl.cmsgbuf),
    };
    ssize_t n = recvmsg(sockfd, &msg, 0);
    // handle errors

    uint8_t *opts = NULL;
    size_t opts_len = 0;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP) {
            if (cmsg->cmsg_type == IP_TOS) {
                memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));
            } else if (cmsg->cmsg_type == IP_TTL) {
                memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
            } else if (cmsg->cmsg_type == IP_OPTIONS) {
                opts = CMSG_DATA(cmsg);
                opts_len = cmsg->cmsg_len - CMSG_LEN(0);
            }
        }
    }

    if (s_ping->s_settings._route) {
        
    }
}

// int handle_user_reply(FT_PING *s_ping, int sockfd);