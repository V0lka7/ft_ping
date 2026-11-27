#ifndef FT_PING_COM_H
#define FT_PING_COM_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ft_ping.h"

typedef struct REPLY {
    uint16_t seq;    // icmp sequence number (from icmp header)
    uint8_t ttl;     // ip ttl value (from ip header)
    size_t icmp_len; // icmp packet length minus icmp header (from icmp header)
    struct in_addr from;    // source address (from ip header)
    struct timeval sent_tv; // timestamp copied from the payload of the icmp
    // packet (from icmp payload)
    bool has_time;
    uint8_t route[40]; // raw record-route option (max 40 bytes)
    size_t route_len;  // 0 if no record-route option, otherwise the length of
                       // the option
} REPLY;

int handle_reply(FT_PING *s_ping, int sockfd);
int handle_root_reply(FT_PING *s_ping, int sockfd);
int handle_user_reply(FT_PING *s_ping, int sockfd);

#endif