#ifndef FT_PING_H
#define FT_PING_H

#include <netdb.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "protocols/ft_icmp.h"
#include "protocols/ft_ip.h"

#define MAX_SEQ 65536

typedef enum PACKET_TYPE { ECHO, TIMESTAMP } PACKET_TYPE;

typedef struct PACKET_SETTING {

#define DEFAULT_TOS 0
#define DEFAULT_TTL 63
#define DEFAULT_ROUTE 0 // false
#define DEFAULT_TYPE 0  // ECHO
#define DEFAULT_PAYLOAD_SIZE 56

#define MAX_TTL 255
#define MAX_TOS 255
#define MAX_PAYLOAD_SIZE                                                       \
    IP_MAXPACKET - (IP_MAX_HDR_LEN + ICMP_MAX_HDR_LEN) // 65535 - (60 + 16)

#define PATTERN_SIZE 16

    uint8_t _tos; // Type of Service
    uint8_t _ttl; // Time to Live

    bool _route; // Same as PING_SETTING _route

    PACKET_TYPE _icmp_type;
    size_t _payload_size; // max 65399 (from ping inetutils)
    uint8_t _pattern[PATTERN_SIZE];
} PACKET_SETTING;

typedef struct PING_SETTING {

#define DEFAULT_VERBOSE 0  // false
#define DEFAULT_QUIET 0    // false
#define DEFAULT_INTERVAL 1 // second
#define DEFAULT_COUNT 0    // 0 = infinite
#define DEFAULT_ROOT 0     // false
#define DEFAULT_LINGER -1
#define DEFAULT_TIMEOUT -1

    bool _verbose;
    bool _quiet;

    bool _route;

    double _interval;
    size_t _count;

    bool _root;
    ssize_t _linger;
    ssize_t _timeout;
} PING_SETTING;

typedef struct STATISTIC {
    size_t _sent;
    size_t _received;
    size_t _duplicates;
    double _min_rtt;
    double _max_rtt;
} STATISTIC;

typedef struct TARGET {
    char _target_name[NI_MAXHOST];
    char _target_ip[INET_ADDRSTRLEN];
    struct sockaddr_in s_dest;

    size_t _seq;
    bool _init;
    bool _route_showed;

    STATISTIC s_statistic;

    struct TARGET *_next;
} TARGET;

typedef struct FT_PING {
    PING_SETTING s_settings;
    PACKET_SETTING s_packet_settings;

    uint8_t _packet[IP_MAXPACKET];
    uint8_t *_ip_header;
    uint8_t *_icmp_header;

    TARGET *s_targets;
    TARGET *s_current_target;
    uint8_t _received[MAX_SEQ / 8]; // Bit array to track received packets
} FT_PING;

void clears_targets(TARGET *targets);

int resolve_dns(FT_PING *s_ping, TARGET *target);
int dns_loopback(FT_PING *s_ping, TARGET *target);

int create_socket(FT_PING *settings);

int create_target_packet(FT_PING *s_ping);
int send_packet(int sockfd, FT_PING *s_ping);

void read_reply(FT_PING *s_ping, int sockfd);

#endif
