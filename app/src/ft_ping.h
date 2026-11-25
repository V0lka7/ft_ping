#ifndef FT_PING_H
#define FT_PING_H

#include <netdb.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "protocols/ft_icmp.h"

typedef enum PACKET_TYPE { ECHO, TIMESTAMP } PACKET_TYPE;

typedef struct PACKET_SETTING {

#define DEFAULT_TOS 0
#define DEFAULT_TTL IPDEFTTL // 64
#define DEFAULT_ROUTE 0      // false
#define DEFAULT_TYPE 0       // ECHO
#define DEFAULT_PAYLOAD_SIZE 56

#define MAX_TTL 255
#define MAX_TOS 255
#define MAX_PAYLOAD_SIZE                                                       \
    IP_MAXPACKET - (MAX_IP_HDR_LEN + MAX_ICMP_HDR_LEN) // 65535 - 76

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
} STATISTIC;

typedef struct TARGET {
    char _target_name[NI_MAXHOST];
    char _target_ip[INET_ADDRSTRLEN];

    size_t _request_count;
    bool _init;

    STATISTIC _statistic;

    struct TARGET *next;
} TARGET;

typedef struct FT_PING {
    PING_SETTING _settings;
    PACKET_SETTING _packet_settings;

    TARGET *_targets;
    TARGET *_current_target;
} FT_PING;

void clear_targets(TARGET *targets);

int resolve_dns(FT_PING *s_ping, TARGET *target);
int dns_loopback(FT_PING *s_ping, TARGET *target);

int create_socket(PING_SETTING *settings);

#endif
