#ifndef FT_PING_H
#define FT_PING_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef enum PACKET_TYPE {
    ECHO,
    TIMESTAMP
} PACKET_TYPE;

#define DEFAULT_TOS 0
#define DEFAULT_TTL 63
#define DEFAULT_ROUTE 0 // false
#define DEFAULT_TYPE 0 // ECHO
#define DEFAULT_PAYLOAD_SIZE 56

typedef struct PACKET_SETTING {
    uint8_t _tos; // Type of Service
    uint8_t _ttl; // Time to Live

    bool _route; // Same as PING_SETTING _route

    PACKET_TYPE _icmp_type;
    size_t _payload_size; // max 65399 (from ping inetutils)

} PACKET_SETTING;

#define DEFAULT_VERBOSE 0 // false
#define DEFAULT_QUIET 0 // false
#define DEFAULT_INTERVAL 1 // second
#define DEFAULT_COUNT // -1 infinite

typedef struct PING_SETTING {
    bool _verbose;
    bool _quiet;

    bool _route;

    size_t _interval;
    ssize_t _count;
} PING_SETTING;

#define DEFAULT_ROOT 0 // false
#define DEFAULT_LINGER -1
#define DEFAULT_TIMEOUT -1

typedef struct SOCKET_SETTING {
    bool _root;
    ssize_t _linger;
    ssize_t _timeout;
} SOCKET_SETTING;

typedef struct FT_PING {
    PING_SETTING _settings;
    PACKET_SETTING _packet_settings;
    SOCKET_SETTING _socket_settings;
} FT_PING;

#endif

