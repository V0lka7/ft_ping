#ifndef FT_PING_H
#define FT_PING_H

#include <stdint.h>
#include <stdlib.h>

#define DEFAULT_PAYLOAD_SIZE 56
#define DEFAULT_INTERVAL 1

typedef enum PACKET_TYPE {
    ECHO,
    TIMESTAMP
} PACKET_TYPE;

typedef struct PACKET_SETTING {
    uint8_t _tos; // Type of Service
    uint8_t _ttl; // Time to Live

    bool _route; // Same as PING_SETTING _route

    PACKET_TYPE _icmp_type;
    size_t _payload_size; // max 65399 (from ping inetutils)

} PACKET_SETTING;

typedef struct PING_SETTING {
    bool _verbose;
    bool _quiet;

    bool _route;

    size_t _interval;
    size_t _count;
} PING_SETTING;

typedef struct SOCKET_SETTING {
    bool _root;
    size_t _linger;
    size_t _timeout;
} SOCKET_SETTING;

typedef struct FT_PING {
    PING_SETTING _settings;
    PACKET_TYPE _packet_type;
    SOCKET_SETTING _socket_settings;
} FT_PING;

#endif

