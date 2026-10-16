#include "packet.h"
#include <bits/types/struct_timeval.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "ft_ping.h"

int init_icmp_packet(uint8_t *packet, const size_t pack_len,
                     const PACKET_TYPE type) {
    if (packet == NULL || pack_len < sizeof(struct icmphdr))
        return -1;

    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;

    icmp_hdr->type =
        type == ECHO ? (uint8_t)ICMP_ECHO : (uint8_t)ICMP_TIMESTAMP;
    icmp_hdr->code = (uint8_t)0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = htons(getpid());
    icmp_hdr->un.echo.sequence = 0;

    return 0;
}

int set_icmp_data(uint8_t *packet, const size_t packet_len,
                  const size_t payload_len, const uint8_t *pattern,
                  const size_t pattern_len) {

    if (packet == NULL || packet_len < sizeof(struct icmphdr) + payload_len)
        return -1;

    if (payload_len > 0) {
        size_t padding = 0;
        if (payload_len >= sizeof(struct timeval)) {
            set_icmp_timeval(packet + sizeof(struct icmphdr),
                             packet_len - sizeof(struct icmphdr));
            padding = sizeof(struct timeval);
        }
        set_icmp_payload(packet + sizeof(struct icmphdr) + padding,
                         packet_len - sizeof(struct icmphdr) - padding,
                         payload_len - padding, pattern, pattern_len);
    }

    struct icmphdr *ptr = (struct icmphdr *)packet;

    ptr->checksum = checksum(packet, packet_len + payload_len);
    return 0;
}

int set_icmp_timeval(uint8_t *packet, const size_t packet_len) {
    if (packet == NULL || packet_len < sizeof(struct timeval))
        return -1;
    struct timeval *time = (struct timeval *)packet;
    gettimeofday(time, NULL);
    return 0;
}

int change_icmp_timeval(uint8_t *packet, const size_t packet_len,
                        const size_t payload_len) {
    if (packet == NULL)
        return -1;
    if (payload_len < sizeof(struct timeval))
        return 0;
    if (set_icmp_timeval(packet + sizeof(struct icmphdr), packet_len) == -1)
        return -1;
    struct icmphdr *ptr = (struct icmphdr *)packet;

    ptr->checksum = 0;
    ptr->checksum = checksum(packet, packet_len);
    return 0;
}

int change_icmp_sequence(uint8_t *packet, const size_t packet_len,
                         const uint16_t seq_value) {
    if (packet == NULL || packet_len < sizeof(struct icmphdr))
        return -1;
    struct icmphdr *ptr = (struct icmphdr *)packet;

    ptr->un.echo.sequence = seq_value;
    ptr->checksum = 0;
    ptr->checksum = checksum(packet, packet_len);
    return 0;
}

int set_icmp_payload(uint8_t *packet, const size_t packet_len,
                     const size_t payload_len, const uint8_t *pattern,
                     const size_t pattern_len) {
    if (packet == NULL || packet_len < payload_len)
        return -1;

    static const char default_pattern[DEFAULT_PATTERN_LEN] = DEFAULT_PATTERN;
    static const size_t default_pattern_len = DEFAULT_PATTERN_LEN;

    const uint8_t *pattern_in_use =
        (pattern == NULL) ? (uint8_t *)default_pattern : pattern;
    const size_t pattern_in_use_len =
        (pattern == NULL) ? default_pattern_len : pattern_len;

    if (pattern_in_use_len == 0) {
        memset(packet, DEFAULT_EMPTY_PATTERN, payload_len);
    } else {
        for (size_t i = 0; i < payload_len; i += pattern_in_use_len) {
            size_t len_to_copy = (payload_len - i < pattern_in_use_len)
                                     ? payload_len - i
                                     : pattern_in_use_len;
            memcpy(packet + i, pattern_in_use, len_to_copy);
        }
    }
    return 0;
}

/*  Checksum function implemented following this document:
    RFC 1071: Computing the internet checksum
    https://www.rfc-editor.org/info/rfc1071/
*/
uint16_t checksum(void *addr, size_t len) {
    uint16_t *word = addr;
    uint32_t result = 0;
    for (size_t i = 0; i < len / sizeof(uint16_t); i++) {
        result += *(word + i);
    }
    if (len % 2 == 1) {
        result += *((uint8_t *)addr + len - 1);
    }
    result = (result >> 16) + (result & 0xffff);
    // Carry the previous add.
    result = (result >> 16) + (result & 0xffff);
    return ~result;
}
