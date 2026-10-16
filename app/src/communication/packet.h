#ifndef PACKET_H
#define PACKET_H

#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>

#define IP_HDR_LEN 20
#define MAX_IP_HDR_LEN IP_HDR_LEN + MAX_IPOPTLEN

#define ICMP_HDR_LEN 8
// 8 bytes of the original Data Datagram RFC 792 parameter problem message
#define MAX_ICMP_HDR_LEN ICMP_HDR_LEN + MAX_IP_HDR_LEN + 8 // => 76 Bytes

#define DEFAULT_PATTERN "0123456789abcdef"
#define DEFAULT_PATTERN_LEN 17
#define DEFAULT_EMPTY_PATTERN '0'

enum PACKET_TYPE;

int init_icmp_packet(uint8_t *packet, const size_t pack_len,
                       const enum PACKET_TYPE type);

int set_icmp_data(uint8_t *packet, const size_t pack_len,
                  const size_t payload_len, const uint8_t *pattern,
                  const size_t pattern_len);

int set_icmp_timeval(uint8_t *packet, const size_t packet_len);
int set_icmp_payload(uint8_t *packet, const size_t packet_len,
                     const size_t payload_len, const uint8_t *pattern,
                     const size_t pattern_len);

int change_icmp_timeval(uint8_t *packet, const size_t packet_len,
                        const size_t payload_len);
int change_icmp_sequence(uint8_t *packet, const size_t packet_len,
                         const uint16_t seq_value);

uint16_t checksum(void *addr, size_t len);

#endif
