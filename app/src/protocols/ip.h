#ifndef IP_H
#define IP_H

#include <stdint.h>

int create_ip_header(uint8_t *packet, const size_t packet_len,
                     const size_t data_len, const uint8_t tos, const uint8_t ttl,
                     const uint8_t protocol, const struct in_addr dest,
                     const uint8_t *opts, const size_t opts_len);

size_t ip_build_rr_option(uint8_t opt)

#endif
