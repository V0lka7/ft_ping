#ifndef PACKET_H
#define PACKET_H

#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#define IP_HDR_LEN 20
#define MAX_IP_HDR_LEN IP_HDR_LEN + MAX_IPOPTLEN

#define ICMP_HDR_LEN 8
// 8 bytes of the original Data Datagram RFC 792 parameter problem message
#define MAX_ICMP_HDR_LEN ICMP_HDR_LEN + MAX_IP_HDR_LEN + 8 // => 76 Bytes



#endif
