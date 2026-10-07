//================================================================================
// You will have to manage a simple IPv4 (address/hostname) as parameters

// You will have to manage FQDN without doing the DNS resolution in the packet
// return

// You are allowed to use all the functions of the printf family

//  -v -?

// Additional -f -l -n -w -W -p -r -s -T --ttl --ip-timestamp flags...

// the flags -V, –usage, –echo are not considered as bonus

// Of course two flags corresponding to the same feature (eg: -t and
// –type) are not considered as two bonuses
//================================================================================

// #include <netinet/in.h>
// #include <sys/socket.h>

// #include <stdio.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "ft_ping.h"
#include "src/initialization/arguments_parser.h"
#include <argp.h>

int main(int argc, char **argv) {
    FT_PING s_ping;

    argp_parse(&g_argp, argc, argv, 0, 0, &s_ping);
    return 0;
}

/*
static int Getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res);
// static int Getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
//                        char *host, socklen_t hostlen, char *serv,
//                        socklen_t servlen, int flags);

struct sockaddr *get_ipv4_node(struct addrinfo *list);
uint16_t checksum(void *addr, size_t len);

int main(int argc, char **argv) {
  struct addrinfo hints;
  struct addrinfo *res;
  char host[NI_MAXHOST], serv[NI_MAXSERV];

  memset(&hints, 0, sizeof(struct addrinfo));
  memset(host, 0, sizeof(host));
  memset(serv, 0, sizeof(serv));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;

  if (argc != 2) {
    fprintf(stderr, "error: %s\n", argv[0]);
    return 1;
  }

  int ret = Getaddrinfo(argv[1], NULL, &hints, &res);
  if (ret != 0) {
    perror("Getaddrinfo");
    return 1;
  }

  // TODO check if res has good family, good type and good protocole
  struct sockaddr_in sock_copy;
  memcpy(&sock_copy, res->ai_addr, sizeof(struct sockaddr_in));
  freeaddrinfo(res);

  struct msghdr msg_hdr;
  memset(&msg_hdr, 0, sizeof(msg_hdr));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));

  msg_hdr.msg_name = &sock_copy;
  msg_hdr.msg_namelen = sizeof(sock_copy);

  char packet[9];
  memset(packet, 0, sizeof(packet));

  // icmphdr = 8bytes
  struct icmphdr *icmp_hdr = (struct icmphdr *)packet;

  icmp_hdr->type = ICMP_ECHO;
  icmp_hdr->code = 0;
  icmp_hdr->checksum = 0;
  icmp_hdr->un.echo.id = htons(getpid());
  icmp_hdr->un.echo.sequence = 0;

  memset(packet + sizeof(struct icmphdr), 'A',
         sizeof(packet) - sizeof(struct icmphdr));
  icmp_hdr->checksum = checksum(packet, sizeof(packet));

  iov.iov_base = packet;
  iov.iov_len = sizeof(packet);

  msg_hdr.msg_iov = &iov;
  msg_hdr.msg_iovlen = 1;

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  sendmsg(sockfd, &msg_hdr, 0);

  char buffer[1024];
  struct iovec m_iov;

  m_iov.iov_base = buffer;
  m_iov.iov_len = sizeof(buffer);

  struct sockaddr_storage addr;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));

  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);

  msg.msg_iov = &m_iov;
  msg.msg_iovlen = 1;
  ssize_t n = recvmsg(sockfd, &msg, 0);

  if (n < 0) {
    perror("recvmsg");
    return 1;
  }

  struct iphdr *ip = (struct iphdr *)buffer;
  int ip_header_len = ip->ihl * 4;

  struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);

  if (icmp->type == ICMP_ECHOREPLY) {
    printf("Got reply!\n");

    printf("id=%d\n", ntohs(icmp->un.echo.id));
    printf("seq=%d\n", ntohs(icmp->un.echo.sequence));
  }

  char ipstr[INET_ADDRSTRLEN];

  struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
  inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));

  printf("From: %s\n", ipstr);

  // for (tmp = res; tmp != NULL; tmp = tmp->ai_next) {
  //   Getnameinfo(tmp->ai_addr, tmp->ai_addrlen, host, sizeof(host), serv,
  //               sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);

  //   // puts(host);
  // }
  return 0;
}

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

struct sockaddr *get_ipv4_node(struct addrinfo *list) {
  struct sockaddr *node = NULL;
  struct addrinfo *tmp = list;

  while (tmp) {
    fprintf(stdout, "Family: %i\tType: %i\tProtocole: %i\n", tmp->ai_family,
            tmp->ai_socktype, tmp->ai_protocol);
    tmp = tmp->ai_next;
  }
  return node;
}

static int Getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **res) {
  int ret = getaddrinfo(node, service, hints, res);

  if (ret != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
    return 1;
  }
  return 0;
}*/

// static int Getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
//                        char *host, socklen_t hostlen, char *serv,
//                        socklen_t servlen, int flags) {
//   int ret = getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);

//   if (ret != 0) {
//     fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
//     return 1;
//   }
//   return 0;
// }

// #define BUFSIZE 1500
// /* globals */
// char sendbuf[BUFSIZE];
// int datalen; /* #bytes of data following ICMP header */
// char *host;
// int nsent; /* add 1 for each sendto() */
// pid_t pid; /* our PID */
// int sockfd;
// int verbose;

// Create socket
// uint8_t -> unsigned char -> 8bits
// uint16_t -> unsigned short -> 16bits
// uint32_t -> unsigned int -> 32bits
// uint64_t -> unsigned long long -> 64bits

// Echo or Echo Reply Message
//  0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |     Type      |     Code      |          Checksum             |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |           Identifier          |        Sequence Number        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |     Data ...
//    +-+-+-+-+-

// Addresses
// Address of the source of the ech message
// will become the address of destination of the reply
