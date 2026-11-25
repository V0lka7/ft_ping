//===============================================================================iii=
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

#include "ft_ping.h"
#include "src/initialization/arguments_parser.h"
#include "src/signals_handler.h"

#include <argp.h>
#include <signal.h>
#include <strings.h>
#include <sys/signalfd.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <sys/epoll.h>

enum {
    FD_SIG,            /* = 0, signalfd for SIGINT and SIGTERM */
    FD_TIMER,          /* = 1, timerfd for sending packets */
    FD_SOCKET,         /* = 2, send and receive */
    FD_TIMEOUT,        /* = 3, timeout for the whole program */
    FD_ANSWER_TIMEOUT, /* = 4, timeout for receiving answers */
    FD_EPOLL,          /* = 5, epoll fd for monitoring all fds */
    FD_COUNT           /* = 6, array size */
};

static int fd_list[FD_COUNT] = {-1, -1, -1, -1, -1, -1};

#define MAX_EVENTS FD_COUNT

static int init_signal_fd();
static void fd_close_all(void);
static int start_timerfd(double interval);
static int ensure_dns_resolution(FT_PING *s_ping);
static void quit(FT_PING *s_ping, int status, const char *str);
static void init_target(FT_PING *s_ping);

int main(int argc, char **argv) {

    // if (init_signals_handler() == -1)
    //     return 1;

    FT_PING s_ping = {
        ._settings = {._verbose = DEFAULT_VERBOSE,
                      ._quiet = DEFAULT_QUIET,
                      ._route = DEFAULT_ROUTE,
                      ._interval = DEFAULT_INTERVAL,
                      ._count = DEFAULT_COUNT,
                      ._root = DEFAULT_ROOT,
                      ._linger = DEFAULT_LINGER,
                      ._timeout = DEFAULT_TIMEOUT},
        ._packet_settings = {._tos = DEFAULT_TOS,
                             ._ttl = DEFAULT_TTL,
                             ._route = DEFAULT_ROUTE,
                             ._icmp_type = DEFAULT_TYPE,
                             ._payload_size = DEFAULT_PAYLOAD_SIZE}};

    bzero(s_ping._packet_settings._pattern,
          sizeof(s_ping._packet_settings._pattern));
    s_ping._settings._root = geteuid() == 0;

    if (argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, &s_ping) != 0) {
        return 1;
    }
    return 0;

    /* Initialize socket file descriptor, first to drop the root privileges */
    fd_list[FD_SOCKET] = create_socket(&s_ping._settings);
    if (fd_list[FD_SOCKET] == -1)
        quit(&s_ping, 1, "create_socket");

    /* Initialize target list */
    init_target(&s_ping);

    /* Initialize signal file descriptor */
    fd_list[FD_SIG] = init_signal_fd();
    if (fd_list[FD_SIG] == -1)
        quit(&s_ping, 1, "init_signal_fd");

    /* Initialize timer file descriptor */
    fd_list[FD_TIMER] = start_timerfd(s_ping._settings._interval);
    if (fd_list[FD_TIMER] == -1) {
        quit(&s_ping, 1, "start_timerfd");
        return 1;
    }
    /* Initialize epoll file descriptor */
    fd_list[FD_EPOLL] = epoll_create1(EPOLL_CLOEXEC);
    if (fd_list[FD_EPOLL] == -1) {
        quit(&s_ping, 1, "epoll_create1");
        return 1;
    }

    /* Initialize timeout file descriptor */
    if (s_ping._settings._timeout > -1) {
        fd_list[FD_TIMEOUT] = start_timerfd(s_ping._settings._timeout);
        if (fd_list[FD_TIMEOUT] == -1) {
            quit(&s_ping, 1, "start_timerfd");
            return 1;
        }
    }

    /* Initialize timeout file descriptor for answer timeout */
    if (s_ping._settings._linger > -1) {
        fd_list[FD_ANSWER_TIMEOUT] = start_timerfd(s_ping._settings._linger);
        if (fd_list[FD_ANSWER_TIMEOUT] == -1) {
            quit(&s_ping, 1, "start_timerfd");
            return 1;
        }
    }

    struct epoll_event ev, events[MAX_EVENTS];

    int nfds = -1;
    while (v_quit) {
        nfds = epoll_wait(fd_list[FD_EPOLL], events, MAX_EVENTS, -1);

        if (s_ping._settings._count != 0) {
            if (s_ping._current_target->_request_count == 0) {
                // move to next target
                s_ping._current_target = s_ping._current_target->next;
                if (s_ping._current_target == NULL) {
                    quit(&s_ping, 0, "");
                }
            }
            s_ping._current_target->_request_count--;
        }
        if (ensure_dns_resolution(&s_ping) == -1) {
            quit(&s_ping, 1, "ensure_dns_resolution");
        }
        printf("PING %s (%s): %zu data bytes\n",
               s_ping._current_target->_target_name,
               s_ping._current_target->_target_ip,
               s_ping._packet_settings._payload_size);
    }

    clear_targets(s_ping._targets);

    return 0;
}

static int init_signal_fd() {
    sigset_t mask;
    int signal_fd;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        return -1;
    signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd == -1)
        return -1;
    return signal_fd;
}

static void fd_close_all(void) {
    for (int i = 0; i < FD_COUNT; i++) {
        if (fd_list[i] >= 0) {
            close(fd_list[i]);
            fd_list[i] = -1;
        }
    }
}

static int start_timerfd(double interval) {
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd == -1)
        return -1;

    time_t sec = (time_t)interval;
    long nsec = (long)((interval - (double)sec) * 1e9);

    /* {0,0} would DISARM the timer: clamp to 1 ns */
    if (sec == 0 && nsec < 1)
        nsec = 1;

    struct itimerspec its = {
        .it_value = {sec, nsec},    /* first tick */
        .it_interval = {sec, nsec}, /* then repeats */
    };
    if (timerfd_settime(tfd, 0, &its, NULL) == -1) {
        close(tfd);
        return -1;
    }
    return tfd;
}

static int ensure_dns_resolution(FT_PING *s_ping) {
    if (s_ping == NULL)
        return -1;

    if (s_ping->_current_target == NULL)
        return -1;

    if (s_ping->_current_target->_init == false) {
        if (resolve_dns(s_ping, s_ping->_current_target) == -1) {
            return -1;
        } else {
            printf("Resolved %s to %s\n", s_ping->_current_target->_target_name,
                   s_ping->_current_target->_target_ip);
            s_ping->_current_target->_init = true;
        }
    }
    return 0;
}

static void quit(FT_PING *s_ping, int status, const char *str) {
    if (errno != 0) {
#ifdef DEBUG
        perror(str);
#endif
    }
    if (s_ping != NULL)
        clear_targets(s_ping->_targets);
    fd_close_all();
    exit(status);
}

static void init_target(FT_PING *s_ping) {
    TARGET *target = s_ping->_targets;
    while (target != NULL) {
        target->_request_count = s_ping->_settings._count;
        target->_init = false;
        target = target->next;
    }
    s_ping->_current_target = s_ping->_targets;
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
                       const struct addrinfo *hints, struct addrinfo **res)
{ int ret = getaddrinfo(node, service, hints, res);

  if (ret != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
    return 1;
  }
  return 0;
}*/

// static int Getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
//                        char *host, socklen_t hostlen, char *serv,
//                        socklen_t servlen, int flags) {
//   int ret = getnameinfo(addr, addrlen, host, hostlen, serv, servlen,
//   flags);

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
