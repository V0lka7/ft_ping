#include "protocols/ft_ip.h"
#include "greatest.h"
#include "utils.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
 
#define BUF_SIZE 128
#define TEST_PROTO 1 // ICMP
 
/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */
 
static struct in_addr addr_of(const char *s) {
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a;
}
 
// Builds hdr + payload in buf. Returns total length (or -1 on failure).
static int build_packet(uint8_t *buf, const uint8_t *opts, size_t opts_len,
                        const uint8_t *payload, size_t payload_len) {
    int hdr = create_ip_header(buf, BUF_SIZE, payload_len, 0, 64, TEST_PROTO,
                               addr_of("8.8.8.8"), opts, opts_len);
    if (hdr < 0)
        return -1;
    if (payload_len > 0)
        memcpy(buf + hdr, payload, payload_len);
    return hdr + (int)payload_len;
}
 
/* ------------------------------------------------------------------------ */
/* create_ip_header                                                         */
/* ------------------------------------------------------------------------ */
 
TEST create_null_packet(void) {
    ASSERT_EQ(-1, create_ip_header(NULL, BUF_SIZE, 0, 0, 64, TEST_PROTO,
                                   addr_of("1.1.1.1"), NULL, 0));
    PASS();
}
 
TEST create_opts_len_not_multiple_of_4(void) {
    uint8_t buf[BUF_SIZE], opts[8] = {0};
    ASSERT_EQ(-1, create_ip_header(buf, BUF_SIZE, 0, 0, 64, TEST_PROTO,
                                   addr_of("1.1.1.1"), opts, 3));
    PASS();
}
 
TEST create_opts_too_long(void) {
    uint8_t buf[BUF_SIZE], opts[48] = {0};
    ASSERT_EQ(-1, create_ip_header(buf, BUF_SIZE, 0, 0, 64, TEST_PROTO,
                                   addr_of("1.1.1.1"), opts, 44));
    PASS();
}
 
TEST create_opts_null_with_len(void) {
    uint8_t buf[BUF_SIZE];
    ASSERT_EQ(-1, create_ip_header(buf, BUF_SIZE, 0, 0, 64, TEST_PROTO,
                                   addr_of("1.1.1.1"), NULL, 4));
    PASS();
}
 
TEST create_buffer_too_small(void) {
    uint8_t buf[BUF_SIZE];
    ASSERT_EQ(-1, create_ip_header(buf, IP_MIN_HDR_LEN - 1, 0, 0, 64,
                                   TEST_PROTO, addr_of("1.1.1.1"), NULL, 0));
    PASS();
}
 
TEST create_total_len_overflow(void) {
    uint8_t buf[BUF_SIZE];
    ASSERT_EQ(-1, create_ip_header(buf, BUF_SIZE, UINT16_MAX, 0, 64,
                                   TEST_PROTO, addr_of("1.1.1.1"), NULL, 0));
    PASS();
}
 
TEST create_no_options(void) {
    uint8_t buf[BUF_SIZE];
    int ret = create_ip_header(buf, BUF_SIZE, 8, 0x10, 42, TEST_PROTO,
                               addr_of("9.9.9.9"), NULL, 0);
    ASSERT_EQ(IP_MIN_HDR_LEN, ret);
 
    const struct iphdr *ip = (const struct iphdr *)buf;
    ASSERT_EQ(4, ip->version);
    ASSERT_EQ(5, ip->ihl);
    ASSERT_EQ(0x10, ip->tos);
    ASSERT_EQ(IP_MIN_HDR_LEN + 8, ntohs(ip->tot_len));
    ASSERT_EQ((uint16_t)getpid(), ntohs(ip->id));
    ASSERT_EQ(0, ip->frag_off);
    ASSERT_EQ(42, ip->ttl);
    ASSERT_EQ(TEST_PROTO, ip->protocol);
    ASSERT_EQ(0, ip->saddr);
    ASSERT_EQ(addr_of("9.9.9.9").s_addr, ip->daddr);
    ASSERT_EQ(0, checksum(buf, IP_MIN_HDR_LEN)); // valid checksum sums to 0
    PASS();
}
 
TEST create_with_options(void) {
    uint8_t buf[BUF_SIZE], opts[IP_MAX_OPTS_LEN];
    ip_build_rr_option(opts, sizeof(opts));
 
    int ret = create_ip_header(buf, BUF_SIZE, 16, 0, 64, TEST_PROTO,
                               addr_of("9.9.9.9"), opts, IP_MAX_OPTS_LEN);
    ASSERT_EQ(IP_MAX_HDR_LEN, ret);
 
    const struct iphdr *ip = (const struct iphdr *)buf;
    ASSERT_EQ(15, ip->ihl);
    ASSERT_EQ(IP_MAX_HDR_LEN + 16, ntohs(ip->tot_len));
    ASSERT_MEM_EQ(opts, buf + IP_MIN_HDR_LEN, IP_MAX_OPTS_LEN);
    ASSERT_EQ(0, checksum(buf, IP_MAX_HDR_LEN)); // checksum covers options
    PASS();
}

/* ------------------------------------------------------------------------ */
/* ip_build_rr_option                                                       */
/* ------------------------------------------------------------------------ */
 
TEST rr_null(void) {
    ASSERT_EQ(0, ip_build_rr_option(NULL, IP_MAX_OPTS_LEN));
    PASS();
}
 
TEST rr_buffer_too_small(void) {
    uint8_t opt[IP_MAX_OPTS_LEN];
    ASSERT_EQ(0, ip_build_rr_option(opt, IP_MAX_OPTS_LEN - 1));
    PASS();
}
 
TEST rr_content(void) {
    uint8_t opt[IP_MAX_OPTS_LEN];
    memset(opt, 0xAA, sizeof(opt));
 
    ASSERT_EQ(IP_MAX_OPTS_LEN, ip_build_rr_option(opt, sizeof(opt)));
    ASSERT_EQ(IPOPT_RR, opt[0]);
    ASSERT_EQ(3 + 4 * IP_RR_MAX_ADDRS, opt[1]);
    ASSERT_EQ(IPOPT_MINOFF, opt[2]);
    for (size_t i = 3; i < IP_MAX_OPTS_LEN; i++)
        ASSERT_EQ(0, opt[i]); // addresses slots + EOL padding
    PASS();
}

 
/* ------------------------------------------------------------------------ */
/* ip_parse                                                                 */
/* ------------------------------------------------------------------------ */
 
TEST parse_null_args(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, NULL, 0);
    ASSERT_EQ(IP_MIN_HDR_LEN, len);
 
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(NULL, len, &info));
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, len, NULL));
    PASS();
}
 
TEST parse_too_short(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    build_packet(buf, NULL, 0, NULL, 0);
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, IP_MIN_HDR_LEN - 1, &info));
    PASS();
}
 
TEST parse_bad_version(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, NULL, 0);
    buf[0] = 0x65; // version 6, ihl 5
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, len, &info));
    PASS();
}
 
TEST parse_ihl_too_small(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, NULL, 0);
    buf[0] = 0x44; // version 4, ihl 4 (16 bytes < 20)
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, len, &info));
    PASS();
}
 
TEST parse_ihl_larger_than_buffer(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, NULL, 0);
    buf[0] = 0x4F; // ihl 15 => 60 bytes, but only 20 provided
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, len, &info));
    PASS();
}
 
TEST parse_total_len_smaller_than_header(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, NULL, 0);
    buf[2] = 0;
    buf[3] = 10; // total_len = 10 < 20
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, len, &info));
    PASS();
}
 
TEST parse_total_len_larger_than_buffer(void) {
    uint8_t buf[BUF_SIZE], payload[10] = {0};
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, payload, sizeof(payload));
    ASSERT_EQ(IP_ERR_MALFORMED, ip_parse(buf, len - 1, &info)); // truncated
    PASS();
}
 
TEST parse_bad_checksum(void) {
    uint8_t buf[BUF_SIZE];
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, NULL, 0);
    buf[8] ^= 0xFF; // corrupt TTL without fixing checksum
    ASSERT_EQ(IP_ERR_CHECKSUM, ip_parse(buf, len, &info));
    PASS();
}
 
TEST parse_valid_no_options(void) {
    uint8_t buf[BUF_SIZE];
    const uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8};
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, payload, sizeof(payload));
 
    ASSERT_EQ(0, ip_parse(buf, len, &info));
    ASSERT_EQ(4, info.version);
    ASSERT_EQ(IP_MIN_HDR_LEN, info.hdr_len);
    ASSERT_EQ(64, info.ttl);
    ASSERT_EQ(TEST_PROTO, info.protocol);
    ASSERT_EQ(len, info.total_len);
    ASSERT_EQ((uint16_t)getpid(), info.id);
    ASSERT_EQ(0, info.src.s_addr);
    ASSERT_EQ(addr_of("8.8.8.8").s_addr, info.dst.s_addr);
    ASSERT_EQ(NULL, info.opts);
    ASSERT_EQ(0, info.opts_len);
    ASSERT_EQ(buf + IP_MIN_HDR_LEN, info.payload);
    ASSERT_EQ(sizeof(payload), info.payload_len);
    ASSERT_MEM_EQ(payload, info.payload, sizeof(payload));
    PASS();
}
 
TEST parse_valid_with_options(void) {
    uint8_t buf[BUF_SIZE], opts[IP_MAX_OPTS_LEN];
    const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    struct ip_info info;
 
    ip_build_rr_option(opts, sizeof(opts));
    int len = build_packet(buf, opts, sizeof(opts), payload, sizeof(payload));
 
    ASSERT_EQ(0, ip_parse(buf, len, &info));
    ASSERT_EQ(IP_MAX_HDR_LEN, info.hdr_len);
    ASSERT_EQ(buf + IP_MIN_HDR_LEN, info.opts);
    ASSERT_EQ(IP_MAX_OPTS_LEN, info.opts_len);
    ASSERT_EQ(buf + IP_MAX_HDR_LEN, info.payload);
    ASSERT_EQ(sizeof(payload), info.payload_len);
    PASS();
}
 
TEST parse_ignores_trailing_bytes(void) {
    // len bigger than total_len (e.g. ethernet padding): payload must be
    // bounded by total_len, not by len
    uint8_t buf[BUF_SIZE] = {0}, payload[4] = {9, 9, 9, 9};
    struct ip_info info;
    int len = build_packet(buf, NULL, 0, payload, sizeof(payload));
 
    ASSERT_EQ(0, ip_parse(buf, len + 10, &info));
    ASSERT_EQ(len, info.total_len);
    ASSERT_EQ(sizeof(payload), info.payload_len);
    PASS();
}

static struct ip_info info_with_opts(const uint8_t *opts, size_t opts_len) {
    struct ip_info info;
    memset(&info, 0, sizeof(info));
    info.opts = opts;
    info.opts_len = opts_len;
    return info;
}
 
TEST rr_addrs_null_args(void) {
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    uint8_t opts[4] = {IPOPT_NOP, IPOPT_NOP, IPOPT_NOP, IPOPT_NOP};
    struct ip_info info = info_with_opts(opts, sizeof(opts));
    struct ip_info no_opts = info_with_opts(NULL, 0);
 
    ASSERT_EQ(0, ip_get_rr_addrs(NULL, addrs, IP_RR_MAX_ADDRS));
    ASSERT_EQ(0, ip_get_rr_addrs(&info, NULL, IP_RR_MAX_ADDRS));
    ASSERT_EQ(0, ip_get_rr_addrs(&no_opts, addrs, IP_RR_MAX_ADDRS));
    PASS();
}
 
TEST rr_addrs_empty_route(void) {
    // pointer = 4 => no address recorded yet
    uint8_t opts[IP_MAX_OPTS_LEN];
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    ip_build_rr_option(opts, sizeof(opts));
    struct ip_info info = info_with_opts(opts, sizeof(opts));
 
    ASSERT_EQ(0, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    PASS();
}
 
TEST rr_addrs_two_addresses(void) {
    uint8_t opts[IP_MAX_OPTS_LEN];
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    struct in_addr a = addr_of("10.0.0.1"), b = addr_of("192.168.1.254");
 
    ip_build_rr_option(opts, sizeof(opts));
    memcpy(opts + 3, &a, 4);
    memcpy(opts + 7, &b, 4);
    opts[2] = 4 + 2 * 4; // pointer after 2 addresses
    struct ip_info info = info_with_opts(opts, sizeof(opts));
 
    ASSERT_EQ(2, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    ASSERT_EQ(a.s_addr, addrs[0].s_addr);
    ASSERT_EQ(b.s_addr, addrs[1].s_addr);
    PASS();
}
 
TEST rr_addrs_full_route(void) {
    // pointer > length => all 9 slots are filled
    uint8_t opts[IP_MAX_OPTS_LEN];
    struct in_addr addrs[IP_RR_MAX_ADDRS];
 
    ip_build_rr_option(opts, sizeof(opts));
    for (int i = 0; i < IP_RR_MAX_ADDRS; i++) {
        struct in_addr a;
        a.s_addr = htonl(0x0A000001 + i);
        memcpy(opts + 3 + 4 * i, &a, 4);
    }
    opts[2] = 4 + 4 * IP_RR_MAX_ADDRS; // 40
    struct ip_info info = info_with_opts(opts, sizeof(opts));
 
    ASSERT_EQ(IP_RR_MAX_ADDRS, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    for (int i = 0; i < IP_RR_MAX_ADDRS; i++)
        ASSERT_EQ(htonl(0x0A000001 + i), addrs[i].s_addr);
    PASS();
}
 
TEST rr_addrs_respects_max(void) {
    uint8_t opts[IP_MAX_OPTS_LEN];
    struct in_addr addrs[2];
 
    ip_build_rr_option(opts, sizeof(opts));
    opts[2] = 4 + 4 * 5; // 5 addresses recorded
    struct ip_info info = info_with_opts(opts, sizeof(opts));
 
    ASSERT_EQ(2, ip_get_rr_addrs(&info, addrs, 2));
    PASS();
}
 
TEST rr_addrs_invalid_pointer(void) {
    uint8_t opts[IP_MAX_OPTS_LEN];
    struct in_addr addrs[IP_RR_MAX_ADDRS];
 
    ip_build_rr_option(opts, sizeof(opts));
    opts[2] = 3; // < IPOPT_MINOFF
    struct ip_info info = info_with_opts(opts, sizeof(opts));
 
    ASSERT_EQ(0, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    PASS();
}
 
TEST rr_addrs_skips_nop_prefix(void) {
    uint8_t opts[12] = {0};
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    struct in_addr a = addr_of("1.2.3.4");
 
    opts[0] = IPOPT_NOP;
    opts[1] = IPOPT_RR;
    opts[2] = 7;  // length: 3 + 1 address
    opts[3] = 8;  // pointer: 1 address recorded
    memcpy(opts + 4, &a, 4);
    struct ip_info info = info_with_opts(opts, 8);
 
    ASSERT_EQ(1, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    ASSERT_EQ(a.s_addr, addrs[0].s_addr);
    PASS();
}
 
TEST rr_addrs_skips_other_option(void) {
    // an unrelated option (type 0x44 = timestamp, len 4) before the RR
    uint8_t opts[12] = {0x44, 4, 0, 0, IPOPT_RR, 7, 8, 0, 0, 0, 0, 0};
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    struct in_addr a = addr_of("5.6.7.8");
 
    // RR is 7 bytes: type, len, ptr, addr(4). Place at index 4.
    memcpy(opts + 7, &a, 4);
    opts[5] = 7; // length
    opts[6] = 8; // pointer
    struct ip_info info = info_with_opts(opts, 12);
 
    ASSERT_EQ(1, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    ASSERT_EQ(a.s_addr, addrs[0].s_addr);
    PASS();
}
 
TEST rr_addrs_eol_stops(void) {
    uint8_t opts[8] = {IPOPT_EOL, IPOPT_RR, 7, 8, 1, 2, 3, 4};
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    struct ip_info info = info_with_opts(opts, sizeof(opts));
 
    ASSERT_EQ(0, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    PASS();
}
 
TEST rr_addrs_malformed_length(void) {
    struct in_addr addrs[IP_RR_MAX_ADDRS];
 
    // option length < 2
    uint8_t bad1[4] = {IPOPT_RR, 1, 4, 0};
    struct ip_info i1 = info_with_opts(bad1, sizeof(bad1));
    ASSERT_EQ(0, ip_get_rr_addrs(&i1, addrs, IP_RR_MAX_ADDRS));
 
    // option length exceeds opts_len
    uint8_t bad2[4] = {IPOPT_RR, 39, 4, 0};
    struct ip_info i2 = info_with_opts(bad2, sizeof(bad2));
    ASSERT_EQ(0, ip_get_rr_addrs(&i2, addrs, IP_RR_MAX_ADDRS));
 
    // type byte is the last byte: no length byte available
    uint8_t bad3[4] = {IPOPT_NOP, IPOPT_NOP, IPOPT_NOP, IPOPT_RR};
    struct ip_info i3 = info_with_opts(bad3, sizeof(bad3));
    ASSERT_EQ(0, ip_get_rr_addrs(&i3, addrs, IP_RR_MAX_ADDRS));
    PASS();
}
 
TEST rr_roundtrip(void) {
    // create_ip_header + ip_parse + ip_get_rr_addrs
    uint8_t buf[BUF_SIZE], opts[IP_MAX_OPTS_LEN];
    struct in_addr addrs[IP_RR_MAX_ADDRS];
    struct in_addr a = addr_of("172.16.0.1");
    struct ip_info info;
 
    ip_build_rr_option(opts, sizeof(opts));
    memcpy(opts + 3, &a, 4);
    opts[2] = 8;
 
    int len = build_packet(buf, opts, sizeof(opts), NULL, 0);
    ASSERT_EQ(0, ip_parse(buf, len, &info));
    ASSERT_EQ(1, ip_get_rr_addrs(&info, addrs, IP_RR_MAX_ADDRS));
    ASSERT_EQ(a.s_addr, addrs[0].s_addr);
    PASS();
}

SUITE(ip_suite) {
    RUN_TEST(create_null_packet);
    RUN_TEST(create_opts_len_not_multiple_of_4);
    RUN_TEST(create_opts_too_long);
    RUN_TEST(create_opts_null_with_len);
    RUN_TEST(create_buffer_too_small);
    RUN_TEST(create_total_len_overflow);
    RUN_TEST(create_no_options);
    RUN_TEST(create_with_options);

    RUN_TEST(rr_null);
    RUN_TEST(rr_buffer_too_small);
    RUN_TEST(rr_content);

    RUN_TEST(parse_null_args);
    RUN_TEST(parse_too_short);
    RUN_TEST(parse_bad_version);
    RUN_TEST(parse_ihl_too_small);
    RUN_TEST(parse_ihl_larger_than_buffer);
    RUN_TEST(parse_total_len_smaller_than_header);
    RUN_TEST(parse_total_len_larger_than_buffer);
    RUN_TEST(parse_bad_checksum);
    RUN_TEST(parse_valid_no_options);
    RUN_TEST(parse_valid_with_options);
    RUN_TEST(parse_ignores_trailing_bytes);

    RUN_TEST(rr_addrs_null_args);
    RUN_TEST(rr_addrs_empty_route);
    RUN_TEST(rr_addrs_two_addresses);
    RUN_TEST(rr_addrs_full_route);
    RUN_TEST(rr_addrs_respects_max);
    RUN_TEST(rr_addrs_invalid_pointer);
    RUN_TEST(rr_addrs_skips_nop_prefix);
    RUN_TEST(rr_addrs_skips_other_option);
    RUN_TEST(rr_addrs_eol_stops);
    RUN_TEST(rr_addrs_malformed_length);
    RUN_TEST(rr_roundtrip);
}

