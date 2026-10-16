#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "greatest.h"

#include "ft_ping.h" /* PACKET_TYPE enum (ECHO / TIMESTAMP) */
#include "protocols/icmp.h"
#include "utils.h" // checksum

#define HDR sizeof(struct icmphdr)
#define TV sizeof(struct timeval)
#define BUF_SIZE 256
#define GUARD 0xAA

/* Shared, 8-byte aligned scratch buffer (struct timeval is written in it). */
static alignas(8) uint8_t buf[BUF_SIZE];

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void reset_buf(void) { memset(buf, GUARD, sizeof buf); }

/* True if all `len` bytes of p equal `v`. */
static int all_bytes_equal(const uint8_t *p, size_t len, uint8_t v) {
    for (size_t i = 0; i < len; i++)
        if (p[i] != v)
            return 0;
    return 1;
}

/* A packet whose checksum field is correct sums (with the field) to 0. */
static int checksum_is_valid(uint8_t *p, size_t len) {
    return checksum(p, len) == 0;
}

/* True if the timeval stored at p lies within [before, after]. */
static int timeval_between(const uint8_t *p, const struct timeval *before,
                           const struct timeval *after) {
    struct timeval got;
    memcpy(&got, p, sizeof got);
    return !timercmp(&got, before, <) && !timercmp(&got, after, >);
}

/* ------------------------------------------------------------------ */
/* init_icmp_packet                                                   */
/* ------------------------------------------------------------------ */

TEST init_null_packet(void) {
    ASSERT_EQ(-1, init_icmp_packet(NULL, 64, ECHO));
    PASS();
}

TEST init_buffer_too_small(void) {
    reset_buf();
    ASSERT_EQ(-1, init_icmp_packet(buf, HDR - 1, ECHO));
    ASSERT_EQ(-1, init_icmp_packet(buf, 0, ECHO));
    /* nothing must have been written */
    ASSERT(all_bytes_equal(buf, sizeof buf, GUARD));
    PASS();
}

TEST init_echo_fields(void) {
    reset_buf();
    ASSERT_EQ(0, init_icmp_packet(buf, HDR, ECHO));

    struct icmphdr *h = (struct icmphdr *)buf;
    ASSERT_EQ_FMT((unsigned)ICMP_ECHO, (unsigned)h->type, "%u");
    ASSERT_EQ_FMT(0u, (unsigned)h->code, "%u");
    ASSERT_EQ_FMT(0u, (unsigned)h->checksum, "%u");
    ASSERT_EQ_FMT((unsigned)htons((uint16_t)getpid()), (unsigned)h->un.echo.id,
                  "%u");
    ASSERT_EQ_FMT(0u, (unsigned)h->un.echo.sequence, "%u");
    /* must not write past the header */
    ASSERT_EQ_FMT((unsigned)GUARD, (unsigned)buf[HDR], "%u");
    PASS();
}

TEST init_timestamp_type(void) {
    reset_buf();
    ASSERT_EQ(0, init_icmp_packet(buf, HDR + 20, TIMESTAMP));
    struct icmphdr *h = (struct icmphdr *)buf;
    ASSERT_EQ_FMT((unsigned)ICMP_TIMESTAMP, (unsigned)h->type, "%u");
    PASS();
}

/* ------------------------------------------------------------------ */
/* set_icmp_timeval                                                   */
/* ------------------------------------------------------------------ */

TEST timeval_len_too_small(void) {
    reset_buf();
    ASSERT_EQ(-1, set_icmp_timeval(buf, TV - 1));
    ASSERT(all_bytes_equal(buf, sizeof buf, GUARD));
    PASS();
}

TEST timeval_writes_current_time(void) {
    struct timeval before, after;
    reset_buf();

    gettimeofday(&before, NULL);
    ASSERT_EQ(0, set_icmp_timeval(buf, TV));
    gettimeofday(&after, NULL);

    ASSERT(timeval_between(buf, &before, &after));
    /* only sizeof(struct timeval) bytes may be touched */
    ASSERT(all_bytes_equal(buf + TV, 16, GUARD));
    PASS();
}

/* ------------------------------------------------------------------ */
/* set_icmp_payload                                                   */
/* ------------------------------------------------------------------ */

TEST payload_null_packet(void) {
    ASSERT_EQ(-1, set_icmp_payload(NULL, 32, 32, NULL, 0));
    PASS();
}

TEST payload_larger_than_buffer(void) {
    reset_buf();
    ASSERT_EQ(-1, set_icmp_payload(buf, 8, 9, NULL, 0));
    PASS();
}

TEST payload_default_pattern(void) {
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 32, 32, NULL, 0));
    ASSERT_MEM_EQ("0123456789abcdef0123456789abcdef", buf, 32);
    PASS();
}

TEST payload_custom_pattern_truncated_last_copy(void) {
    const uint8_t pat[] = {'a', 'b', 'c'};
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 8, 8, pat, sizeof pat));
    ASSERT_MEM_EQ("abcabcab", buf, 8);
    PASS();
}

TEST payload_pattern_longer_than_payload(void) {
    const uint8_t pat[] = {'x', 'y', 'z', 'w'};
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 2, 2, pat, sizeof pat));
    ASSERT_MEM_EQ("xy", buf, 2);
    PASS();
}

TEST payload_empty_pattern_uses_fallback_char(void) {
    const uint8_t pat[] = {'a'};
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 10, 10, pat, 0));
    ASSERT(all_bytes_equal(buf, 10, DEFAULT_EMPTY_PATTERN));
    PASS();
}

/* Buffer bigger than the requested payload: only payload_len bytes may be
 * written, whatever the pattern kind. */
TEST payload_does_not_overrun_payload_len_pattern(void) {
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 64, 10, NULL, 0));
    ASSERT_MEM_EQ("0123456789", buf, 10);
    ASSERT(all_bytes_equal(buf + 10, 64 - 10, GUARD));
    PASS();
}

TEST payload_does_not_overrun_payload_len_fallback(void) {
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 64, 10, (const uint8_t *)"a", 0));
    ASSERT(all_bytes_equal(buf, 10, DEFAULT_EMPTY_PATTERN));
    ASSERT(all_bytes_equal(buf + 10, 64 - 10, GUARD));
    PASS();
}

TEST payload_zero_len_writes_nothing(void) {
    reset_buf();
    ASSERT_EQ(0, set_icmp_payload(buf, 16, 0, NULL, 0));
    ASSERT(all_bytes_equal(buf, sizeof buf, GUARD));
    PASS();
}

/* ------------------------------------------------------------------ */
/* set_icmp_data                                                      */
/* ------------------------------------------------------------------ */

TEST data_null_packet(void) {
    ASSERT_EQ(-1, set_icmp_data(NULL, 64, 56, NULL, 0));
    PASS();
}

TEST data_buffer_too_small(void) {
    reset_buf();
    ASSERT_EQ(-1, set_icmp_data(buf, HDR + 55, 56, NULL, 0));
    ASSERT_EQ(-1, set_icmp_data(buf, HDR - 1, 0, NULL, 0));
    PASS();
}

TEST data_small_payload_has_no_timestamp(void) {
    /* payload < sizeof(struct timeval): only pattern, no timestamp */
    const size_t payload = TV - 4;
    reset_buf();
    init_icmp_packet(buf, HDR + payload, ECHO);
    ASSERT_EQ(0, set_icmp_data(buf, HDR + payload, payload, NULL, 0));
    ASSERT_MEM_EQ("0123456789ab", buf + HDR, payload);
    PASS();
}

TEST data_standard_ping_payload_layout(void) {
    /* classic ping: 56 bytes = timeval + (56 - sizeof(timeval)) pattern */
    const size_t payload = 56;
    const size_t total = HDR + payload;
    struct timeval before, after;
    reset_buf();
    init_icmp_packet(buf, total, ECHO);

    gettimeofday(&before, NULL);
    ASSERT_EQ(0, set_icmp_data(buf, total, payload, NULL, 0));
    gettimeofday(&after, NULL);

    ASSERT(timeval_between(buf + HDR, &before, &after));
    ASSERT_MEM_EQ("0123456789abcdef0123456789abcdef0123456789abcdef",
                  buf + HDR + TV, payload - TV);
    PASS();
}

TEST data_custom_pattern_after_timeval(void) {
    const uint8_t pat[] = {0xde, 0xad};
    const size_t payload = TV + 5;
    const size_t total = HDR + payload;
    reset_buf();
    init_icmp_packet(buf, total, ECHO);
    ASSERT_EQ(0, set_icmp_data(buf, total, payload, pat, sizeof pat));
    ASSERT_MEM_EQ("\xde\xad\xde\xad\xde", buf + HDR + TV, 5);
    PASS();
}

TEST data_checksum_is_stored_and_valid(void) {
    const size_t payload = 56;
    const size_t total = HDR + payload;
    reset_buf();
    init_icmp_packet(buf, total, ECHO);
    ASSERT_EQ(0, set_icmp_data(buf, total, payload, NULL, 0));

    struct icmphdr *h = (struct icmphdr *)buf;
    ASSERT(h->checksum != 0);
    ASSERT(checksum_is_valid(buf, total));
    PASS();
}

TEST data_checksum_header_only(void) {
    reset_buf();
    init_icmp_packet(buf, HDR, ECHO);
    ASSERT_EQ(0, set_icmp_data(buf, HDR, 0, NULL, 0));
    ASSERT(checksum_is_valid(buf, HDR));
    PASS();
}

TEST data_does_not_touch_bytes_after_payload(void) {
    const size_t payload = 24;
    const size_t total = HDR + payload;
    reset_buf();
    init_icmp_packet(buf, total + 32, ECHO); /* buffer bigger than packet */
    ASSERT_EQ(0, set_icmp_data(buf, total + 32, payload, NULL, 0));
    ASSERT(all_bytes_equal(buf + total, 32, GUARD));
    PASS();
}

/* ------------------------------------------------------------------ */
/* change_icmp_timeval                                                */
/* ------------------------------------------------------------------ */

TEST change_tv_null_packet(void) {
    ASSERT_EQ(-1, change_icmp_timeval(NULL, 64, 56));
    PASS();
}

TEST change_tv_small_payload_is_noop(void) {
    uint8_t copy[HDR + 4];
    reset_buf();
    init_icmp_packet(buf, sizeof copy, ECHO);
    memcpy(copy, buf, sizeof copy);

    ASSERT_EQ(0, change_icmp_timeval(buf, sizeof copy, 4));
    ASSERT_MEM_EQ(copy, buf, sizeof copy);
    PASS();
}

TEST change_tv_updates_time_and_checksum(void) {
    const size_t payload = 56;
    const size_t total = HDR + payload;
    struct timeval before, after;
    reset_buf();
    init_icmp_packet(buf, total, ECHO);
    set_icmp_data(buf, total, payload, NULL, 0);

    /* force an obviously stale timestamp */
    memset(buf + HDR, 0, TV);

    gettimeofday(&before, NULL);
    ASSERT_EQ(0, change_icmp_timeval(buf, total, payload));
    gettimeofday(&after, NULL);

    ASSERT(timeval_between(buf + HDR, &before, &after));
    ASSERT(checksum_is_valid(buf, total));
    PASS();
}

/* ------------------------------------------------------------------ */
/* change_icmp_sequence                                               */
/* ------------------------------------------------------------------ */

TEST change_seq_null_or_too_small(void) {
    ASSERT_EQ(-1, change_icmp_sequence(NULL, 64, 1));
    reset_buf();
    ASSERT_EQ(-1, change_icmp_sequence(buf, HDR - 1, 1));
    PASS();
}

TEST change_seq_sets_field(void) {
    reset_buf();
    init_icmp_packet(buf, HDR, ECHO);
    ASSERT_EQ(0, change_icmp_sequence(buf, HDR, 0x1234));
    struct icmphdr *h = (struct icmphdr *)buf;
    ASSERT_EQ_FMT(0x1234u, (unsigned)h->un.echo.sequence, "%u");
    PASS();
}

TEST change_seq_updates_checksum(void) {
    const size_t payload = 56;
    const size_t total = HDR + payload;
    reset_buf();
    init_icmp_packet(buf, total, ECHO);
    set_icmp_data(buf, total, payload, NULL, 0);

    ASSERT_EQ(0, change_icmp_sequence(buf, total, 7));
    ASSERT(checksum_is_valid(buf, total));

    ASSERT_EQ(0, change_icmp_sequence(buf, total, 8));
    ASSERT(checksum_is_valid(buf, total));
    PASS();
}

/* ------------------------------------------------------------------ */
/* checksum (RFC 1071)                                                */
/* ------------------------------------------------------------------ */

TEST checksum_rfc1071_example(void) {
    /* RFC 1071 section 3: sum = 0xddf2 -> checksum = 0x220d (network order) */
    uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t c = checksum(data, sizeof data);
    ASSERT_MEM_EQ("\x22\x0d", &c, 2);
    PASS();
}

TEST checksum_odd_length(void) {
    /* odd trailing byte is padded with a zero byte */
    uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6};
    uint16_t c = checksum(data, sizeof data);
    ASSERT_MEM_EQ("\x23\x04", &c, 2);
    PASS();
}

TEST checksum_empty_input(void) {
    uint8_t data[1] = {0};
    ASSERT_EQ_FMT(0xffffu, (unsigned)checksum(data, 0), "%u");
    PASS();
}

TEST checksum_carry_folding(void) {
    /* 0xffff + 0xffff + 0x0001 needs two folds */
    uint8_t data[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x01};
    uint16_t c = checksum(data, sizeof data);
    ASSERT_MEM_EQ("\xff\xfe", &c, 2);
    PASS();
}

TEST checksum_verifies_to_zero_once_inserted(void) {
    uint8_t data[] = {0x08, 0x00, 0x00, 0x00, 0x12, 0x34,
                      0x00, 0x01, 'p',  'i',  'n',  'g'};
    uint16_t c = checksum(data, sizeof data);
    memcpy(data + 2, &c, sizeof c); /* checksum field at offset 2 */
    ASSERT_EQ_FMT(0u, (unsigned)checksum(data, sizeof data), "%u");
    PASS();
}

SUITE(icmp_suite) {
    RUN_TEST(init_null_packet);
    RUN_TEST(init_buffer_too_small);
    RUN_TEST(init_echo_fields);
    RUN_TEST(init_timestamp_type);

    RUN_TEST(timeval_len_too_small);
    RUN_TEST(timeval_writes_current_time);

    RUN_TEST(change_tv_null_packet);
    RUN_TEST(change_tv_small_payload_is_noop);
    RUN_TEST(change_tv_updates_time_and_checksum);

    RUN_TEST(payload_null_packet);
    RUN_TEST(payload_larger_than_buffer);
    RUN_TEST(payload_default_pattern);
    RUN_TEST(payload_custom_pattern_truncated_last_copy);
    RUN_TEST(payload_pattern_longer_than_payload);
    RUN_TEST(payload_empty_pattern_uses_fallback_char);
    RUN_TEST(payload_does_not_overrun_payload_len_pattern);
    RUN_TEST(payload_does_not_overrun_payload_len_fallback);
    RUN_TEST(payload_zero_len_writes_nothing);

    RUN_TEST(data_null_packet);
    RUN_TEST(data_buffer_too_small);
    RUN_TEST(data_small_payload_has_no_timestamp);
    RUN_TEST(data_standard_ping_payload_layout);
    RUN_TEST(data_custom_pattern_after_timeval);
    RUN_TEST(data_checksum_is_stored_and_valid);
    RUN_TEST(data_checksum_header_only);
    RUN_TEST(data_does_not_touch_bytes_after_payload);

    RUN_TEST(change_seq_null_or_too_small);
    RUN_TEST(change_seq_sets_field);
    RUN_TEST(change_seq_updates_checksum);

    RUN_TEST(checksum_rfc1071_example);
    RUN_TEST(checksum_odd_length);
    RUN_TEST(checksum_empty_input);
    RUN_TEST(checksum_carry_folding);
    RUN_TEST(checksum_verifies_to_zero_once_inserted);
}
