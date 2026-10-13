#include "ft_ping.h"
#include "greatest.h"
#include "initialization/arguments_parser.h"

#include <argp.h>
#include <signal.h>
#include <sys/types.h>

static FT_PING *s_ping = NULL;

static void setup(void *data) {
    (void)data;
    s_ping = malloc(sizeof(FT_PING));

    s_ping->_settings._verbose = DEFAULT_VERBOSE;
    s_ping->_settings._quiet = DEFAULT_QUIET;
    s_ping->_settings._route = DEFAULT_ROUTE;
    s_ping->_settings._interval = DEFAULT_INTERVAL;
    s_ping->_settings._count = DEFAULT_COUNT;

    s_ping->_packet_settings._tos = DEFAULT_TOS;
    s_ping->_packet_settings._ttl = DEFAULT_TTL;
    s_ping->_packet_settings._route = DEFAULT_ROUTE;
    s_ping->_packet_settings._icmp_type = DEFAULT_TYPE;
    s_ping->_packet_settings._payload_size = DEFAULT_PAYLOAD_SIZE;

    s_ping->_socket_settings._root = DEFAULT_ROOT;
    s_ping->_socket_settings._linger = DEFAULT_LINGER;
    s_ping->_socket_settings._timeout = DEFAULT_TIMEOUT;

    s_ping->_targets = NULL;
}

static void teardown(void *data) {
    (void)data;
    clear_targets(s_ping->_targets);
    free(s_ping);
}

static int tab_len(char **tab) {
    int i = 0;

    while (tab[i])
        i++;
    return i;
}

TEST test_echo_mispelled_but_ok(void) {
    char *argv[] = {"ft_ping", "--ech", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_echo_mispelled_2(void) {
    char *argv[] = {"ft_ping", "--echoo", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_echo_type(void) {
    char *argv[] = {"ft_ping", "--echo", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(ECHO, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_timestamp_mispelled_but_ok(void) {
    char *argv[] = {"ft_ping", "--timesta", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timestamp_mispelled_2(void) {
    char *argv[] = {"ft_ping", "--timestampp", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timestamp_type(void) {
    char *argv[] = {"ft_ping", "--timestamp", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(TIMESTAMP, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_multiple_type_cmd_1(void) {
    char *argv[] = {"ft_ping", "--timestamp", "--echo", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(ECHO, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_multiple_type_cmd_2(void) {
    char *argv[] = {"ft_ping",     "--timestamp", "--echo",
                    "--timestamp", "test.com",    NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(TIMESTAMP, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_type_arg_unhandled(void) {
    char *argv[] = {"ft_ping", "-t", "unhandled", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(-1, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_type_arg_empty(void) {
    char *argv[] = {"ft_ping", "-t", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_type_arg_echo(void) {
    char *argv[] = {"ft_ping", "-t", "echo", "test.com", NULL};
    int argc = tab_len(argv);

    int ret = argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping);
    ASSERT_EQ(0, ret);

    // ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(ECHO, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_type_arg_timestamp(void) {
    char *argv[] = {"ft_ping", "-t", "timestamp", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(TIMESTAMP, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_type__multi_args_valid_1(void) {
    char *argv[] = {"ft_ping", "-t",       "timestamp", "-t",
                    "echo",    "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(ECHO, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_type__multi_args_valid_2(void) {
    char *argv[] = {"ft_ping", "-t",        "timestamp", "-t", "echo",
                    "-t",      "timestamp", "test.com",  NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(TIMESTAMP, s_ping->_packet_settings._icmp_type);
    PASS();
}

TEST test_count_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--count", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_count_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--count", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_count_not_a_number_2(void) {
    char *argv[] = {"ft_ping", "--count", "--2", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_count_not_a_number_3(void) {
    char *argv[] = {"ft_ping", "--count", "-20d", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_count_valid_number_1(void) {
    char *argv[] = {"ft_ping", "--count", "20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(20, s_ping->_settings._count);
    PASS();
}

TEST test_count_valid_number_2(void) {
    char *argv[] = {"ft_ping", "--count", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ((ssize_t)strtoul("-20", NULL, 10), s_ping->_settings._count);
    PASS();
}

SUITE(test_init) {
    SET_SETUP(setup, NULL);
    SET_TEARDOWN(teardown, NULL);

    // Type tests
    RUN_TEST(test_echo_type);
    RUN_TEST(test_echo_mispelled_but_ok);
    RUN_TEST(test_echo_mispelled_2);
    RUN_TEST(test_echo_type);
    RUN_TEST(test_timestamp_mispelled_but_ok);
    RUN_TEST(test_timestamp_mispelled_2);
    RUN_TEST(test_timestamp_type);
    RUN_TEST(test_multiple_type_cmd_1);
    RUN_TEST(test_multiple_type_cmd_2);
    RUN_TEST(test_type_arg_unhandled);
    RUN_TEST(test_type_arg_empty);
    RUN_TEST(test_type_arg_echo);
    RUN_TEST(test_type_arg_timestamp);
    RUN_TEST(test_type__multi_args_valid_1);
    RUN_TEST(test_type__multi_args_valid_2);

    // count tests
    RUN_TEST(test_count_complete_cmd_empty);
    RUN_TEST(test_count_not_a_number_1);
    RUN_TEST(test_count_not_a_number_2);
    RUN_TEST(test_count_not_a_number_3);
    RUN_TEST(test_count_valid_number_1);
    RUN_TEST(test_count_valid_number_2);
}
