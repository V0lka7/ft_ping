#include "ft_ping.h"
#include "greatest.h"
#include "initialization/arguments_parser.h"

#include <argp.h>
#include <strings.h>
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

    bzero(&(s_ping->_packet_settings._pattern), PATTERN_SIZE);

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

/* ------------------------------------------------------------------ */
/* Defaults / unknown options / missing operands                       */
/* ------------------------------------------------------------------ */

TEST test_defaults_untouched(void) {
    char *argv[] = {"ft_ping", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(DEFAULT_VERBOSE, s_ping->_settings._verbose);
    ASSERT_EQ(DEFAULT_QUIET, s_ping->_settings._quiet);
    ASSERT_EQ(DEFAULT_ROUTE, s_ping->_settings._route);
    ASSERT_EQ(DEFAULT_INTERVAL, s_ping->_settings._interval);
    ASSERT_EQ(DEFAULT_COUNT, s_ping->_settings._count);
    ASSERT_EQ(DEFAULT_TOS, s_ping->_packet_settings._tos);
    ASSERT_EQ(DEFAULT_TTL, s_ping->_packet_settings._ttl);
    ASSERT_EQ(DEFAULT_ROUTE, s_ping->_packet_settings._route);
    ASSERT_EQ(ECHO, s_ping->_packet_settings._icmp_type);
    ASSERT_EQ(DEFAULT_PAYLOAD_SIZE, s_ping->_packet_settings._payload_size);
    ASSERT_EQ(DEFAULT_LINGER, s_ping->_socket_settings._linger);
    ASSERT_EQ(DEFAULT_TIMEOUT, s_ping->_socket_settings._timeout);
    PASS();
}

TEST test_unknown_long_option(void) {
    char *argv[] = {"ft_ping", "--unknown", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_unknown_short_option(void) {
    char *argv[] = {"ft_ping", "-z", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_missing_host_no_args(void) {
    char *argv[] = {"ft_ping", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_missing_host_only_options(void) {
    char *argv[] = {"ft_ping", "-v", "-c", "3", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_option_missing_argument_1(void) {
    char *argv[] = {"ft_ping", "test.com", "-c", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_option_missing_argument_2(void) {
    char *argv[] = {"ft_ping", "test.com", "--ttl", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

/* ------------------------------------------------------------------ */
/* Targets                                                             */
/* ------------------------------------------------------------------ */

TEST test_target_single(void) {
    char *argv[] = {"ft_ping", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT(s_ping->_targets != NULL);
    ASSERT_STR_EQ("test.com", s_ping->_targets->target_name);
    ASSERT(s_ping->_targets->next == NULL);
    PASS();
}

TEST test_target_multiple(void) {
    char *argv[] = {"ft_ping", "a.com", "b.com", "c.com", NULL};
    int argc = tab_len(argv);
    const char *expected[] = {"a.com", "b.com", "c.com"};
    TARGET *node;

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    node = s_ping->_targets;
    for (int i = 0; i < 3; i++) {
        ASSERT(node != NULL);
        ASSERT_STR_EQ(expected[i], node->target_name);
        node = node->next;
    }
    ASSERT(node == NULL);
    PASS();
}

TEST test_target_option_after_host(void) {
    char *argv[] = {"ft_ping", "test.com", "-v", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._verbose);
    ASSERT(s_ping->_targets != NULL);
    ASSERT_STR_EQ("test.com", s_ping->_targets->target_name);
    ASSERT(s_ping->_targets->next == NULL);
    PASS();
}

TEST test_target_name_truncated(void) {
    char long_host[NI_MAXHOST + 50];

    memset(long_host, 'a', sizeof(long_host) - 1);
    long_host[sizeof(long_host) - 1] = '\0';

    char *argv[] = {"ft_ping", long_host, NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT(s_ping->_targets != NULL);
    ASSERT_EQ((size_t)(NI_MAXHOST - 1), strlen(s_ping->_targets->target_name));
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test type                                                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Test count                                                         */
/* ------------------------------------------------------------------ */

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

TEST test_count_valid_number_3(void) {
    char *argv[] = {"ft_ping", "-c", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ((ssize_t)strtoul("-20", NULL, 10), s_ping->_settings._count);
    PASS();
}

TEST test_count_valid_short_positive(void) {
    char *argv[] = {"ft_ping", "-c", "5", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(5, s_ping->_settings._count);
    PASS();
}

TEST test_count_valid_zero(void) {
    char *argv[] = {"ft_ping", "--count", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(0, s_ping->_settings._count);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test interval                                                      */
/* ------------------------------------------------------------------ */

TEST test_interval_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--interval", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_interval_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--interval", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_interval_not_a_number_2(void) {
    char *argv[] = {"ft_ping", "--interval", "--2", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_interval_not_a_number_3(void) {
    char *argv[] = {"ft_ping", "--interval", "-20d", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_interval_valid_number_1(void) {
    char *argv[] = {"ft_ping", "--interval", "20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(20, s_ping->_settings._interval);
    PASS();
}

TEST test_interval_valid_number_2(void) {
    char *argv[] = {"ft_ping", "--interval", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ((ssize_t)strtoul("-20", NULL, 10), s_ping->_settings._interval);
    PASS();
}

TEST test_interval_valid_number_3(void) {
    char *argv[] = {"ft_ping", "-i", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ((ssize_t)strtoul("-20", NULL, 10), s_ping->_settings._interval);
    PASS();
}

TEST test_interval_valid_short_positive(void) {
    char *argv[] = {"ft_ping", "-i", "3", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(3, s_ping->_settings._interval);
    PASS();
}

TEST test_interval_valid_zero(void) {
    char *argv[] = {"ft_ping", "--interval", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(0, s_ping->_settings._interval);
    PASS();
}

/* ------------------------------------------------------------------ */
/* TTL                                                                */
/* ------------------------------------------------------------------ */

TEST test_ttl_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--ttl", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_ttl_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--ttl", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_ttl_not_a_number_2(void) {
    char *argv[] = {"ft_ping", "--ttl", "20d", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_ttl_overflow_1(void) {
    char *argv[] = {"ft_ping", "--ttl", "256", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_ttl_overflow_2(void) {
    char *argv[] = {"ft_ping", "--ttl", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_ttl_valid_1(void) {
    char *argv[] = {"ft_ping", "--ttl", "20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(20, s_ping->_packet_settings._ttl);
    PASS();
}

TEST test_ttl_valid_2(void) {
    char *argv[] = {"ft_ping", "--ttl", "255", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(255, s_ping->_packet_settings._ttl);
    PASS();
}

TEST test_ttl_valid_3(void) {
    char *argv[] = {"ft_ping", "--ttl", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(0, s_ping->_packet_settings._ttl);
    PASS();
}

/* ------------------------------------------------------------------ */
/* TOS                                                                */
/* ------------------------------------------------------------------ */

TEST test_tos_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--tos", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--tos", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_overflow_1(void) {
    char *argv[] = {"ft_ping", "--tos", "256", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_overflow_2(void) {
    char *argv[] = {"ft_ping", "--tos", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_valid_1(void) {
    char *argv[] = {"ft_ping", "--tos", "20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_valid_2(void) {
    char *argv[] = {"ft_ping", "--tos", "2", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_valid_3(void) {
    char *argv[] = {"ft_ping", "--tos", "255", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_tos_valid_4(void) {
    char *argv[] = {"ft_ping", "-T", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

/* ------------------------------------------------------------------ */
/* Verbose                                                             */
/* ------------------------------------------------------------------ */

TEST test_verbose_short(void) {
    char *argv[] = {"ft_ping", "-v", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._verbose);
    PASS();
}

TEST test_verbose_long(void) {
    char *argv[] = {"ft_ping", "--verbose", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._verbose);
    PASS();
}

TEST test_verbose_long_mispelled_but_ok(void) {
    char *argv[] = {"ft_ping", "--verb", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._verbose);
    PASS();
}

TEST test_verbose_mispelled_2(void) {
    char *argv[] = {"ft_ping", "--verbosee", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_verbose_with_arg_rejected(void) {
    char *argv[] = {"ft_ping", "--verbose=1", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

/* ------------------------------------------------------------------ */
/* Timeout (-w)                                                        */
/* ------------------------------------------------------------------ */

TEST test_timeout_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--timeout", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timeout_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--timeout", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timeout_not_a_number_2(void) {
    char *argv[] = {"ft_ping", "-w", "10s", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timeout_overflow_1(void) {
    char *argv[] = {"ft_ping", "--timeout", "2147483648", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timeout_overflow_2(void) {
    char *argv[] = {"ft_ping", "--timeout", "-1", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_timeout_valid_1(void) {
    char *argv[] = {"ft_ping", "--timeout", "10", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(10, s_ping->_socket_settings._timeout);
    PASS();
}

TEST test_timeout_valid_2(void) {
    char *argv[] = {"ft_ping", "-w", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(0, s_ping->_socket_settings._timeout);
    PASS();
}

TEST test_timeout_valid_int_max(void) {
    char *argv[] = {"ft_ping", "-w", "2147483647", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(INT_MAX, s_ping->_socket_settings._timeout);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Linger (-W)                                                         */
/* ------------------------------------------------------------------ */

TEST test_linger_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--linger", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_linger_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--linger", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_linger_not_a_number_2(void) {
    char *argv[] = {"ft_ping", "-W", "10s", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_linger_overflow_1(void) {
    char *argv[] = {"ft_ping", "--linger", "2147483648", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_linger_overflow_2(void) {
    char *argv[] = {"ft_ping", "--linger", "-1", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_linger_valid_1(void) {
    char *argv[] = {"ft_ping", "--linger", "10", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(10, s_ping->_socket_settings._linger);
    PASS();
}

TEST test_linger_valid_2(void) {
    char *argv[] = {"ft_ping", "-W", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(0, s_ping->_socket_settings._linger);
    PASS();
}

TEST test_linger_valid_int_max(void) {
    char *argv[] = {"ft_ping", "-W", "2147483647", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(INT_MAX, s_ping->_socket_settings._linger);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Quiet                                                               */
/* ------------------------------------------------------------------ */

TEST test_quiet_short(void) {
    char *argv[] = {"ft_ping", "-q", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._quiet);
    PASS();
}

TEST test_quiet_long(void) {
    char *argv[] = {"ft_ping", "--quiet", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._quiet);
    PASS();
}

TEST test_quiet_long_mispelled_but_ok(void) {
    char *argv[] = {"ft_ping", "--qui", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._quiet);
    PASS();
}

TEST test_quiet_mispelled_2(void) {
    char *argv[] = {"ft_ping", "--quietly", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

/* ------------------------------------------------------------------ */
/* Route                                                               */
/* ------------------------------------------------------------------ */

TEST test_route_short(void) {
    char *argv[] = {"ft_ping", "-R", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._route);
    ASSERT_EQ(true, s_ping->_packet_settings._route);
    PASS();
}

TEST test_route_long(void) {
    char *argv[] = {"ft_ping", "--route", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(true, s_ping->_settings._route);
    ASSERT_EQ(true, s_ping->_packet_settings._route);
    PASS();
}

TEST test_route_mispelled_2(void) {
    char *argv[] = {"ft_ping", "--routee", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

/* ------------------------------------------------------------------ */
/* Size                                                                */
/* ------------------------------------------------------------------ */

TEST test_size_complete_cmd_empty(void) {
    char *argv[] = {"ft_ping", "--size", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_size_not_a_number_1(void) {
    char *argv[] = {"ft_ping", "--size", "jfnsjfn", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_size_not_a_number_2(void) {
    char *argv[] = {"ft_ping", "-s", "56d", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_size_overflow_1(void) {
    char *argv[] = {"ft_ping", "--size", "65400", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_size_overflow_2(void) {
    char *argv[] = {"ft_ping", "--size", "-20", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_size_valid_1(void) {
    char *argv[] = {"ft_ping", "--size", "100", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(100, s_ping->_packet_settings._payload_size);
    PASS();
}

TEST test_size_valid_2(void) {
    char *argv[] = {"ft_ping", "-s", "0", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(0, s_ping->_packet_settings._payload_size);
    PASS();
}

TEST test_size_valid_max(void) {
    char *argv[] = {"ft_ping", "-s", "65399", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(MAX_PAYLOAD_SIZE, s_ping->_packet_settings._payload_size);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Pattern                                                             */
/* ------------------------------------------------------------------ */

TEST test_pattern_empty(void) {
    char *argv[] = {"ft_ping", "--pattern", "", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ('0', s_ping->_packet_settings._pattern[0]);
    ASSERT_EQ('0', s_ping->_packet_settings._pattern[PATTERN_SIZE - 2]);
    PASS();
}

TEST test_pattern_not_hex_1(void) {
    char *argv[] = {"ft_ping", "--pattern", "xyz", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_pattern_not_hex_2(void) {
    char *argv[] = {"ft_ping", "-p", "12g4", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_pattern_not_hex_3(void) {
    char *argv[] = {"ft_ping", "-p", "0x1f", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

TEST test_pattern_valid_digits(void) {
    char *argv[] = {"ft_ping", "--pattern", "0123", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_STR_EQ("0123", (char *)s_ping->_packet_settings._pattern);
    PASS();
}

TEST test_pattern_valid_lowercase(void) {
    char *argv[] = {"ft_ping", "-p", "abcdef", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_STR_EQ("abcdef", (char *)s_ping->_packet_settings._pattern);
    PASS();
}

TEST test_pattern_valid_uppercase_is_lowered(void) {
    char *argv[] = {"ft_ping", "-p", "ABCDEF", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_STR_EQ("abcdef", (char *)s_ping->_packet_settings._pattern);
    PASS();
}

TEST test_pattern_valid_mixed_case(void) {
    char *argv[] = {"ft_ping", "-p", "aB1cD2", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_STR_EQ("ab1cd2", (char *)s_ping->_packet_settings._pattern);
    PASS();
}

TEST test_pattern_too_long_is_truncated(void) {
    char *argv[] = {"ft_ping", "-p", "0123456789ABCDEF0123", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_STRN_EQ("0123456789abcdef",
                   (char *)s_ping->_packet_settings._pattern, PATTERN_SIZE);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Combined options                                                    */
/* ------------------------------------------------------------------ */

TEST test_combined_options_valid(void) {
    char *argv[] = {"ft_ping", "-c", "3",           "-i",       "2",  "-s",
                    "100",     "-v", "-q",          "--ttl",    "42", "-T",
                    "8",       "-w", "30",          "-W",       "5",  "-R",
                    "-p",      "ff", "--timestamp", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_EQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    ASSERT_EQ(3, s_ping->_settings._count);
    ASSERT_EQ(2, s_ping->_settings._interval);
    ASSERT_EQ(100, s_ping->_packet_settings._payload_size);
    ASSERT_EQ(true, s_ping->_settings._verbose);
    ASSERT_EQ(true, s_ping->_settings._quiet);
    ASSERT_EQ(42, s_ping->_packet_settings._ttl);
    ASSERT_EQ(8, s_ping->_packet_settings._tos);
    ASSERT_EQ(30, s_ping->_socket_settings._timeout);
    ASSERT_EQ(5, s_ping->_socket_settings._linger);
    ASSERT_EQ(true, s_ping->_settings._route);
    ASSERT_EQ(true, s_ping->_packet_settings._route);
    ASSERT_STR_EQ("ff", (char *)s_ping->_packet_settings._pattern);
    ASSERT_EQ(TIMESTAMP, s_ping->_packet_settings._icmp_type);
    ASSERT(s_ping->_targets != NULL);
    ASSERT_STR_EQ("test.com", s_ping->_targets->target_name);
    PASS();
}

TEST test_combined_options_one_invalid(void) {
    char *argv[] = {"ft_ping", "-v", "--ttl", "999", "-q", "test.com", NULL};
    int argc = tab_len(argv);

    ASSERT_NEQ(0, argp_parse(&g_argp, argc, argv, ARGP_NO_EXIT, 0, s_ping));
    PASS();
}

SUITE(test_init) {
    SET_SETUP(setup, NULL);
    SET_TEARDOWN(teardown, NULL);

    RUN_TEST(test_defaults_untouched);
    RUN_TEST(test_unknown_long_option);
    RUN_TEST(test_unknown_short_option);
    RUN_TEST(test_missing_host_no_args);
    RUN_TEST(test_missing_host_only_options);
    RUN_TEST(test_option_missing_argument_1);
    RUN_TEST(test_option_missing_argument_2);

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
    RUN_TEST(test_count_valid_number_3);
    RUN_TEST(test_count_valid_short_positive);
    RUN_TEST(test_count_valid_zero);

    // interval tests
    RUN_TEST(test_interval_complete_cmd_empty);
    RUN_TEST(test_interval_not_a_number_1);
    RUN_TEST(test_interval_not_a_number_2);
    RUN_TEST(test_interval_not_a_number_3);
    RUN_TEST(test_interval_valid_number_1);
    RUN_TEST(test_interval_valid_number_2);
    RUN_TEST(test_interval_valid_number_3);
    RUN_TEST(test_interval_valid_short_positive);
    RUN_TEST(test_interval_valid_zero);

    // tos tests
    RUN_TEST(test_tos_complete_cmd_empty);
    RUN_TEST(test_tos_not_a_number_1);
    RUN_TEST(test_tos_overflow_1);
    RUN_TEST(test_tos_overflow_2);
    RUN_TEST(test_tos_valid_1);
    RUN_TEST(test_tos_valid_2);
    RUN_TEST(test_tos_valid_3);
    RUN_TEST(test_tos_valid_4);

    // ttl tests
    RUN_TEST(test_ttl_complete_cmd_empty);
    RUN_TEST(test_ttl_not_a_number_1);
    RUN_TEST(test_ttl_not_a_number_2);
    RUN_TEST(test_ttl_overflow_1);
    RUN_TEST(test_ttl_overflow_2);
    RUN_TEST(test_ttl_valid_1);
    RUN_TEST(test_ttl_valid_2);
    RUN_TEST(test_ttl_valid_3);

    // verbose tests
    RUN_TEST(test_verbose_short);
    RUN_TEST(test_verbose_long);
    RUN_TEST(test_verbose_long_mispelled_but_ok);
    RUN_TEST(test_verbose_mispelled_2);
    RUN_TEST(test_verbose_with_arg_rejected);

    // timeout tests
    RUN_TEST(test_timeout_complete_cmd_empty);
    RUN_TEST(test_timeout_not_a_number_1);
    RUN_TEST(test_timeout_not_a_number_2);
    RUN_TEST(test_timeout_overflow_1);
    RUN_TEST(test_timeout_overflow_2);
    RUN_TEST(test_timeout_valid_1);
    RUN_TEST(test_timeout_valid_2);
    RUN_TEST(test_timeout_valid_int_max);

    // linger tests
    RUN_TEST(test_linger_complete_cmd_empty);
    RUN_TEST(test_linger_not_a_number_1);
    RUN_TEST(test_linger_not_a_number_2);
    RUN_TEST(test_linger_overflow_1);
    RUN_TEST(test_linger_overflow_2);
    RUN_TEST(test_linger_valid_1);
    RUN_TEST(test_linger_valid_2);
    RUN_TEST(test_linger_valid_int_max);

    // quiet tests
    RUN_TEST(test_quiet_short);
    RUN_TEST(test_quiet_long);
    RUN_TEST(test_quiet_long_mispelled_but_ok);
    RUN_TEST(test_quiet_mispelled_2);

    // route tests
    RUN_TEST(test_route_short);
    RUN_TEST(test_route_long);
    RUN_TEST(test_route_mispelled_2);

    // size tests
    RUN_TEST(test_size_complete_cmd_empty);
    RUN_TEST(test_size_not_a_number_1);
    RUN_TEST(test_size_not_a_number_2);
    RUN_TEST(test_size_overflow_1);
    RUN_TEST(test_size_overflow_2);
    RUN_TEST(test_size_valid_1);
    RUN_TEST(test_size_valid_2);
    RUN_TEST(test_size_valid_max);

    // pattern tests
    RUN_TEST(test_pattern_empty);
    RUN_TEST(test_pattern_not_hex_1);
    RUN_TEST(test_pattern_not_hex_2);
    RUN_TEST(test_pattern_not_hex_3);
    RUN_TEST(test_pattern_valid_digits);
    RUN_TEST(test_pattern_valid_lowercase);
    RUN_TEST(test_pattern_valid_uppercase_is_lowered);
    RUN_TEST(test_pattern_valid_mixed_case);
    RUN_TEST(test_pattern_too_long_is_truncated);

    // combined tests
    RUN_TEST(test_combined_options_valid);
    RUN_TEST(test_combined_options_one_invalid);
}
