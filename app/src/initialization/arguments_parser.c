#include <argp.h>
#include <float.h>
#include <math.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ft_ping.h"

const char *argp_program_version = "ft_ping 1.0";

const char *argp_program_bug_address = "<jduval@student.42angouleme.fr>";

static const char argp_doc[] =
    "Send ICMP ECHO_REQUEST packets to network hosts.";

enum { ECHO_OPT = 128, TIMESTAMP_OPT, TTL_OPT, USAGE_OPT };

static struct argp_option options_icmp_control[] = {
    {0, 0, 0, 0, "Options controlling ICMP request types:", 1},
    {"echo", ECHO_OPT, 0, 0, "send ICMP_ECHO packets (default)", 1},
    {"timestamp", TIMESTAMP_OPT, 0, 0, "send ICMP_TIMESTAMP packets", 1},
    {"type", 't', "TYPE", 0, "send TYPE packets (echo and timestamp only)", 1},

    {0, 0, 0, 0, "Options valid for all request types:", 2},
    {"count", 'c', "NUMBER", 0, "stop after sending NUMBER packets", 2},
    {"interval", 'i', "NUMBER", 0,
     "wait NUMBER seconds between sending each packet", 2},
    {"ttl", TTL_OPT, "N", 0, "specify N as time-to-live", 2},
    {"tos", 'T', "NUM", 0, "set type of service (TOS) to NUM", 2},
    {"verbose", 'v', 0, 0, "verbose output", 2},
    {"timeout", 'w', "N", 0, "stop after N seconds", 2},
    {"linger", 'W', "N", 0, "number of seconds to wait for a response", 2},

    {0, 0, 0, 0, "Options valid for --echo requests:", 3},
    {"pattern", 'p', "PATTERN", 0, "fill ICMP packet with given pattern (hex)",
     3},
    {"quiet", 'q', 0, 0, "quiet output", 3},
    {"route", 'R', 0, 0, "record route", 3},
    {"size", 's', "NUMBER", 0, "send NUMBER data octets", 3},

    {0, 0, 0, 0, "", 3},
    {"help", '?', 0, 0, "give this help list", 4},
    {"usage", USAGE_OPT, 0, 0, "give a short usage message", 4},
    {0}};

static double parse_double(struct argp_state *state, const char *arg,
                           double min, double max);
static unsigned long parse_number(struct argp_state *state, char *arg,
                                  unsigned long max);
static void parse_pattern(FT_PING *s_ping, struct argp_state *state, char *arg);
static int create_target_list(TARGET **head, struct argp_state *state);

static int error;
static int help_activated = 0;

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    error = 0;
    if (help_activated == 1)
        return 0;
    FT_PING *s_ping = (FT_PING *)state->input;

    switch (key) {
    case ECHO_OPT:
        s_ping->_packet_settings._icmp_type = ECHO;
        break;
    case TIMESTAMP_OPT:
        s_ping->_packet_settings._icmp_type = TIMESTAMP;
        break;
    case 't': {
        if (strcmp(arg, "echo") == 0)
            s_ping->_packet_settings._icmp_type = ECHO;
        else if (strcmp(arg, "timestamp") == 0)
            s_ping->_packet_settings._icmp_type = TIMESTAMP;
        else {
            argp_error(state, "Unsupported packet type: %s", arg);
            error = -1;
        }
        break;
    }

    case 'c':
        s_ping->_settings._count = (size_t)parse_number(state, arg, ULONG_MAX);
        break;
    case 'i': {
        double val = parse_double(state, arg, -DBL_MAX, DBL_MAX);

        // root has no limit and negative values are converted to positive
        if (s_ping->_settings._root) {
            val = fabs(val);
        } else if (val <= 0.1) {
            // non-root users cannot set interval lower than 0.1s
            argp_error(state, "option value too small: %s", arg);
            error = -1;
        }

        s_ping->_settings._interval = val;
        break;
    }
    case TTL_OPT:
        s_ping->_packet_settings._ttl =
            (uint8_t)parse_number(state, arg, MAX_TTL);
        break;
    case 'T':
        s_ping->_packet_settings._tos =
            (uint8_t)parse_number(state, arg, MAX_TOS);
        break;
    case 'v':
        s_ping->_settings._verbose = true;
        break;
    case 'w':
        s_ping->_settings._timeout = (ssize_t)parse_number(state, arg, INT_MAX);
        break;
    case 'W':
        s_ping->_settings._linger = (ssize_t)parse_number(state, arg, INT_MAX);
        break;

    case 'p':
        parse_pattern(s_ping, state, arg);
        break;
    case 'q':
        s_ping->_settings._quiet = true;
        break;
    case 'R':
        s_ping->_settings._route = true;
        s_ping->_packet_settings._route = true;
        break;
    case 's':
        s_ping->_packet_settings._payload_size =
            (size_t)parse_number(state, arg, MAX_PAYLOAD_SIZE);
        break;

    case '?':
        help_activated = 1;
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        break;
    case USAGE_OPT:
        help_activated = 1;
        argp_state_help(state, stdout, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
        break;

    case ARGP_KEY_ARGS:
        if (create_target_list(&s_ping->_targets, state) == -1) {
            argp_error(state, "unexpected error");
            error = -1;
        }
        break;
    case ARGP_KEY_END:
        if (state->arg_num == 0 && state->next == state->argc) {
            argp_error(state, "missing host operand");
            error = -1;
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return error;
}

struct argp g_argp = {.options = options_icmp_control,
                      .parser = parse_opt,
                      .args_doc = "HOST ...",
                      .doc = argp_doc};

static unsigned long parse_number(struct argp_state *state, char *arg,
                                  unsigned long max) {
    char *end = NULL;
    unsigned long val;

    errno = 0;
    val = strtoul(arg, &end, 10);

    if (end != NULL && *end != '\0') {
        argp_error(state, "invalid value (`%s' near `%s')", arg,
                   end); // exit the program
        error = -1;
    } else if (max != ULONG_MAX && val > max) {
        argp_error(state, "option value too big: %s", arg); // exit the program
        error = -1;
    }
    return val;
}

static double parse_double(struct argp_state *state, const char *arg,
                           double min, double max) {
    char *end = NULL;
    double val;

    if (arg == NULL || strlen(arg) == 0)
        return 0.0;

    errno = 0;
    val = strtod(arg, &end);

    if (end == arg || *end != '\0') {
        argp_error(state, "invalid value (`%s' near `%s')", arg, end);
        error = -1;
    } else if (errno == ERANGE || !isfinite(val)) { /* rejects nan / inf too */
        argp_error(state, "option value out of range: %s", arg);
        error = -1;
    } else if (val < min) {
        argp_error(state, "option value too small: %s", arg);
        error = -1;
    } else if (val > max) {
        argp_error(state, "option value too big: %s", arg);
        error = -1;
    }

    return val;
}

static void parse_pattern(FT_PING *s_ping, struct argp_state *state,
                          char *arg) {

    char *ptr = (char *)s_ping->_packet_settings._pattern;

    if (strlen(arg) == 0) {
        memset(ptr, '0', PATTERN_SIZE - 1);
        return;
    }

    size_t i = 0;

    while (arg[i]) {
        if (!isxdigit(arg[i])) {
            argp_error(state, "error in pattern near `%s\'", arg + i);
            error = -1;
            return;
        }
        i++;
    }
    size_t arg_len = strlen(arg);
    // to lower all alpha caracters
    i = 0;
    while (i < arg_len && i < PATTERN_SIZE) {
        ptr[i] = (char)tolower(arg[i]);
        i++;
    }
}

static int create_target_list(TARGET **head, struct argp_state *state) {
    TARGET **tmp_head = head;

    for (int i = state->next; i < state->argc; i++) {
        TARGET *node = (TARGET *)calloc(1, sizeof(TARGET));

        if (node == NULL)
            return -1;
        bzero(node->_target_name, NI_MAXHOST);
        bzero(node->_target_ip, INET_ADDRSTRLEN);
        strncpy(node->_target_name, state->argv[i], NI_MAXHOST - 1);
        node->next = NULL;

        *tmp_head = node;
        tmp_head = &node->next;
    }
    return 0;
}
