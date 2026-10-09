#include <argp.h>
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

static unsigned long parse_number(struct argp_state *state, char *arg, unsigned long max);

static int error = 0;

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
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
            error = EINVAL;
        }
        break;
    }

    case 'c':
        s_ping->_settings._count = (ssize_t)parse_number(state, arg, ULONG_MAX);
        break;
    case 'i':
        s_ping->_settings._interval = (size_t)parse_number(state, arg, ULONG_MAX);
        break;
    case TTL_OPT:
        s_ping->_packet_settings._ttl = (uint8_t)parse_number(state, arg, MAX_TTL);
        break;
    case 'T':
        s_ping->_packet_settings._tos = (uint8_t)parse_number(state, arg, MAX_TOS);
        break;
    case 'v':
        s_ping->_settings._verbose = true;
        break;
    case 'w':
        s_ping->_socket_settings._timeout = (ssize_t)parse_number(state, arg, INT_MAX);
        break;
    case 'W':
        s_ping->_socket_settings._linger = (ssize_t)parse_number(state, arg, INT_MAX);
        break;

    case 'p':
        printf("pattern: %s\n", arg);
        break;
    case 'q':
        s_ping->_settings._quiet = true;
        break;
    case 'R':
        s_ping->_settings._route = true;
        s_ping->_packet_settings._route = true;
        break;
    case 's':
        s_ping->_packet_settings._payload_size = (size_t)parse_number(state, arg, MAX_PAYLOAD_SIZE);
        break;

    case '?':
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
        break;
    case USAGE_OPT:
        argp_state_help(state, stdout, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
        break;

    case ARGP_KEY_ARGS:
        for (int i = state->next; i < state->argc; i++)
            printf("host: %s\n", state->argv[i]);
        break;
    case ARGP_KEY_END:
        if (state->arg_num == 0 && state->next == state->argc) {
            argp_error(state, "missing host operand");
            error = EINVAL;
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return error;
}

struct argp g_argp = {options_icmp_control, parse_opt, "HOST ...", argp_doc};

static unsigned long parse_number(struct argp_state *state, char *arg, unsigned long max) {
    char *end = NULL;
    unsigned long val;

    errno = 0;
    val = strtoul(arg, &end, 10);

    if (end != NULL && *end != '\0') {
        argp_error(state, "invalid value (`%s' near `%s')", arg,
                   end); // exit the program
        error = EINVAL;
    } else if (max != ULONG_MAX && val > max) {
        argp_error(state, "option value too big: %s", arg); // exit the program
        error = EINVAL;
    }
    return val;
}
