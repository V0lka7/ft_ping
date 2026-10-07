#include <argp.h>
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

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    FT_PING *s_ping = (FT_PING *)state->input;
    (void)s_ping;

    switch (key) {
    case ECHO_OPT:
        printf("echo\n");
        break;
    case TIMESTAMP_OPT:
        printf("timestamp\n");
        break;
    case 't':
        printf("type: %s\n", arg);
        break;

    case 'c':
        printf("count: %s\n", arg);
        break;
    case 'i':
        printf("interval: %s\n", arg);
        break;
    case TTL_OPT:
        printf("ttl: %s\n", arg);
        break;
    case 'T':
        printf("tos: %s\n", arg);
        break;
    case 'v':
        printf("verbose\n");
        break;
    case 'w':
        printf("timeout: %s\n", arg);
        break;
    case 'W':
        printf("linger: %s\n", arg);
        break;

    case 'p':
        printf("pattern: %s\n", arg);
        break;
    case 'q':
        printf("quiet\n");
        break;
    case 'R':
        printf("route\n");
        break;
    case 's':
        printf("size: %s\n", arg);
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
        if (state->arg_num == 0 && state->next == state->argc)
            argp_error(state, "missing host operand");
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp g_argp = {options_icmp_control, parse_opt, "HOST ...", argp_doc};

bool is_root(void) { return geteuid() == 0; }
