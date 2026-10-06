#include "argp.h"

const char *argp_program_version = "ft_ping 1.0";

const char *argp_program_bug_address = "<jduval@student.42angouleme.fr>";

static struct argp_option options_icmp_control[] = {
    {0, 0, 0, 0, "Options controlling ICMP request types:", 1},
    {"echo", 0, 0, 0, "send ICMP_ECHO packets (default)", 1},
    {"timestamp", 0, 0, 0, "send ICMP_TIMESTAMP packets", 1},
    {"type", 't', "TYPE", 0, "send TYPE packets (echo and timestamp only)", 1},

    {0, 0, 0, 0, "Options valid for all request types:", 2},
    {"count", 'c', "NUMBER", 0, "stop after sending NUMBER packets", 2},
    {"interval", 'i', "NUMBER", 0,
     "wait NUMBER seconds between sending each packet", 2},
    {"ttl", 0, "N", 0, "specify N as time-to-live", 2},
    {"tos", 'T', "NUM", 0, "set type of service (TOS) to N", 2},
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
    {"usage", 0, 0, 0, "give a short usage message", 4},
    {"version", 'v', 0, 0, "print program version", 4},
    {0}};
