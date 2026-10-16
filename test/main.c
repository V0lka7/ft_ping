#include "greatest.h"

// Define suite here
// SUITE(test_suite_name)
SUITE(arguments_parser_suite);
SUITE(icmp_suite);

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN(); /*	command line initialization. */

    RUN_SUITE(arguments_parser_suite);
    RUN_SUITE(icmp_suite);
    GREATEST_MAIN_END(); /* display result */
}
