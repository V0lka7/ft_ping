#include "greatest.h"

// Define suite here
// SUITE(test_suite_name)
SUITE(test_init);
SUITE(init_suite);
SUITE(timeval_suite);
SUITE(payload_suite);
SUITE(data_suite);
SUITE(change_timeval_suite);
SUITE(change_sequence_suite);
SUITE(checksum_suite);

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN(); /*	command line initialization. */

    RUN_SUITE(test_init);
    GREATEST_MAIN_END(); /* display result */
}
