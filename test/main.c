#include "greatest.h"

// Define suite here
// SUITE(test_suite_name)
SUITE(test_init);

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN(); /*	command line initialization. */

    RUN_SUITE(test_init);
    GREATEST_MAIN_END(); /* display result */
}
