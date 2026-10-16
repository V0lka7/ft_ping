#include "utils.h"

/*  Checksum function implemented following this document:
    RFC 1071: Computing the internet checksum
    https://www.rfc-editor.org/info/rfc1071/
*/
uint16_t checksum(void *addr, size_t len) {
    uint16_t *word = addr;
    uint32_t result = 0;
    for (size_t i = 0; i < len / sizeof(uint16_t); i++) {
        result += *(word + i);
    }
    if (len % 2 == 1) {
        result += *((uint8_t *)addr + len - 1);
    }
    result = (result >> 16) + (result & 0xffff);
    // Carry the previous add.
    result = (result >> 16) + (result & 0xffff);
    return ~result;
}
