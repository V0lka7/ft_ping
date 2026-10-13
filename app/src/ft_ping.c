#include "ft_ping.h"

void clear_targets(TARGET *head) {
    TARGET *node;

    while (head) {
        node = head;
        head = head->next;
        free(node);
    }
}
