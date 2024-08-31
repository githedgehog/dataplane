#include <rte_errno.h>

int const rte_get_errno(void) {
    return rte_errno;
}