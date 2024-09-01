#include <rte_errno.h>

int const rte_get_errno() {
    return rte_errno;
}