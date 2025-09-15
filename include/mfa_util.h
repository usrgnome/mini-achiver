#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>  /* for size_t */

unsigned char *load_file(const char *path, size_t *out_len);

#endif /* UTIL_H */