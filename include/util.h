#ifndef MFA_UTIL_H
#define MFA_UTIL_H

#include <stddef.h>

/* Load entire file into memory (binary).
   Returns malloc'ed buffer and sets *out_len.
   On error, returns NULL and *out_len is left unchanged. */
unsigned char *load_file(const char *path, size_t *out_len);

#endif /* MFA_UTIL_H */
