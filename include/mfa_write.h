#ifndef WRITE_H
#define WRITE_H

#include "mfa_types.h"
#include <stdlib.h>  /* for size_t */
#include <stdio.h>

/* Little-endian writers, no <stdint.h> needed */
int write_u32_le(FILE *fp, unsigned long v);

int write_u16_le(FILE *fp, unsigned long v);

int write_u64_le(FILE *fp, unsigned long long v);

int write_bytes(FILE *fp, const void *buf, size_t len);

long long pad_to(FILE *fp, unsigned long long off, unsigned long align);

int build_archive(const char *path, enc_file_t files[], size_t file_count);

/* helper: return pointer to basename within a path */
static const char *basename_c(const char *p) {
    const char *last = p;
    for (const char *s = p; *s; ++s) {
        if (*s == '/' || *s == '\\') last = s + 1;
    }
    return last;
}

#endif /* WRITE_H */