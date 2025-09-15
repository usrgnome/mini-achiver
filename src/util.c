#include "util.h"
#include <stdio.h>
#include <stdlib.h>

unsigned char *load_file(const char *path, size_t *out_len) {
    if (!path || !out_len) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }

    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); fclose(f); return NULL; }
    rewind(f);

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { perror("malloc"); fclose(f); return NULL; }

    size_t n = fread(buf, 1, (size_t)sz, f);
    if (n != (size_t)sz) { perror("fread"); free(buf); fclose(f); return NULL; }

    if (fclose(f) != 0) { perror("fclose"); free(buf); return NULL; }

    *out_len = n;
    return buf;
}
