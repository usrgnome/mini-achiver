#include "mfa_util.h"
#include "mfa_types.h"
#include <stdio.h>
#include <stdlib.h>

void free_files(enc_file_t *files, size_t n) {
    if (!files) return;
    for (size_t i = 0; i < n; ++i) {
        free(files[i].data);      /* free(NULL) is safe */
        files[i].data = NULL;
        files[i].len = 0;
        /* files[i].path is not owned; do not free */
    }
}

/* Load entire file into memory (binary).
   Returns malloc'ed buffer and sets *out_len.
   On error, returns NULL and *out_len is left unchanged. */
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

int load_all(enc_file_t *files, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        files[i].data = NULL;
        files[i].len = 0;
        size_t len = 0;
        unsigned char *buf = load_file(files[i].path, &len);
        if (!buf) {
            fprintf(stderr, "Failed to load: %s\n", files[i].path);
            return -1;
        }
        files[i].data = buf;
        files[i].len = len;
    }
    return 0;
}

int build_archive(const char *path, enc_file_t files[], size_t file_count) {
    return 0;
}

int validate_pass(const char *pass) {
    int pass_len = strlen(pass);
    if (!pass || pass_len == 0) return 0;
    // Example validation: at least 1 characters
    return pass_len >= 1;
}
