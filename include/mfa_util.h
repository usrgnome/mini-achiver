#ifndef UTIL_H
#define UTIL_H

#include "mfa_types.h"
#include <stdlib.h>  /* for size_t */

void free_files(enc_file_t *files, size_t n);

unsigned char *load_file(const char *path, size_t *out_len);

int load_all(enc_file_t *files, size_t n);

int build_archive(const char *path, enc_file_t files[], size_t file_count);

int validate_pass(const char *pass);

#endif /* UTIL_H */
