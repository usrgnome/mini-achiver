#ifndef COMPRESS_H
#define COMPRESS_H

#include "mfa_types.h"

int compress_file(enc_file_t *file);

int compress_files(enc_file_t files[], size_t file_count);

#endif /* COMPRESS_H */