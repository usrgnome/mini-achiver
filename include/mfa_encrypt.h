#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "mfa_types.h"

int enc_file(enc_file_t *file, char *pass);

int enc_files(enc_file_t files[], size_t file_count, char *pass);

#endif /* ENCRYPT_H */