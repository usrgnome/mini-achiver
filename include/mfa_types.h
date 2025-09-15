#ifndef TYPES_H
#define TYPES_H

#include <stdlib.h>  /* for size_t */

typedef struct {
    char *path;              // original path
    size_t len;             // original length
    unsigned char *data;    // original data
    size_t elen;            // encrypted length
    unsigned char *edata;   // encrypted data
} enc_file_t;

#endif /* TYPES_H */