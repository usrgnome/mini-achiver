#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------- Little-endian readers ----------------------- */

int read_exact(FILE *fp, void *buf, size_t n);

int read_u16_le(FILE *fp, unsigned long *out);

int read_u32_le(FILE *fp, unsigned long *out);

int read_u64_le(FILE *fp, unsigned long long *out);

/* ----------------------- Small helpers ----------------------- */

/* Replace path separators so we don't need to create directories */
void sanitize_name(char *s);

/* Join out_dir + "/" + name into a malloc'd path (or just name if out_dir NULL/empty) */
char *join_path(const char *out_dir, const char *name);

/* Stream copy from fp (at current position) to a new file of size 'len' */
int write_out_file(const char *path, FILE *fp, unsigned long long len);

/* ----------------------- Core reader/extractor ----------------------- */

typedef struct {
    char *name;                       /* malloc'd, sanitized */
    unsigned long long orig_size;
    unsigned long long stored_size;
    unsigned long long data_offset;   /* absolute in archive */
    unsigned long      flags;         /* bit1 => encrypted, bit0 => compressed (as per writer) */
    unsigned long      alg_id;        /* 0=raw bytes written, else depends on your design */
    /* meta is skipped in this minimal reader; add if you need it */
} mfa_entry;

/* Free TOC entries */
void free_entries(mfa_entry *e, size_t n);

/* Parse header and TOC; returns entries array via *out and count via *out_n */
int mfa_read_toc(FILE *fp, mfa_entry **out, size_t *out_n,
                        unsigned long long *out_data_off);

/* List contents to stdout */
int mfa_list(const char *archive_path);

/* Extract all entries to out_dir (or current dir if out_dir NULL/"") */
int mfa_extract_all(const char *archive_path, const char *out_dir);