#ifndef MFA_UTIL_H
#define MFA_UTIL_H

#include "linked_list.h"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/* ---------------- File handle ---------------- */
typedef struct {
    const char *path;  /* input path (not owned) */
    uint8_t    *buf;   /* loaded bytes (owned) */
    size_t      len;   /* size of buf */
} mfa_file;

/* ============================================================
   Utility helpers for MFA archive format
   ------------------------------------------------------------
   Provides little-endian readers/writers, padding, and
   small path/name helpers. Shared by packer/unpacker.
   ============================================================ */

/* -------- I/O convenience -------- */

/* Read exactly n bytes; return 0 on success, -1 on short read. */
int mfa_read_exact(FILE *fp, void *buf, size_t n);

/* Write exactly n bytes; return 0 on success, -1 on error. */
int mfa_write_exact(FILE *fp, const void *buf, size_t n);

/* -------- Little-endian writers -------- */

int mfa_w16(FILE *fp, uint16_t v);
int mfa_w32(FILE *fp, uint32_t v);
int mfa_w64(FILE *fp, uint64_t v);

/* -------- Little-endian readers -------- */

int mfa_r16(FILE *fp, uint16_t *out);
int mfa_r32(FILE *fp, uint32_t *out);
int mfa_r64(FILE *fp, uint64_t *out);

/* -------- Alignment / padding -------- */

/* Pad file to next multiple of `align`, writing zeros.
   Returns new file offset or -1 on error. */
long long mfa_pad_to(FILE *fp, unsigned long long off, unsigned align);

/* -------- Path helpers -------- */

/* Return pointer to basename within a path. */
const char *mfa_basename(const char *p);

/* Sanitize path so no separators (replace with '_'). */
void mfa_sanitize(char *s);

/* Join directory + name into a newly malloc'd string.
   Caller must free. If dir is NULL/empty, just dup name. */
char *mfa_join_path(const char *dir, const char *name);

/* Sort a list of paths in-place. */
int mfa_sort_paths(linked_list *paths);

#endif /* MFA_UTIL_H */
