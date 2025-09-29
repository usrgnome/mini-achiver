#ifndef MFA_H
#define MFA_H

#include "linked_list.h"
#include <stddef.h>   /* size_t */
#include <stdint.h>   /* uint8_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- File handle ---------------- */
typedef struct {
    const char *path;  /* input path (not owned) */
    uint8_t    *buf;   /* loaded bytes (owned) */
    size_t      len;   /* size of buf */
} mfa_file;

/* ---------------- Transform flags ---------------- */
enum {
    MFA_COMPRESS = 1u << 0,  /* (placeholder; no-op until you implement) */
    MFA_ENCRYPT  = 1u << 1   /* simple XOR demo */
};

/* ---------------- Public API ---------------- */

/* Load file contents into memory for each entry (fills buf/len). */
int  mfa_load_all(linked_list *files);

/* Free file buffers for each entry (frees buf, zeroes len). */
void mfa_free_all(linked_list *files);

/* Create an archive from files[]. If flags contain MFA_ENCRYPT, `pass` is used.
   Returns 0 on success. */
int mfa_pack(const char *archive_path,
             linked_list *files,
             const char *pass, unsigned flags);

/* Print a table of contents for the archive to stdout. */
int mfa_list(const char *archive_path);

/* Extract all entries to out_dir (or current dir if out_dir NULL/empty). */
int mfa_extract_all(const char *archive_path, const char *out_dir);

#ifdef __cplusplus
}
#endif
#endif /* MFA_H */
