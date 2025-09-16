#include "mfa_read.h"
#include "mfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ----------------------- Little-endian readers ----------------------- */
 int read_exact(FILE *fp, void *buf, size_t n) {
    return fread(buf, 1, n, fp) == n ? 0 : -1;
}
 int read_u16_le(FILE *fp, unsigned long *out) {
    unsigned char b[2];
    if (read_exact(fp, b, 2)) return -1;
    *out = (unsigned long)b[0] | ((unsigned long)b[1] << 8);
    return 0;
}
 int read_u32_le(FILE *fp, unsigned long *out) {
    unsigned char b[4];
    if (read_exact(fp, b, 4)) return -1;
    *out = (unsigned long)b[0]
         | ((unsigned long)b[1] << 8)
         | ((unsigned long)b[2] << 16)
         | ((unsigned long)b[3] << 24);
    return 0;
}
 int read_u64_le(FILE *fp, unsigned long long *out) {
    unsigned char b[8];
    if (read_exact(fp, b, 8)) return -1;
    *out =  ((unsigned long long)b[0])
          | ((unsigned long long)b[1] << 8)
          | ((unsigned long long)b[2] << 16)
          | ((unsigned long long)b[3] << 24)
          | ((unsigned long long)b[4] << 32)
          | ((unsigned long long)b[5] << 40)
          | ((unsigned long long)b[6] << 48)
          | ((unsigned long long)b[7] << 56);
    return 0;
}

/* ----------------------- Small helpers ----------------------- */

/* Replace path separators so we don't need to create directories */
 void sanitize_name(char *s) {
    for (; *s; ++s) {
        if (*s == '/' || *s == '\\' || *s == ':') *s = '_';
    }
}

/* Join out_dir + "/" + name into a malloc'd path (or just name if out_dir NULL/empty) */
 char *join_path(const char *out_dir, const char *name) {
    if (!out_dir || !*out_dir) {
        size_t n = strlen(name);
        char *p = (char *)malloc(n + 1);
        if (!p) return NULL;
        memcpy(p, name, n + 1);
        return p;
    }
    size_t a = strlen(out_dir), b = strlen(name);
    int need_sep = (a > 0 && out_dir[a - 1] != '/');
    size_t n = a + (need_sep ? 1 : 0) + b;
    char *p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, out_dir, a);
    if (need_sep) p[a] = '/', a += 1;
    memcpy(p + a, name, b);
    p[n] = '\0';
    return p;
}

/* Stream copy from fp (at current position) to a new file of size 'len' */
 int write_out_file(const char *path, FILE *fp, unsigned long long len) {
    FILE *out = fopen(path, "wb");
    if (!out) { perror(path); return -1; }
    unsigned char *buf = (unsigned char *)malloc(64 * 1024);
    if (!buf) { perror("malloc"); fclose(out); return -1; }

    unsigned long long remaining = len;
    while (remaining > 0) {
        size_t chunk = (remaining > 64 * 1024ULL) ? (64 * 1024U) : (size_t)remaining;
        size_t r = fread(buf, 1, chunk, fp);
        if (r != chunk) { perror("fread"); free(buf); fclose(out); return -1; }
        if (fwrite(buf, 1, r, out) != r) { perror("fwrite"); free(buf); fclose(out); return -1; }
        remaining -= r;
    }

    free(buf);
    if (fclose(out) != 0) { perror("fclose"); return -1; }
    return 0;
}

/* Free TOC entries */
 void free_entries(mfa_entry *e, size_t n) {
    if (!e) return;
    for (size_t i = 0; i < n; ++i) free(e[i].name);
    free(e);
}

/* Parse header and TOC; returns entries array via *out and count via *out_n */
 int mfa_read_toc(FILE *fp, mfa_entry **out, size_t *out_n,
                        unsigned long long *out_data_off) {
    char magic[8];
    if (read_exact(fp, magic, 8)) return -1;
    if (memcmp(magic, "MFAARCH", 7) != 0 || magic[7] != '\0') {
        fprintf(stderr, "Bad magic\n");
        return -1;
    }

    unsigned long version = 0, hdr_sz = 0, gflags = 0, count32 = 0;
    unsigned long long toc_off = 0, data_off = 0, arch_sz = 0;

    if (read_u16_le(fp, &version)) return -1;
    if (read_u16_le(fp, &hdr_sz)) return -1;
    if (read_u32_le(fp, &gflags)) return -1;
    if (read_u32_le(fp, &count32)) return -1;
    if (read_u64_le(fp, &toc_off)) return -1;
    if (read_u64_le(fp, &data_off)) return -1;
    if (read_u64_le(fp, &arch_sz)) return -1;

    /* skip reserved 12 bytes */
    unsigned char zeros[12];
    if (read_exact(fp, zeros, 12)) return -1;

    if (version != 1 || hdr_sz != 56) {
        fprintf(stderr, "Unsupported version or header size\n");
        return -1;
    }

    size_t n = (size_t)count32;
    mfa_entry *entries = (mfa_entry *)calloc(n, sizeof *entries);
    if (!entries) { perror("calloc"); return -1; }

    /* jump to TOC */
    if (fseek(fp, (long)toc_off, SEEK_SET) != 0) { perror("fseek TOC"); free(entries); return -1; }

    for (size_t i = 0; i < n; ++i) {
        unsigned long name_len = 0;
        if (read_u32_le(fp, &name_len)) { free_entries(entries, n); return -1; }

        char *name = (char *)malloc((size_t)name_len + 1);
        if (!name && name_len) { perror("malloc name"); free_entries(entries, n); return -1; }
        if (name_len && read_exact(fp, name, (size_t)name_len)) { free(name); free_entries(entries, n); return -1; }
        if (name) name[name_len] = '\0';

        unsigned long long orig = 0, stored = 0, off = 0;
        unsigned long flags = 0, alg_id = 0, meta_len = 0;

        if (read_u64_le(fp, &orig))   { free(name); free_entries(entries, n); return -1; }
        if (read_u64_le(fp, &stored)) { free(name); free_entries(entries, n); return -1; }
        if (read_u64_le(fp, &off))    { free(name); free_entries(entries, n); return -1; }
        if (read_u32_le(fp, &flags))  { free(name); free_entries(entries, n); return -1; }

        if (read_u16_le(fp, &alg_id)) { free(name); free_entries(entries, n); return -1; }
        if (read_u16_le(fp, &meta_len)) { free(name); free_entries(entries, n); return -1; }

        /* skip meta */
        if (meta_len) {
            if (fseek(fp, (long)meta_len, SEEK_CUR) != 0) { free(name); free_entries(entries, n); return -1; }
        }

        if (name) sanitize_name(name);

        entries[i].name        = name ? name : strdup(""); /* never NULL */
        entries[i].orig_size   = orig;
        entries[i].stored_size = stored;
        entries[i].data_offset = off;
        entries[i].flags       = flags;
        entries[i].alg_id      = alg_id;
    }

    *out = entries;
    *out_n = n;
    if (out_data_off) *out_data_off = data_off;
    return 0;
}

/* List contents to stdout */
int mfa_list(const char *archive_path) {
    FILE *fp = fopen(archive_path, "rb");
    if (!fp) { perror(archive_path); return -1; }

    mfa_entry *ents = NULL; size_t n = 0; unsigned long long data_off = 0;
    if (mfa_read_toc(fp, &ents, &n, &data_off)) { fclose(fp); return -1; }

    printf("Archive: %s\n", archive_path);
    printf("%-6s  %-10s  %-10s  %s\n", "Index", "OrigSize", "Stored", "Name");
    for (size_t i = 0; i < n; ++i) {
        printf("%-6zu  %-10llu  %-10llu  %s\n",
               i,
               (unsigned long long)ents[i].orig_size,
               (unsigned long long)ents[i].stored_size,
               ents[i].name);
    }

    free_entries(ents, n);
    fclose(fp);
    return 0;
}

/* Extract all entries to out_dir (or current dir if out_dir NULL/"") */
int mfa_extract_all(const char *archive_path, const char *out_dir) {
    FILE *fp = fopen(archive_path, "rb");
    if (!fp) { perror(archive_path); return -1; }

    mfa_entry *ents = NULL; size_t n = 0; unsigned long long data_off = 0;
    if (mfa_read_toc(fp, &ents, &n, &data_off)) { fclose(fp); return -1; }

    for (size_t i = 0; i < n; ++i) {
        /* Seek to data offset and stream out */
        if (fseek(fp, (long)ents[i].data_offset, SEEK_SET) != 0) {
            perror("fseek file payload");
            free_entries(ents, n);
            fclose(fp);
            return -1;
        }

        char *out_path = join_path(out_dir, ents[i].name);
        if (!out_path) {
            perror("malloc out_path");
            free_entries(ents, n);
            fclose(fp);
            return -1;
        }

        /* If later you add compression/encryption:
           - If flags say compressed/encrypted, read into a temp buffer,
             transform, then fwrite the decoded bytes.
           - For now we just write stored bytes verbatim. */
        if (write_out_file(out_path, fp, ents[i].stored_size)) {
            fprintf(stderr, "Failed writing %s\n", out_path);
            free(out_path);
            free_entries(ents, n);
            fclose(fp);
            return -1;
        }

        free(out_path);
    }

    free_entries(ents, n);
    fclose(fp);
    return 0;
}