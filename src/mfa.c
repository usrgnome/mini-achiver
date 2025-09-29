#include "mfa.h"
#include "mfa_util.h"
#include "linked_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================================================
   Transforms (currently disabled)
   ============================================================ */

/* Simple RLE compression stub: disabled (no-op) */
static int tf_compress(uint8_t **pbuf, size_t *plen) {
    (void)pbuf; (void)plen;
    return 0;
}

/* RLE decompression stub: disabled (no-op) */
static int tf_decompress_rle(const uint8_t *in, size_t in_len,
                             uint8_t **out_buf, size_t *out_len,
                             uint64_t expected_out_len) {
    (void)in; (void)in_len; (void)out_buf; (void)out_len; (void)expected_out_len;
    return 0;
}

/* Encryption: disabled (no-op) */
static int tf_xor_encrypt(uint8_t **pbuf, size_t *plen, const char *pass) {
    (void)pbuf; (void)plen; (void)pass;
    return 0;
}

/* Decryption: disabled (no-op) */
/*static int tf_xor_detcrypt(uint8_t **pbuf, size_t *plen, const char *pass) {
    (void)pbuf; (void)plen; (void)pass;
    return 0;
}*/

/* ============================================================
   Loading & freeing
   ============================================================ */

int mfa_load_all(linked_list *files) {
    linked_list_node *node;
    size_t processed;

    if (!files) return -1;

    node = files->head;
    processed = 0;

    for (; node; node = node->next, ++processed) {
        mfa_file *file;
        FILE *f;
        long sz;
        uint8_t *buf;

        if (!node->data) return -1;
        file = (mfa_file *)node->data;
        if (!file || !file->path) return -1;

        f = fopen(file->path, "rb");
        if (!f) { perror(file->path); goto fail; }

        if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); goto fail; }
        sz = ftell(f);
        if (sz < 0) { perror("ftell"); fclose(f); goto fail; }
        rewind(f);

        buf = (uint8_t *)malloc((size_t)sz);
        if (!buf) { perror("malloc"); fclose(f); goto fail; }

        if (mfa_read_exact(f, buf, (size_t)sz)) { perror("fread"); free(buf); fclose(f); goto fail; }
        if (fclose(f) != 0) { perror("fclose"); free(buf); goto fail; }

        file->buf = buf;
        file->len = (size_t)sz;
    }
    return 0;

fail:
    node = files->head;
    for (; processed > 0 && node; --processed, node = node->next) {
        mfa_file *f2 = (mfa_file *)node->data;
        if (f2) { free(f2->buf); f2->buf = NULL; f2->len = 0; }
    }
    return -1;
}

void mfa_free_all(linked_list *ll) {
    linked_list_node *node;
    if (!ll) return;

    node = ll->head;
    while (node) {
        mfa_file *file = (mfa_file *)node->data;
        if (file) {
            free(file->buf);
            file->buf = NULL;
            file->len = 0;
        }
        node = node->next;
    }
}

/* ============================================================
   Archive format (LE)
   ============================================================ */

int mfa_pack(const char *path, linked_list *ll,
             const char *pass, unsigned flags)
{
    FILE *f;
    const unsigned ALIGN = 16;
    size_t n;
    uint64_t *orig_sizes;
    uint64_t *dataoff_patch;
    uint8_t zeros[12];
    long toc_pos, data_pos, size_pos;
    long toc_off_l, after_toc;
    long long data_off_ll;
    uint64_t cursor;
    uint64_t toc_off, data_off, arch_sz;

    linked_list_node *node;
    size_t i;

    (void)pass;  /* encryption disabled */
    (void)flags; /* do not set bits unless transforms actually occur */

    if (!path || !ll || ll->size == 0) return -1;

    n = ll->size;

    /* Save original sizes in list order */
    orig_sizes = (uint64_t *)calloc(n, sizeof *orig_sizes);
    if (!orig_sizes) { perror("calloc"); return -1; }

    i = 0;
    node = ll->head;
    for (; node; node = node->next, ++i) {
        mfa_file *file = (mfa_file *)node->data;
        if (!file) { free(orig_sizes); return -1; }
        orig_sizes[i] = (uint64_t)file->len;
    }

    /* Apply transforms (currently no-ops) but DO NOT set flag bits */
    i = 0;
    node = ll->head;
    for (; node; node = node->next, ++i) {
        mfa_file *file = (mfa_file *)node->data;
        if (!file) { free(orig_sizes); return -1; }

        /* Compression disabled: keep as-is; do not set compressed bit */
        (void)tf_compress; /* silence unused if compiled out */
        /* Encryption disabled: keep as-is; do not set encrypted bit */
        (void)tf_xor_encrypt;
    }

    f = fopen(path, "wb");
    if (!f) { perror(path); free(orig_sizes); return -1; }

    /* --- Header preamble --- */
    {
        const char magic[8] = { 'M','F','A','A','R','C','H','\0' };
        if (mfa_write_exact(f, magic, 8)) goto io_err;
    }
    if (mfa_w16(f, 1)) goto io_err;
    if (mfa_w16(f, 56)) goto io_err;
    if (mfa_w32(f, 0)) goto io_err;
    if (mfa_w32(f, (uint32_t)n)) goto io_err;

    toc_pos  = ftell(f); if (toc_pos  < 0) goto io_err; if (mfa_w64(f, 0)) goto io_err;
    data_pos = ftell(f); if (data_pos < 0) goto io_err; if (mfa_w64(f, 0)) goto io_err;
    size_pos = ftell(f); if (size_pos < 0) goto io_err; if (mfa_w64(f, 0)) goto io_err;

    memset(zeros, 0, sizeof zeros);
    if (mfa_write_exact(f, zeros, 12)) goto io_err;

    toc_off_l = ftell(f); if (toc_off_l < 0) goto io_err;

    /* Positions for backpatching data offsets */
    dataoff_patch = (uint64_t *)malloc(n * sizeof *dataoff_patch);
    if (!dataoff_patch) { perror("malloc"); goto io_err; }

    /* ---- TOC entries ---- */
    i = 0;
    node = ll->head;
    for (; node; node = node->next, ++i) {
        mfa_file *file = (mfa_file *)node->data;
        const char *name;
        size_t name_len;
        long p;
        uint32_t per_flags = 0; /* no transforms actually applied */
        uint16_t alg_id = 0;    /* 0: raw */

        name = (file && file->path) ? mfa_basename(file->path) : "";
        name_len = strlen(name);

        if (mfa_w32(f, (uint32_t)name_len)) goto toc_err;
        if (name_len && mfa_write_exact(f, name, name_len)) goto toc_err;

        if (mfa_w64(f, orig_sizes[i])) goto toc_err;                 /* orig_size */
        if (mfa_w64(f, (uint64_t)file->len)) goto toc_err;           /* stored_size */

        p = ftell(f); if (p < 0) goto toc_err;
        dataoff_patch[i] = (uint64_t)p;
        if (mfa_w64(f, 0)) goto toc_err;                             /* data_offset placeholder */

        if (mfa_w32(f, per_flags)) goto toc_err;                     /* per-file flags (none) */
        if (mfa_w16(f, alg_id)) goto toc_err;                        /* alg_id = 0 */
        if (mfa_w16(f, 0)) goto toc_err;                             /* meta_len = 0 */
    }

    /* ---- Data section ---- */
    after_toc = ftell(f); if (after_toc < 0) goto toc_err;
    data_off_ll = mfa_pad_to(f, (unsigned long long)after_toc, ALIGN);
    if (data_off_ll < 0) goto toc_err;
    cursor = (uint64_t)data_off_ll;

    i = 0;
    node = ll->head;
    for (; node; node = node->next, ++i) {
        mfa_file *file = (mfa_file *)node->data;
        long long nc;

        if (fseek(f, (long)dataoff_patch[i], SEEK_SET) != 0) goto toc_err;
        if (mfa_w64(f, cursor)) goto toc_err;

        if (fseek(f, (long)cursor, SEEK_SET) != 0) goto toc_err;
        if (file->len && mfa_write_exact(f, file->buf, file->len)) goto toc_err;

        cursor += (uint64_t)file->len;
        nc = mfa_pad_to(f, cursor, ALIGN);
        if (nc < 0) goto toc_err;
        cursor = (uint64_t)nc;
    }

    /* Finalize header */
    toc_off = (uint64_t)toc_off_l;
    data_off = (uint64_t)data_off_ll;
    arch_sz = (uint64_t)ftell(f);

    if (fseek(f, toc_pos,  SEEK_SET) != 0) goto toc_err;
    if (mfa_w64(f, toc_off)) goto toc_err;

    if (fseek(f, data_pos, SEEK_SET) != 0) goto toc_err;
    if (mfa_w64(f, data_off)) goto toc_err;

    if (fseek(f, size_pos, SEEK_SET) != 0) goto toc_err;
    if (mfa_w64(f, arch_sz)) goto toc_err;

    free(dataoff_patch);
    free(orig_sizes);
    if (fclose(f) != 0) { perror("fclose"); return -1; }
    return 0;

toc_err:
    free(dataoff_patch);
io_err:
    perror("I/O");
    if (f) fclose(f);
    free(orig_sizes);
    return -1;
}

/* ============================================================
   TOC reader
   ============================================================ */

typedef struct {
    char     *name;
    uint64_t  orig_size;
    uint64_t  stored_size;
    uint64_t  data_offset;
    uint32_t  flags;
    uint16_t  alg_id;
} mfa_toc_entry;

static void *xmalloc_zero(size_t n) {
    void *p = malloc(n);
    if (p) memset(p, 0, n);
    return p;
}

static void toc_free(mfa_toc_entry *e, size_t n) {
    size_t i;
    if (!e) return;
    for (i = 0; i < n; ++i) free(e[i].name);
    free(e);
}

static int toc_read(FILE *fp, mfa_toc_entry **out, size_t *out_n, uint64_t *out_data_off) {
    char magic[8];
    uint16_t version=0, hdr_sz=0;
    uint32_t gflags=0, count=0;
    uint64_t toc_off=0, data_off=0, arch_sz=0;
    uint8_t  zeros[12];
    mfa_toc_entry *ents;
    uint32_t i;

    if (mfa_read_exact(fp, magic, 8)) return -1;
    if (memcmp(magic, "MFAARCH", 7) != 0 || magic[7] != '\0') return -1;

    if (mfa_r16(fp, &version) || mfa_r16(fp, &hdr_sz) ||
        mfa_r32(fp, &gflags)  || mfa_r32(fp, &count)  ||
        mfa_r64(fp, &toc_off) || mfa_r64(fp, &data_off) || mfa_r64(fp, &arch_sz) ||
        mfa_read_exact(fp, zeros, 12))
        return -1;

    if (version != 1 || hdr_sz != 56) return -1;

    if (fseek(fp, (long)toc_off, SEEK_SET) != 0) return -1;
    ents = (mfa_toc_entry *)calloc(count, sizeof *ents);
    if (!ents) return -1;

    for (i = 0; i < count; ++i) {
        uint32_t name_len = 0;
        char *name;
        uint64_t orig=0, stored=0, off=0;
        uint32_t flags=0; uint16_t alg=0, meta_len=0;

        if (mfa_r32(fp, &name_len)) { toc_free(ents, i); return -1; }

        name = (char *)malloc(name_len + 1);
        if (!name && name_len) { toc_free(ents, i); return -1; }
        if (name_len && mfa_read_exact(fp, name, name_len)) { free(name); toc_free(ents, i); return -1; }
        if (name) name[name_len] = '\0';
        if (name) mfa_sanitize(name);

        if (mfa_r64(fp, &orig)   || mfa_r64(fp, &stored) ||
            mfa_r64(fp, &off)    || mfa_r32(fp, &flags)  ||
            mfa_r16(fp, &alg)    || mfa_r16(fp, &meta_len)) {
            free(name); toc_free(ents, i); return -1;
        }

        if (meta_len && fseek(fp, (long)meta_len, SEEK_CUR) != 0) { free(name); toc_free(ents, i); return -1; }

        if (name) {
            ents[i].name = name;
        } else {
            ents[i].name = (char *)xmalloc_zero(1); /* fallback for empty name without strdup */
            if (!ents[i].name) { toc_free(ents, i); return -1; }
        }
        ents[i].orig_size   = orig;
        ents[i].stored_size = stored;
        ents[i].data_offset = off;
        ents[i].flags       = flags;
        ents[i].alg_id      = alg;
    }

    *out = ents;
    *out_n = (size_t)count;
    if (out_data_off) *out_data_off = data_off;
    return 0;
}

/* ============================================================
   List
   ============================================================ */

int mfa_list(const char *archive_path) {
    FILE *fp;
    mfa_toc_entry *ents = NULL;
    size_t n = 0;
    uint64_t data_off = 0;
    size_t i;

    fp = fopen(archive_path, "rb");
    if (!fp) { perror(archive_path); return -1; }

    if (toc_read(fp, &ents, &n, &data_off)) { fclose(fp); return -1; }

    printf("Archive: %s\n", archive_path);
    printf("%-6s  %-10s  %-10s  %s\n", "Index", "OrigSize", "Stored", "Name");
    for (i = 0; i < n; ++i) {
        printf("%-6zu  %-10llu  %-10llu  %s\n",
               i,
               (unsigned long long)ents[i].orig_size,
               (unsigned long long)ents[i].stored_size,
               ents[i].name);
    }

    toc_free(ents, n);
    fclose(fp);
    return 0;
}

/* ============================================================
   Extract
   ============================================================ */

static int stream_copy_to(const char *out_path, FILE *fp, uint64_t len) {
    FILE *out;
    uint8_t *buf;
    uint64_t remaining;

    out = fopen(out_path, "wb");
    if (!out) { perror(out_path); return -1; }

    buf = (uint8_t *)malloc(64 * 1024);
    if (!buf) { perror("malloc"); fclose(out); return -1; }

    remaining = len;
    while (remaining) {
        size_t chunk = (remaining > 64 * 1024ULL) ? (64 * 1024U) : (size_t)remaining;
        if (mfa_read_exact(fp, buf, chunk)) { perror("fread"); free(buf); fclose(out); return -1; }
        if (mfa_write_exact(out, buf, chunk)) { perror("fwrite"); free(buf); fclose(out); return -1; }
        remaining -= chunk;
    }

    free(buf);
    if (fclose(out) != 0) { perror("fclose"); return -1; }
    return 0;
}

int mfa_extract_all(const char *archive_path, const char *out_dir) {
    FILE *fp;
    mfa_toc_entry *ents = NULL;
    size_t n = 0;
    uint64_t data_off = 0;
    size_t i;

    fp = fopen(archive_path, "rb");
    if (!fp) { perror(archive_path); return -1; }

    if (toc_read(fp, &ents, &n, &data_off)) { fclose(fp); return -1; }

    for (i = 0; i < n; ++i) {
        char *out_path;
        int is_compressed;

        if (fseek(fp, (long)ents[i].data_offset, SEEK_SET) != 0) {
            perror("fseek"); toc_free(ents, n); fclose(fp); return -1;
        }

        out_path = mfa_join_path(out_dir, ents[i].name);
        if (!out_path) { perror("malloc"); toc_free(ents, n); fclose(fp); return -1; }

        is_compressed = (ents[i].flags & (1u << 0)) != 0;

        if (!is_compressed) {
            if (stream_copy_to(out_path, fp, ents[i].stored_size)) {
                fprintf(stderr, "Failed writing %s\n", out_path);
                free(out_path); toc_free(ents, n); fclose(fp); return -1;
            }
        } else {
            /* Compression is disabled in pack; this branch shouldn't occur.
               Left here for future compatibility. */
            size_t s = (size_t)ents[i].stored_size;
            uint8_t *stored = (uint8_t *)malloc(s ? s : 1);
            uint8_t *plain = NULL;
            size_t plain_len = 0;

            if (!stored) { perror("malloc"); free(out_path); toc_free(ents, n); fclose(fp); return -1; }
            if (s && mfa_read_exact(fp, stored, s)) {
                perror("fread"); free(stored); free(out_path); toc_free(ents, n); fclose(fp); return -1;
            }

            if (tf_decompress_rle(stored, s, &plain, &plain_len, ents[i].orig_size) != 0) {
                fprintf(stderr, "Decompression failed for %s\n", ents[i].name);
                free(stored); free(out_path); toc_free(ents, n); fclose(fp); return -1;
            }
            free(stored);

            {
                FILE *out = fopen(out_path, "wb");
                if (!out) { perror(out_path); free(plain); free(out_path); toc_free(ents, n); fclose(fp); return -1; }
                if (plain_len && mfa_write_exact(out, plain, plain_len)) {
                    perror("fwrite"); fclose(out); free(plain); free(out_path); toc_free(ents, n); fclose(fp); return -1;
                }
                if (fclose(out) != 0) { perror("fclose"); free(plain); free(out_path); toc_free(ents, n); fclose(fp); return -1; }
            }

            if (plain_len != (size_t)ents[i].orig_size) {
                fprintf(stderr, "Size mismatch after decompression for %s\n", ents[i].name);
                free(plain); free(out_path); toc_free(ents, n); fclose(fp); return -1;
            }
            free(plain);
        }

        free(out_path);
    }

    toc_free(ents, n);
    fclose(fp);
    return 0;
}
