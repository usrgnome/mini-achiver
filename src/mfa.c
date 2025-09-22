#include "mfa.h"
#include "mfa_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
   Transforms (kept tiny on purpose)
   - Each transform may consume *pbuf and return a new buffer.
   - Replace these implementations later without touching pack/list/extract.
   ============================================================ */

/* Placeholder "compression" (currently a no-op). */
static int tf_compress(uint8_t **pbuf, size_t *plen) {
    (void)pbuf; (void)plen;
    return 0; /* implement real compression later */
}

/* Toy XOR encryption: for demo only, NOT secure. */
static int tf_xor_encrypt(uint8_t **pbuf, size_t *plen, const char *pass) {
    /*
    if (!pass || !*pass) return 0;
    size_t n = *plen;
    size_t k = strlen(pass);
    uint8_t *in  = *pbuf;
    uint8_t *out = (uint8_t *)malloc(n);
    if (!out) { perror("malloc"); return -1; }
    for (size_t i = 0; i < n; ++i) out[i] = in[i] ^ (uint8_t)pass[i % k];
    free(in);
    *pbuf = out; *plen = n;
    return 0;
    */
    (void)pbuf;  /* unused */
    (void)plen;  /* unused */
    (void)pass;  /* unused */
    return 0;    /* always succeed */
}

/* ============================================================
   Loading & freeing
   ============================================================ */

int mfa_load_all(mfa_file files[], size_t n) {
    for (size_t i = 0; i < n; ++i) {
        const char *path = files[i].path;
        FILE *f = fopen(path, "rb");
        if (!f) { perror(path); return -1; }

        if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return -1; }
        long sz = ftell(f);
        if (sz < 0) { perror("ftell"); fclose(f); return -1; }
        rewind(f);

        uint8_t *buf = (uint8_t *)malloc((size_t)sz);
        if (!buf) { perror("malloc"); fclose(f); return -1; }

        if (mfa_read_exact(f, buf, (size_t)sz)) { perror("fread"); free(buf); fclose(f); return -1; }
        if (fclose(f) != 0) { perror("fclose"); free(buf); return -1; }

        files[i].buf = buf;
        files[i].len = (size_t)sz;
    }
    return 0;
}

void mfa_free_all(mfa_file files[], size_t n) {
    for (size_t i = 0; i < n; ++i) {
        free(files[i].buf);
        files[i].buf = NULL;
        files[i].len = 0;
    }
}

/* ============================================================
   Archive format (LE)
   ------------------------------------------------------------
   Global header (56 bytes):
     magic[8]="MFAARCH\0"
     u16 version=1
     u16 header_size=56
     u32 global_flags=0
     u32 file_count
     u64 toc_offset
     u64 data_offset
     u64 archive_size
     12 reserved=0
   TOC entry (per file):
     u32 name_len
     name bytes (no NUL)
     u64 orig_size
     u64 stored_size
     u64 data_offset
     u32 flags (bit0=compressed, bit1=encrypted)
     u16 alg_id   (0=raw, 100=XOR demo)
     u16 meta_len
     meta bytes (skipped)
   Data section: file payloads aligned to 16 bytes.
   ============================================================ */

int mfa_pack(const char *path, mfa_file files[], size_t n,
             const char *pass, unsigned flags)
{
    if (!path || !files || n == 0) return -1;

    /* Apply transforms in memory. */
    for (size_t i = 0; i < n; ++i) {
        if (flags & MFA_COMPRESS) { if (tf_compress(&files[i].buf, &files[i].len)) return -1; }
        if (flags & MFA_ENCRYPT)  { if (tf_xor_encrypt(&files[i].buf, &files[i].len, pass)) return -1; }
    }

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }

    /* 1) Write global header (placeholders) */
    {
        const char magic[8] = { 'M','F','A','A','R','C','H','\0' };
        if (mfa_write_exact(f, magic, 8)) goto io_err;
        if (mfa_w16(f, 1)) goto io_err;      /* version */
        if (mfa_w16(f, 56)) goto io_err;     /* header_size */
        if (mfa_w32(f, 0)) goto io_err;      /* global_flags */
        if (mfa_w32(f, (uint32_t)n)) goto io_err;

        /* placeholders for toc_offset, data_offset, archive_size */
        long toc_pos  = ftell(f); if (toc_pos  < 0) goto io_err; if (mfa_w64(f, 0)) goto io_err;
        long data_pos = ftell(f); if (data_pos < 0) goto io_err; if (mfa_w64(f, 0)) goto io_err;
        long size_pos = ftell(f); if (size_pos < 0) goto io_err; if (mfa_w64(f, 0)) goto io_err;

        uint8_t zeros[12] = {0};
        if (mfa_write_exact(f, zeros, 12)) goto io_err;

        /* 2) TOC start */
        long toc_off_l = ftell(f); if (toc_off_l < 0) goto io_err;

        /* 3) Write TOC entries, keeping positions for data_offset backpatch */
        uint64_t *dataoff_patch = (uint64_t *)malloc(n * sizeof *dataoff_patch);
        if (!dataoff_patch) { perror("malloc"); goto io_err; }

        for (size_t i = 0; i < n; ++i) {
            const char *name = files[i].path ? mfa_basename(files[i].path) : "";
            size_t name_len = strlen(name);

            if (mfa_w32(f, (uint32_t)name_len)) { free(dataoff_patch); goto io_err; }
            if (name_len && mfa_write_exact(f, name, name_len)) { free(dataoff_patch); goto io_err; }

            /* Keep orig_size==stored_size for now (no real compression). */
            if (mfa_w64(f, (uint64_t)files[i].len)) { free(dataoff_patch); goto io_err; }
            if (mfa_w64(f, (uint64_t)files[i].len)) { free(dataoff_patch); goto io_err; }

            long p = ftell(f); if (p < 0) { free(dataoff_patch); goto io_err; }
            dataoff_patch[i] = (uint64_t)p;
            if (mfa_w64(f, 0)) { free(dataoff_patch); goto io_err; } /* placeholder data_offset */

            uint32_t per_flags = 0;
            if (flags & MFA_COMPRESS) per_flags |= (1u << 0);
            if (flags & MFA_ENCRYPT)  per_flags |= (1u << 1);
            if (mfa_w32(f, per_flags)) { free(dataoff_patch); goto io_err; }

            uint16_t alg_id = (flags & MFA_ENCRYPT) ? 100u : 0u;
            if (mfa_w16(f, alg_id)) { free(dataoff_patch); goto io_err; }

            if (mfa_w16(f, 0)) { free(dataoff_patch); goto io_err; } /* meta_len=0 */
        }

        /* 4) Align to data section */
        const unsigned ALIGN = 16;
        long after_toc = ftell(f); if (after_toc < 0) { free(dataoff_patch); goto io_err; }
        long long data_off_ll = mfa_pad_to(f, (unsigned long long)after_toc, ALIGN);
        if (data_off_ll < 0) { free(dataoff_patch); goto io_err; }
        uint64_t cursor = (uint64_t)data_off_ll;

        /* 5) Write payloads; backpatch each data_offset */
        for (size_t i = 0; i < n; ++i) {
            if (fseek(f, (long)dataoff_patch[i], SEEK_SET) != 0) { free(dataoff_patch); goto io_err; }
            if (mfa_w64(f, cursor)) { free(dataoff_patch); goto io_err; }

            if (fseek(f, (long)cursor, SEEK_SET) != 0) { free(dataoff_patch); goto io_err; }
            if (files[i].len && mfa_write_exact(f, files[i].buf, files[i].len)) { free(dataoff_patch); goto io_err; }

            cursor += (uint64_t)files[i].len;
            long long nc = mfa_pad_to(f, cursor, ALIGN);
            if (nc < 0) { free(dataoff_patch); goto io_err; }
            cursor = (uint64_t)nc;
        }

        /* 6) Finalize header fields */
        uint64_t toc_off = (uint64_t)toc_off_l;
        uint64_t data_off = (uint64_t)data_off_ll;
        uint64_t arch_sz = (uint64_t)ftell(f);

        if (fseek(f, toc_pos,  SEEK_SET) != 0) { free(dataoff_patch); goto io_err; }
        if (mfa_w64(f, toc_off)) { free(dataoff_patch); goto io_err; }

        if (fseek(f, data_pos, SEEK_SET) != 0) { free(dataoff_patch); goto io_err; }
        if (mfa_w64(f, data_off)) { free(dataoff_patch); goto io_err; }

        if (fseek(f, size_pos, SEEK_SET) != 0) { free(dataoff_patch); goto io_err; }
        if (mfa_w64(f, arch_sz)) { free(dataoff_patch); goto io_err; }

        free(dataoff_patch);
    }

    if (fclose(f) != 0) { perror("fclose"); return -1; }
    return 0;

io_err:
    perror("I/O");
    if (f) fclose(f);
    return -1;
}

/* ---------------- TOC reader (internal) ---------------- */

typedef struct {
    char     *name;
    uint64_t  orig_size;
    uint64_t  stored_size;
    uint64_t  data_offset;
    uint32_t  flags;
    uint16_t  alg_id;
} mfa_toc_entry;

static void toc_free(mfa_toc_entry *e, size_t n) {
    if (!e) return;
    for (size_t i = 0; i < n; ++i) free(e[i].name);
    free(e);
}

static int toc_read(FILE *fp, mfa_toc_entry **out, size_t *out_n, uint64_t *out_data_off) {
    char magic[8];
    if (mfa_read_exact(fp, magic, 8)) return -1;
    if (memcmp(magic, "MFAARCH", 7) != 0 || magic[7] != '\0') return -1;

    uint16_t version=0, hdr_sz=0;
    uint32_t gflags=0, count=0;
    uint64_t toc_off=0, data_off=0, arch_sz=0;
    uint8_t  zeros[12];

    if (mfa_r16(fp, &version) || mfa_r16(fp, &hdr_sz) ||
        mfa_r32(fp, &gflags)  || mfa_r32(fp, &count)  ||
        mfa_r64(fp, &toc_off) || mfa_r64(fp, &data_off) || mfa_r64(fp, &arch_sz) ||
        mfa_read_exact(fp, zeros, 12))
        return -1;

    if (version != 1 || hdr_sz != 56) return -1;

    if (fseek(fp, (long)toc_off, SEEK_SET) != 0) return -1;
    mfa_toc_entry *ents = (mfa_toc_entry *)calloc(count, sizeof *ents);
    if (!ents) return -1;

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t name_len = 0;
        if (mfa_r32(fp, &name_len)) { toc_free(ents, i); return -1; }

        char *name = (char *)malloc(name_len + 1);
        if (!name && name_len) { toc_free(ents, i); return -1; }
        if (name_len && mfa_read_exact(fp, name, name_len)) { free(name); toc_free(ents, i); return -1; }
        if (name) name[name_len] = '\0';
        if (name) mfa_sanitize(name);

        uint64_t orig=0, stored=0, off=0;
        uint32_t flags=0; uint16_t alg=0, meta_len=0;

        if (mfa_r64(fp, &orig)   || mfa_r64(fp, &stored) ||
            mfa_r64(fp, &off)    || mfa_r32(fp, &flags)  ||
            mfa_r16(fp, &alg)    || mfa_r16(fp, &meta_len)) {
            free(name); toc_free(ents, i); return -1;
        }

        if (meta_len && fseek(fp, (long)meta_len, SEEK_CUR) != 0) { free(name); toc_free(ents, i); return -1; }

        ents[i].name        = name ? name : strdup("");
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

/* ---------------- List & Extract ---------------- */

int mfa_list(const char *archive_path) {
    FILE *fp = fopen(archive_path, "rb");
    if (!fp) { perror(archive_path); return -1; }

    mfa_toc_entry *ents = NULL; size_t n = 0; uint64_t data_off = 0;
    if (toc_read(fp, &ents, &n, &data_off)) { fclose(fp); return -1; }

    printf("Archive: %s\n", archive_path);
    printf("%-6s  %-10s  %-10s  %s\n", "Index", "OrigSize", "Stored", "Name");
    for (size_t i = 0; i < n; ++i) {
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

static int stream_copy_to(const char *out_path, FILE *fp, uint64_t len) {
    FILE *out = fopen(out_path, "wb");
    if (!out) { perror(out_path); return -1; }

    uint8_t *buf = (uint8_t *)malloc(64 * 1024);
    if (!buf) { perror("malloc"); fclose(out); return -1; }

    uint64_t remaining = len;
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
    FILE *fp = fopen(archive_path, "rb");
    if (!fp) { perror(archive_path); return -1; }

    mfa_toc_entry *ents = NULL; size_t n = 0; uint64_t data_off = 0;
    if (toc_read(fp, &ents, &n, &data_off)) { fclose(fp); return -1; }

    for (size_t i = 0; i < n; ++i) {
        if (fseek(fp, (long)ents[i].data_offset, SEEK_SET) != 0) {
            perror("fseek"); toc_free(ents, n); fclose(fp); return -1;
        }

        char *out_path = mfa_join_path(out_dir, ents[i].name);
        if (!out_path) { perror("malloc"); toc_free(ents, n); fclose(fp); return -1; }

        /* NOTE: If you later keep real compression/encryption,
                 read into a temp buffer, reverse transforms, then write. */
        if (stream_copy_to(out_path, fp, ents[i].stored_size)) {
            fprintf(stderr, "Failed writing %s\n", out_path);
            free(out_path); toc_free(ents, n); fclose(fp); return -1;
        }

        free(out_path);
    }

    toc_free(ents, n);
    fclose(fp);
    return 0;
}
