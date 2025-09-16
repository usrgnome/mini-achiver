#include "mfa_write.h"
#include "mfa_types.h"
#include <stdlib.h>
#include <string.h>

/* Little-endian writers, no <stdint.h> needed */
int write_u32_le(FILE *fp, unsigned long v) {
    unsigned char b[4];
    b[0] = (unsigned char)((v >> 0)  & 0xFF);
    b[1] = (unsigned char)((v >> 8)  & 0xFF);
    b[2] = (unsigned char)((v >> 16) & 0xFF);
    b[3] = (unsigned char)((v >> 24) & 0xFF);
    return fwrite(b, 1, 4, fp) == 4 ? 0 : -1;
}

int write_u16_le(FILE *fp, unsigned long v) {
    unsigned char b[2];
    b[0] = (unsigned char)(v & 0xFFu);
    b[1] = (unsigned char)((v >> 8) & 0xFFu);
    return fwrite(b, 1, 2, fp) == 2 ? 0 : -1;
}

int write_u64_le(FILE *fp, unsigned long long v) {
    unsigned char b[8];
    b[0]=(unsigned char)((v>>0)&0xFF);  b[1]=(unsigned char)((v>>8)&0xFF);
    b[2]=(unsigned char)((v>>16)&0xFF); b[3]=(unsigned char)((v>>24)&0xFF);
    b[4]=(unsigned char)((v>>32)&0xFF); b[5]=(unsigned char)((v>>40)&0xFF);
    b[6]=(unsigned char)((v>>48)&0xFF); b[7]=(unsigned char)((v>>56)&0xFF);
    return fwrite(b, 1, 8, fp) == 8 ? 0 : -1;
}

int write_bytes(FILE *fp, const void *buf, size_t len) {
    return fwrite(buf, 1, len, fp) == len ? 0 : -1;
}

long long pad_to(FILE *fp, unsigned long long off, unsigned long align) {
    unsigned long pad = (unsigned long)((align - (off % align)) % align);
    static const unsigned char zeros[16] = {0};
    while (pad) {
        unsigned long chunk = pad > sizeof zeros ? (unsigned long)sizeof zeros : pad;
        if (fwrite(zeros, 1, chunk, fp) != chunk) return -1;
        off += chunk; pad -= chunk;
    }
    return (long long)off;
}

/* ---------------- Archive writer ---------------- */

/*
Global header (56 bytes total; LE):
  0:  magic[8] = "MFAARCH\0"
  8:  u16 version = 1
 10:  u16 header_size = 56
 12:  u32 global_flags = 0
 16:  u32 file_count
 20:  u64 toc_offset
 28:  u64 data_offset
 36:  u64 archive_size
 44:  12 bytes reserved = 0
TOC entry (per file, variable due to name/meta):
  u32 name_len
  name_len bytes of UTF-8 name (no NUL)
  u64 orig_size
  u64 stored_size
  u64 data_offset  (absolute, will be backpatched)
  u32 per_file_flags (bit0=compressed, bit1=encrypted)
  u16 alg_id       (0=raw, 100=your-enc; adjust as you wish)
  u16 meta_len
  meta_len bytes of metadata (none here)
Data blobs:
  each file's stored bytes at its data_offset, aligned (16B)
*/

int build_archive(const char *path, enc_file_t files[], size_t file_count) {
    if (!path || !files || file_count == 0) return -1;

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }

    unsigned long long *dataoff_field_pos = NULL;

    /* ---- 1) Write placeholder global header ---- */
    const char magic[8] = { 'M','F','A','A','R','C','H','\0' };
    if (write_bytes(f, magic, 8)) goto io_err;
    if (write_u16_le(f, 1)) goto io_err;           /* version */
    if (write_u16_le(f, 56)) goto io_err;          /* header size */
    if (write_u32_le(f, 0)) goto io_err;           /* global flags */
    if (write_u32_le(f, (unsigned long)file_count)) goto io_err;

    /* Remember header fields’ positions to backpatch */
    long toc_off_pos  = ftell(f); if (toc_off_pos  < 0) goto io_err;
    if (write_u64_le(f, 0)) goto io_err;           /* toc_offset placeholder */
    long data_off_pos = ftell(f); if (data_off_pos < 0) goto io_err;
    if (write_u64_le(f, 0)) goto io_err;           /* data_offset placeholder */
    long size_pos     = ftell(f); if (size_pos     < 0) goto io_err;
    if (write_u64_le(f, 0)) goto io_err;           /* archive_size placeholder */
    { unsigned char z[12] = {0}; if (write_bytes(f, z, 12)) goto io_err; } /* reserved */

    /* ---- 2) TOC start ---- */
    long toc_offset_l = ftell(f);
    if (toc_offset_l < 0) goto io_err;
    unsigned long long toc_offset = (unsigned long long)toc_offset_l;

    /* We’ll need to backpatch each entry’s data_offset: remember positions */
    dataoff_field_pos = malloc(file_count * sizeof *dataoff_field_pos);
    if (!dataoff_field_pos) { perror("malloc"); goto io_err; }

    /* ---- 3) Write TOC entries ---- */
    for (size_t i = 0; i < file_count; ++i) {
        const char *name = files[i].path ? basename_c(files[i].path) : "";
        size_t name_len  = strlen(name);

        /* which bytes to store? prefer encrypted if present */
        const unsigned char *payload = files[i].edata ? files[i].edata : files[i].data;
        size_t stored_len = files[i].edata ? files[i].elen : files[i].len;

        /* per-file flags */
        unsigned long per_flags = 0;
        if (files[i].edata) per_flags |= (1u << 1); /* encrypted */

        unsigned long alg_id = files[i].edata ? 100u : 0u; /* example IDs */

        if (write_u32_le(f, (unsigned long)name_len)) goto io_err;
        if (name_len && write_bytes(f, name, name_len)) goto io_err;

        if (write_u64_le(f, (unsigned long long)files[i].len)) goto io_err;   /* orig_size */
        if (write_u64_le(f, (unsigned long long)stored_len)) goto io_err;     /* stored_size */

        /* placeholder for data_offset; remember where it is */
        long pos = ftell(f); if (pos < 0) goto io_err;
        dataoff_field_pos[i] = (unsigned long long)pos;
        if (write_u64_le(f, 0)) goto io_err;  /* to be patched later */

        if (write_u32_le(f, per_flags)) goto io_err;
        if (write_u16_le(f, alg_id)) goto io_err;

        /* no metadata for now */
        if (write_u16_le(f, 0)) goto io_err;
        (void)payload; /* used later when writing data */
    }

    /* ---- 4) Align to data section start ---- */
    const unsigned long ALIGN = 16;
    long after_toc_l = ftell(f); if (after_toc_l < 0) goto io_err;
    long long data_offset_ll = pad_to(f, (unsigned long long)after_toc_l, ALIGN);
    if (data_offset_ll < 0) goto io_err;
    unsigned long long data_offset = (unsigned long long)data_offset_ll;

    /* ---- 5) Write file data blobs and backpatch each data_offset ---- */
    unsigned long long cursor = data_offset;

    for (size_t i = 0; i < file_count; ++i) {
        const unsigned char *payload = files[i].edata ? files[i].edata : files[i].data;
        size_t stored_len = files[i].edata ? files[i].elen : files[i].len;

        /* Backpatch this entry's data_offset in the TOC */
        if (fseek(f, (long)dataoff_field_pos[i], SEEK_SET) != 0) goto io_err;
        if (write_u64_le(f, cursor)) goto io_err;

        /* Seek to write position and write payload */
        if (fseek(f, (long)cursor, SEEK_SET) != 0) goto io_err;
        if (stored_len && write_bytes(f, payload, stored_len)) goto io_err;

        cursor += (unsigned long long)stored_len;
        long long new_cursor = pad_to(f, cursor, ALIGN);
        if (new_cursor < 0) goto io_err;
        cursor = (unsigned long long)new_cursor;
    }

    /* ---- 6) Finalize header (archive size, toc_offset, data_offset) ---- */
    unsigned long long archive_size = (unsigned long long)ftell(f);

    if (fseek(f, toc_off_pos, SEEK_SET) != 0) goto io_err;
    if (write_u64_le(f, toc_offset)) goto io_err;

    if (fseek(f, data_off_pos, SEEK_SET) != 0) goto io_err;
    if (write_u64_le(f, data_offset)) goto io_err;

    if (fseek(f, size_pos, SEEK_SET) != 0) goto io_err;
    if (write_u64_le(f, archive_size)) goto io_err;

    if (fclose(f) != 0) { perror("fclose"); free(dataoff_field_pos); return -1; }
    free(dataoff_field_pos);
    return 0;

io_err:
    perror("I/O");
    if (f) fclose(f);
    /* dataoff_field_pos may be NULL-safe */
    free(dataoff_field_pos);
    return -1;
}