#include "mfa_util.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ---- I/O helpers ---- */
int mfa_read_exact(FILE *fp, void *buf, size_t n) {
    return fread(buf, 1, n, fp) == n ? 0 : -1;
}
int mfa_write_exact(FILE *fp, const void *buf, size_t n) {
    return fwrite(buf, 1, n, fp) == n ? 0 : -1;
}

/* ---- LE writers ---- */
int mfa_w16(FILE *fp, uint16_t v) {
    uint8_t b[2] = { v & 0xFF, (uint8_t)(v >> 8) };
    return mfa_write_exact(fp, b, 2);
}
int mfa_w32(FILE *fp, uint32_t v) {
    uint8_t b[4] = { v, v>>8, v>>16, v>>24 };
    return mfa_write_exact(fp, b, 4);
}
int mfa_w64(FILE *fp, uint64_t v) {
    uint8_t b[8] = {
        v, v>>8, v>>16, v>>24,
        v>>32, v>>40, v>>48, v>>56
    };
    return mfa_write_exact(fp, b, 8);
}

/* ---- LE readers ---- */
int mfa_r16(FILE *fp, uint16_t *out) {
    uint8_t b[2]; if (mfa_read_exact(fp,b,2)) return -1;
    *out = (uint16_t)(b[0] | (b[1] << 8)); return 0;
}
int mfa_r32(FILE *fp, uint32_t *out) {
    uint8_t b[4]; if (mfa_read_exact(fp,b,4)) return -1;
    *out = (uint32_t)b[0] | ((uint32_t)b[1]<<8)
         | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
    return 0;
}
int mfa_r64(FILE *fp, uint64_t *out) {
    uint8_t b[8]; if (mfa_read_exact(fp,b,8)) return -1;
    *out = (uint64_t)b[0] | ((uint64_t)b[1]<<8) | ((uint64_t)b[2]<<16)
         | ((uint64_t)b[3]<<24) | ((uint64_t)b[4]<<32) | ((uint64_t)b[5]<<40)
         | ((uint64_t)b[6]<<48) | ((uint64_t)b[7]<<56);
    return 0;
}

/* ---- Alignment ---- */
long long mfa_pad_to(FILE *fp, unsigned long long off, unsigned align) {
    unsigned pad = (unsigned)((align - (off % align)) % align);
    static const uint8_t zeros[16] = {0};
    while (pad) {
        unsigned chunk = pad > sizeof zeros ? (unsigned)sizeof zeros : pad;
        if (fwrite(zeros,1,chunk,fp) != chunk) return -1;
        off += chunk; pad -= chunk;
    }
    return (long long)off;
}

/* ---- Path helpers ---- */
const char *mfa_basename(const char *p) {
    const char *last = p;
    const char *s = p;
    for (; *s; ++s) if (*s=='/'||*s=='\\') last = s+1;
    return last;
}
void mfa_sanitize(char *s) {
    for (; *s; ++s) if (*s=='/'||*s=='\\'||*s==':') *s='_';
}
char *mfa_join_path(const char *dir, const char *name) {
    if (!dir || !*dir) return strdup(name);
    size_t a=strlen(dir), b=strlen(name);
    int need_sep = (a>0 && dir[a-1]!='/');
    char *p = malloc(a+need_sep+b+1);
    if (!p) return NULL;
    memcpy(p, dir, a);
    if (need_sep) p[a++]='/';
    memcpy(p+a, name, b);
    p[a+b]='\0';
    return p;
}
