#include "mfa_util.h"
#include "mfa_write.h"
#include "mfa_encrypt.h"
#include "mfa_compress.h"
#include "mfa_read.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* tiny helper: show the first few bytes so user can see it worked */
static void print_preview(const unsigned char *buf, size_t n)
{
    size_t show = n < 16 ? n : 16;
    printf("  preview (%zu byte%s):", show, show == 1 ? "" : "s");
    for (size_t i = 0; i < show; ++i)
    {
        printf(" %02X", buf[i]);
    }
    if (n > show)
        printf(" ...");
    printf("\n");
}

void encrypt(char *pass, size_t pass_len, enc_file_t files[], size_t file_count)
{

    for (size_t i = 0; i < file_count; ++i)
    {
        size_t len = 0;
        unsigned char *buf = load_file(files[i].path, &len);
        files[i].data = buf;
        files[i].len = len;
    }
}

// create a encrypted version of file
int main(int argc, char **argv)
{
    /* Usage: mfa_read OUT_FILE PASS FILE1 [FILE2 ...] */
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <out_file> <pass> <file1> [file2 ...]\n", argv[0]);
        return 1;
    }

    const char *out_path = argv[1];
    const char *pass     = argv[2];
    const int   total    = argc - 3;

    if (total <= 0) {
        fprintf(stderr, "No input files provided.\n");
        return 1;
    }

    if (!validate_pass(pass)) {
        fprintf(stderr, "Passphrase invalid or missing.\n");
        return 1;
    }

    /* heap-allocate the file table (avoid VLA/stack blowups) */
    enc_file_t *files = (enc_file_t *)calloc((size_t)total, sizeof *files);
    if (!files) {
        perror("calloc");
        return 1;
    }

    /* populate paths first */
    for (int i = 0; i < total; ++i) {
        files[i].path = argv[3 + i];
        files[i].data = NULL;
        files[i].len  = 0;
    }

    int rc = 1; /* assume failure */
    /* Load → Encrypt → Archive, with cleanup on any error */
    if (load_all(files, (size_t)total) != 0) {
        goto cleanup;
    }

    if (compress_files(files, (size_t)total) != 0) {
        fprintf(stderr, "Compression failed.\n");
        goto cleanup;
    } 

    if (enc_files(files, (size_t)total, pass) != 0) {
        fprintf(stderr, "Encryption failed.\n");
        goto cleanup;
    }

    if (build_archive(out_path, files, (size_t)total) != 0) {
        fprintf(stderr, "Failed to write archive: %s\n", out_path);
        goto cleanup;
    }

    rc = 0; /* success */

cleanup:
    free_files(files, (size_t)total);
    free(files);


    /* testing try to extract archive */
    printf("Testing extraction of archive: %s\n", out_path);
    if (mfa_extract_all(out_path, "") != 0) {
        fprintf(stderr, "Failed to extract archive: %s\n", out_path);
        return 1;
    }

    return rc;
}
