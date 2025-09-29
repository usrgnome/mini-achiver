#include "linked_list.h"
#include "mfa.h"
#include <stdio.h>
#include <stdlib.h>

/* Usage:
   ./mfa <archive.mfa> <pass> <file1> [file2 ...]
*/
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <out_archive> <pass> <file1> [file2...]\n", argv[0]);
        return 1;
    }

    const char *archive_path = argv[1];
    const char *pass         = argv[2];
    size_t file_count        = (size_t)(argc - 3);
    size_t i;

    /* Build file table */
    linked_list *files = ll_create();

    if (!files) { perror("calloc"); return 1; }
    for (i = 0; i < file_count; ++i) {
        mfa_file *f = (mfa_file *)malloc(sizeof(mfa_file));
        f->path = argv[3 + i];
        f->buf  = NULL;
        f->len  = 0;
        ll_append(files, f);
    }

    /* Sort paths alphabetically by file name for consistent order */
    if(mfa_sort_paths(files) != 0) {
        fprintf(stderr, "Failed to sort input files.\n");
        ll_free(files);
        return 1;
    }

    /* Load files into memory */
    if (mfa_load_all(files) != 0) {
        fprintf(stderr, "Failed to load input files.\n");
        ll_free(files);
        return 1;
    }

    /* Pack archive with both compression+encryption flags (compression is no-op for now) */
    if (mfa_pack(archive_path, files, pass, MFA_COMPRESS | MFA_ENCRYPT) != 0) {
        fprintf(stderr, "Failed to create archive.\n");
        mfa_free_all(files);
        ll_free(files);
        return 1;
    }

    printf("Archive created: %s\n", archive_path);

    /* Clean up file buffers */
    mfa_free_all(files);
    ll_free(files);

    /* List archive contents */
    printf("\nListing archive:\n");
    if (mfa_list(archive_path) != 0) {
        fprintf(stderr, "Listing failed.\n");
        return 1;
    }

    /* Extract archive */
    printf("\nExtracting archive:\n");
    if (mfa_extract_all(archive_path, ".") != 0) {
        fprintf(stderr, "Extraction failed.\n");
        return 1;
    }

    printf("Extraction complete.\n");
    return 0;
}
