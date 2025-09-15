#include "mfa_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mfa_encrypt.h"

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

static int read_one(const char *path)
{
    size_t len = 0;
    unsigned char *buf = load_file(path, &len);
    if (!buf)
    {
        fprintf(stderr, "Failed to read: %s\n", path);
        return 1;
    }
    printf("Read '%s' (%zu bytes)\n", path, len);
    print_preview(buf, len);
    free(buf);
    return 0;
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
    /* Usage:
       - mfa_read phrase file1 [file2 ...]
       - or run with no args and enter paths interactively
    */
    if (argc >= 3)
    {
        int phrase_length = strlen(argv[1]);

        if (phrase_length == 0)
        {
            printf("Passphrase must be provided.\n");
            return 1;
        }

        int total_files = argc - 2;
        enc_file_t files[total_files];
        for (int i = 2, index = 0; i < argc; ++i, index++) files[index].path = argv[i];
        encrypt(argv[1], phrase_length, files, total_files);
    }
    else
    {
        printf("Usage: %s file1 [file2 ...]\n", argv[0]);
        printf("Or run with no args and enter paths interactively.\n");
        return 1;
    }

    return 0;
}
