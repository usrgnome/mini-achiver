#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* tiny helper: show the first few bytes so user can see it worked */
static void print_preview(const unsigned char *buf, size_t n) {
    size_t show = n < 16 ? n : 16;
    printf("  preview (%zu byte%s):", show, show == 1 ? "" : "s");
    for (size_t i = 0; i < show; ++i) {
        printf(" %02X", buf[i]);
    }
    if (n > show) printf(" ...");
    printf("\n");
}

static int read_one(const char *path) {
    size_t len = 0;
    unsigned char *buf = load_file(path, &len);
    if (!buf) {
        fprintf(stderr, "Failed to read: %s\n", path);
        return 1;
    }
    printf("Read '%s' (%zu bytes)\n", path, len);
    print_preview(buf, len);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    /* Usage:
       - mfa_read file1 [file2 ...]
       - or run with no args and enter paths interactively
    */
    if (argc >= 2) {
        int rc = 0;
        for (int i = 1; i < argc; ++i) {
            rc |= read_one(argv[i]);
        }
        return rc ? 1 : 0;
    }

    /* No args: ask user for file paths */
    char line[4096];
    printf("Enter one or more file paths (separated by spaces), then press Enter:\n> ");
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "No input received.\n");
        return 1;
    }

    /* tokenize by whitespace */
    int any = 0;
    for (char *tok = strtok(line, " \t\r\n"); tok; tok = strtok(NULL, " \t\r\n")) {
        any = 1;
        read_one(tok);
    }
    if (!any) {
        fprintf(stderr, "No file paths provided.\n");
        return 1;
    }
    return 0;
}
