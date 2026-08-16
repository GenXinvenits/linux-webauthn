#include "credential.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int credential_enumerate(
    const char *base_directory,
    CredentialMatchCallback callback,
    void *user_data)
{
    char credentials_dir[4096];
    DIR *dir;
    struct dirent *entry;

    if (!base_directory || !callback)
        return -1;

    if (snprintf(
            credentials_dir,
            sizeof(credentials_dir),
            "%s/credentials",
            base_directory) >= (int)sizeof(credentials_dir))
        return -1;

    dir = opendir(credentials_dir);
    if (!dir) {
        if (errno == ENOENT)
            return 0;
        perror(credentials_dir);
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        size_t name_len;
        uint8_t id[TPM_CREDENTIAL_ID_SIZE];
        WebAuthnCredential credential;
        int result;

        if (entry->d_name[0] == '.')
            continue;

        name_len = strlen(entry->d_name);
        if (name_len != TPM_CREDENTIAL_ID_SIZE * 2)
            continue;

        for (size_t i = 0; i < TPM_CREDENTIAL_ID_SIZE; i++) {
            int hi = hex_value(entry->d_name[i * 2]);
            int lo = hex_value(entry->d_name[i * 2 + 1]);

            if (hi < 0 || lo < 0) {
                name_len = 0;
                break;
            }

            id[i] = (uint8_t)((hi << 4) | lo);
        }

        if (name_len == 0)
            continue;

        credential_init(&credential);

        if (credential_load(
                &credential,
                base_directory,
                id,
                sizeof(id)) != 0) {
            credential_free(&credential);
            continue;
        }

        result = callback(&credential, user_data);
        credential_free(&credential);

        if (result != 0) {
            closedir(dir);
            return result;
        }
    }

    closedir(dir);
    return 0;
}
