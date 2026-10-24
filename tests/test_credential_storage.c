#include "credential.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_METADATA_MAGIC 0x474E5743U
#define TEST_METADATA_VERSION 1U

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t credential_id_len;
    uint32_t user_handle_len;
    uint32_t sign_count;
    char rp_id[WEBAUTHN_RP_ID_MAX];
    char user_name[WEBAUTHN_USER_NAME_MAX];
    char display_name[WEBAUTHN_DISPLAY_NAME_MAX];
    uint8_t credential_id[TPM_CREDENTIAL_ID_SIZE];
    uint8_t user_handle[WEBAUTHN_USER_HANDLE_MAX];
} TestCredentialMetadata;

static unsigned int tpm_load_calls;

void tpm_credential_free(TpmCredential *credential)
{
    if (!credential)
        return;
    free(credential->public_blob);
    free(credential->private_blob);
    memset(credential, 0, sizeof(*credential));
}

int tpm_load_credential(TpmCredential *credential, const char *directory)
{
    (void)credential;
    (void)directory;
    tpm_load_calls++;
    return -1;
}

int tpm_create_credential(TpmContext *ctx, TpmCredential *credential)
{
    (void)ctx;
    (void)credential;
    return -1;
}

int tpm_save_credential(const TpmCredential *credential, const char *directory)
{
    (void)credential;
    (void)directory;
    return -1;
}

static int write_all(int fd, const void *data, size_t size)
{
    const unsigned char *p = data;
    size_t offset = 0;
    while (offset < size) {
        ssize_t n = write(fd, p + offset, size - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        offset += (size_t)n;
    }
    return 0;
}

static int write_file(const char *path, const void *data, size_t size, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return -1;
    int result = write_all(fd, data, size);
    if (fchmod(fd, mode) != 0)
        result = -1;
    if (close(fd) != 0)
        result = -1;
    return result;
}

static int make_layout(
    char *base, size_t base_size, char *credential_dir, size_t credential_dir_size,
    char *metadata_path, size_t metadata_path_size, const uint8_t id[TPM_CREDENTIAL_ID_SIZE])
{
    char template[] = "/tmp/linux-webauthn-storage-test-XXXXXX";
    char credentials_dir[4096];
    char id_hex[TPM_CREDENTIAL_ID_SIZE * 2 + 1];

    if (!mkdtemp(template))
        return -1;
    if (snprintf(base, base_size, "%s", template) >= (int)base_size)
        return -1;
    if (snprintf(credentials_dir, sizeof(credentials_dir), "%s/credentials", base)
        >= (int)sizeof(credentials_dir))
        return -1;
    if (mkdir(credentials_dir, 0700) != 0)
        return -1;
    if (credential_id_hex(id, TPM_CREDENTIAL_ID_SIZE, id_hex, sizeof(id_hex)) != 0)
        return -1;
    if (snprintf(credential_dir, credential_dir_size, "%s/%s", credentials_dir, id_hex)
        >= (int)credential_dir_size)
        return -1;
    if (mkdir(credential_dir, 0700) != 0)
        return -1;
    if (snprintf(metadata_path, metadata_path_size, "%s/metadata", credential_dir)
        >= (int)metadata_path_size)
        return -1;
    return 0;
}

static void cleanup_layout(const char *base, const char *credential_dir,
                           const char *metadata_path, const char *target_path)
{
    if (metadata_path)
        unlink(metadata_path);
    if (target_path)
        unlink(target_path);
    if (credential_dir) {
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/public", credential_dir) < (int)sizeof(path))
            unlink(path);
        if (snprintf(path, sizeof(path), "%s/private", credential_dir) < (int)sizeof(path))
            unlink(path);
        rmdir(credential_dir);
    }
    if (base) {
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/credentials", base) < (int)sizeof(path))
            rmdir(path);
        rmdir(base);
    }
}

static int test_metadata(void)
{
    uint8_t id[TPM_CREDENTIAL_ID_SIZE];
    char base[4096] = {0}, credential_dir[4096] = {0};
    char metadata_path[4096] = {0}, target_path[4096] = {0};
    TestCredentialMetadata metadata;
    WebAuthnCredential credential;
    int failed = 0;

    memset(id, 0x12, sizeof(id));
    memset(&metadata, 0, sizeof(metadata));
    metadata.magic = TEST_METADATA_MAGIC;
    metadata.version = TEST_METADATA_VERSION;
    metadata.credential_id_len = TPM_CREDENTIAL_ID_SIZE;
    metadata.user_handle_len = 1;
    memcpy(metadata.credential_id, id, sizeof(id));
    metadata.user_handle[0] = 1;
    strcpy(metadata.rp_id, "example.com");
    strcpy(metadata.user_name, "test-user");
    strcpy(metadata.display_name, "Test User");

    if (make_layout(base, sizeof(base), credential_dir, sizeof(credential_dir),
                    metadata_path, sizeof(metadata_path), id) != 0) {
        fprintf(stderr, "storage test setup failed\n");
        return 1;
    }
    credential_init(&credential);

    /* Valid metadata must pass metadata validation and reach the TPM loader. */
    if (write_file(metadata_path, &metadata, sizeof(metadata), 0600) != 0) {
        fprintf(stderr, "could not write valid metadata\n");
        failed = 1;
    } else {
        (void)credential_load(&credential, base, id, sizeof(id));
        if (tpm_load_calls != 1) {
            fprintf(stderr, "valid metadata did not reach TPM loader\n");
            failed = 1;
        }
    }

    /* A symlink must be rejected before the target can be parsed. */
    unlink(metadata_path);
    if (snprintf(target_path, sizeof(target_path), "%s/target", credential_dir)
        >= (int)sizeof(target_path) ||
        write_file(target_path, &metadata, sizeof(metadata), 0600) != 0 ||
        symlink(target_path, metadata_path) != 0) {
        fprintf(stderr, "could not prepare symlink test\n");
        failed = 1;
    } else {
        (void)credential_load(&credential, base, id, sizeof(id));
        if (tpm_load_calls != 1) {
            fprintf(stderr, "symlinked metadata was accepted\n");
            failed = 1;
        }
    }

    /* Private metadata with a zero-length user handle is malformed. */
    unlink(metadata_path);
    unlink(target_path);
    metadata.user_handle_len = 0;
    if (write_file(metadata_path, &metadata, sizeof(metadata), 0600) != 0) {
        fprintf(stderr, "could not write malformed metadata\n");
        failed = 1;
    } else {
        (void)credential_load(&credential, base, id, sizeof(id));
        if (tpm_load_calls != 1) {
            fprintf(stderr, "malformed metadata was accepted\n");
            failed = 1;
        }
    }

    /* Group/world-readable metadata is rejected. */
    unlink(metadata_path);
    metadata.user_handle_len = 1;
    if (write_file(metadata_path, &metadata, sizeof(metadata), 0644) != 0) {
        fprintf(stderr, "could not write permission test metadata\n");
        failed = 1;
    } else {
        (void)credential_load(&credential, base, id, sizeof(id));
        if (tpm_load_calls != 1) {
            fprintf(stderr, "non-private metadata was accepted\n");
            failed = 1;
        }
    }

    credential_free(&credential);
    cleanup_layout(base, credential_dir, metadata_path, target_path);
    return failed;
}

int main(void)
{
    if (test_metadata() != 0)
        return EXIT_FAILURE;
    puts("credential storage security tests passed");
    return EXIT_SUCCESS;
}
