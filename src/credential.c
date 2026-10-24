#define _GNU_SOURCE
#include "credential.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Write private state atomically, never following a symlink at the target. */
static int write_file_atomic(const char *path, const void *data, size_t size)
{
    char temporary[4096];
    int fd = -1, saved_errno = 0;
    size_t offset = 0;
    static unsigned long sequence;
    if (!path || (!data && size != 0)) return -1;
    for (unsigned int attempt = 0; attempt < 32; attempt++) {
        int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%lu",
                         path, (long)getpid(), ++sequence);
        if (n < 0 || (size_t)n >= sizeof(temporary)) return -1;
        fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                  O_NOFOLLOW, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) { perror(temporary); return -1; }
    }
    if (fd < 0) return -1;
    while (offset < size) {
        ssize_t n = write(fd, (const char *)data + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { saved_errno = errno ? errno : EIO; goto fail; }
        offset += (size_t)n;
    }
    if (fsync(fd) != 0) { saved_errno = errno; goto fail; }
    if (close(fd) != 0) { fd = -1; saved_errno = errno; goto fail; }
    fd = -1;
    if (rename(temporary, path) != 0) { saved_errno = errno; goto fail; }
    {
        char parent[4096];
        const char *slash = strrchr(path, '/');
        if (slash) {
            size_t n = (size_t)(slash - path);
            if (n == 0) n = 1;
            if (n < sizeof(parent)) {
                memcpy(parent, path, n); parent[n] = '\0';
                int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                 O_NOFOLLOW);
                if (dirfd >= 0) { (void)fsync(dirfd); close(dirfd); }
            }
        }
    }
    return 0;
fail:
    if (fd >= 0) close(fd);
    unlink(temporary);
    errno = saved_errno;
    perror("secure file write");
    return -1;
}

static int open_private_regular_file(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0) {
        fprintf(stderr, "Refusing unsafe credential file: %s\n", path);
        close(fd); errno = EPERM; return -1;
    }
    return fd;
}

#define CREDENTIAL_METADATA_MAGIC   0x474E5743U
#define CREDENTIAL_METADATA_VERSION 1U

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
} CredentialMetadata;

static int ensure_directory(const char *path)
{
    struct stat st;
    if (!path || !*path) return -1;
    if (lstat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid()) {
            fprintf(stderr, "Refusing unsafe credential directory: %s\n", path);
            return -1;
        }
        if ((st.st_mode & 0077) != 0 && chmod(path, 0700) != 0) {
            perror("chmod credential directory"); return -1;
        }
        return 0;
    }
    if (errno != ENOENT) { perror(path); return -1; }
    if (mkdir(path, 0700) != 0) { perror(path); return -1; }
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0) {
        fprintf(stderr, "Created credential directory failed security checks: %s\n", path);
        return -1;
    }
    return 0;
}

/*
 * Safely construct a path using snprintf().
 *
 * Returns 0 on success and -1 if the resulting path would be
 * truncated or if an invalid argument is supplied.
 */
static int build_path(
    char *buffer,
    size_t buffer_size,
    const char *format,
    const char *first,
    const char *second)
{
    int written;

    if (!buffer ||
        buffer_size == 0 ||
        !format ||
        !first) {
        return -1;
    }

    written = snprintf(
        buffer,
        buffer_size,
        format,
        first,
        second);

    if (written < 0 ||
        (size_t)written >= buffer_size) {
        fprintf(stderr, "Credential path too long\n");
        return -1;
    }

    return 0;
}

static int write_metadata(
    const char *path, const CredentialMetadata *metadata)
{
    if (!path || !metadata) return -1;
    return write_file_atomic(path, metadata, sizeof(*metadata));
}

static int read_metadata(
    const char *path,
    CredentialMetadata *metadata)
{
    struct stat st;
    int fd;
    size_t offset = 0;

    if (!path || !metadata) return -1;
    fd = open_private_regular_file(path);
    if (fd < 0) { perror(path); return -1; }
    if (fstat(fd, &st) != 0 || st.st_size != (off_t)sizeof(*metadata)) {
        fprintf(stderr, "Invalid credential metadata file size: %s\n", path);
        close(fd); return -1;
    }
    while (offset < sizeof(*metadata)) {
        ssize_t n = read(fd, (char *)metadata + offset, sizeof(*metadata) - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            fprintf(stderr, "Invalid credential metadata: %s\n", path);
            close(fd); return -1;
        }
        offset += (size_t)n;
    }
    close(fd);

    if (metadata->magic != CREDENTIAL_METADATA_MAGIC ||
        metadata->version != CREDENTIAL_METADATA_VERSION) {
        fprintf(stderr, "Unsupported credential metadata format\n");
        return -1;
    }
    if (metadata->credential_id_len != TPM_CREDENTIAL_ID_SIZE ||
        metadata->user_handle_len == 0 ||
        metadata->user_handle_len > WEBAUTHN_USER_HANDLE_MAX ||
        !memchr(metadata->rp_id, '\0', sizeof(metadata->rp_id)) ||
        !memchr(metadata->user_name, '\0', sizeof(metadata->user_name)) ||
        !memchr(metadata->display_name, '\0', sizeof(metadata->display_name))) {
        fprintf(stderr, "Invalid credential metadata lengths or strings\n");
        return -1;
    }
    return 0;
}

void credential_init(WebAuthnCredential *credential)
{
    if (!credential)
        return;

    memset(
        credential,
        0,
        sizeof(*credential));
}

void credential_free(WebAuthnCredential *credential)
{
    if (!credential)
        return;

    tpm_credential_free(&credential->tpm);

    /*
     * Clear the complete credential structure so sensitive TPM
     * material and credential data are not left in memory.
     */
    memset(
        credential,
        0,
        sizeof(*credential));
}

int credential_id_hex(
    const uint8_t *id,
    size_t id_len,
    char *hex,
    size_t hex_size)
{
    static const char digits[] =
        "0123456789abcdef";

    if (!id ||
        !hex ||
        id_len == 0) {
        return -1;
    }

    /*
     * Protect against integer overflow in:
     *
     *     (id_len * 2) + 1
     */
    if (id_len > (SIZE_MAX - 1) / 2)
        return -1;

    if (hex_size < (id_len * 2) + 1)
        return -1;

    for (size_t i = 0; i < id_len; i++) {
        hex[i * 2] =
            digits[id[i] >> 4];

        hex[i * 2 + 1] =
            digits[id[i] & 0x0f];
    }

    hex[id_len * 2] = '\0';

    return 0;
}

int credential_create(
    TpmContext *tpm,
    WebAuthnCredential *credential,
    const char *rp_id,
    const uint8_t *user_handle,
    size_t user_handle_len,
    const char *user_name,
    const char *display_name)
{
    if (!tpm ||
        !credential ||
        !rp_id ||
        !user_handle ||
        !user_name ||
        !display_name) {
        return -1;
    }

    if (strlen(rp_id) >= WEBAUTHN_RP_ID_MAX ||
        strlen(user_name) >= WEBAUTHN_USER_NAME_MAX ||
        strlen(display_name) >= WEBAUTHN_DISPLAY_NAME_MAX) {
        fprintf(
            stderr,
            "WebAuthn credential string too long\n");
        return -1;
    }

    if (user_handle_len == 0 ||
        user_handle_len > WEBAUTHN_USER_HANDLE_MAX) {
        fprintf(
            stderr,
            "Invalid WebAuthn user handle length\n");
        return -1;
    }

    credential_free(credential);
    credential_init(credential);

    if (tpm_create_credential(
            tpm,
            &credential->tpm) != 0) {
        return -1;
    }

    memcpy(
        credential->id,
        credential->tpm.credential_id,
        TPM_CREDENTIAL_ID_SIZE);

    credential->id_len =
        TPM_CREDENTIAL_ID_SIZE;

    memcpy(
        credential->user_handle,
        user_handle,
        user_handle_len);

    credential->user_handle_len =
        user_handle_len;

    /*
     * The lengths above were validated against the destination
     * arrays, so these copies are bounded by the corresponding
     * WebAuthn constants.
     */
    strcpy(
        credential->rp_id,
        rp_id);

    strcpy(
        credential->user_name,
        user_name);

    strcpy(
        credential->display_name,
        display_name);

    credential->sign_count = 0;

    return 0;
}

int credential_save(
    const WebAuthnCredential *credential,
    const char *base_directory)
{
    char credentials_dir[4096];
    char credential_dir[4096];
    char metadata_path[4096];
    char id_hex[(TPM_CREDENTIAL_ID_SIZE * 2) + 1];

    CredentialMetadata metadata;

    if (!credential ||
        !base_directory ||
        credential->id_len != TPM_CREDENTIAL_ID_SIZE ||
        !credential->tpm.public_blob ||
        !credential->tpm.private_blob) {
        return -1;
    }

    if (credential_id_hex(
            credential->id,
            credential->id_len,
            id_hex,
            sizeof(id_hex)) != 0) {
        return -1;
    }

    if (ensure_directory(base_directory) != 0)
        return -1;

    /*
     * <base_directory>/credentials
     */
    if (build_path(
            credentials_dir,
            sizeof(credentials_dir),
            "%s/credentials",
            base_directory,
            NULL) != 0) {
        return -1;
    }

    if (ensure_directory(credentials_dir) != 0)
        return -1;

    /*
     * <base_directory>/credentials/<credential-id>
     */
    if (build_path(
            credential_dir,
            sizeof(credential_dir),
            "%s/%s",
            credentials_dir,
            id_hex) != 0) {
        return -1;
    }

    if (ensure_directory(credential_dir) != 0)
        return -1;

    memset(
        &metadata,
        0,
        sizeof(metadata));

    metadata.magic =
        CREDENTIAL_METADATA_MAGIC;

    metadata.version =
        CREDENTIAL_METADATA_VERSION;

    metadata.credential_id_len =
        credential->id_len;

    metadata.user_handle_len =
        credential->user_handle_len;

    metadata.sign_count =
        credential->sign_count;

    memcpy(
        metadata.credential_id,
        credential->id,
        credential->id_len);

    memcpy(
        metadata.user_handle,
        credential->user_handle,
        credential->user_handle_len);

    /*
     * credential_create() validates these strings before they can
     * reach credential_save().
     */
    strcpy(
        metadata.rp_id,
        credential->rp_id);

    strcpy(
        metadata.user_name,
        credential->user_name);

    strcpy(
        metadata.display_name,
        credential->display_name);

    /*
     * <credential-dir>/metadata
     */
    if (build_path(
            metadata_path,
            sizeof(metadata_path),
            "%s/metadata",
            credential_dir,
            NULL) != 0) {
        return -1;
    }

    if (write_metadata(
            metadata_path,
            &metadata) != 0) {
        return -1;
    }

    if (tpm_save_credential(
            &credential->tpm,
            credential_dir) != 0) {

        /*
         * Metadata must not remain if the TPM credential could
         * not be saved successfully.
         */
        unlink(metadata_path);

        return -1;
    }

    return 0;
}

int credential_load(
    WebAuthnCredential *credential,
    const char *base_directory,
    const uint8_t *credential_id,
    size_t credential_id_len)
{
    char credentials_dir[4096];
    char credential_dir[4096];
    char metadata_path[4096];
    char id_hex[(TPM_CREDENTIAL_ID_SIZE * 2) + 1];

    CredentialMetadata metadata;

    if (!credential ||
        !base_directory ||
        !credential_id ||
        credential_id_len != TPM_CREDENTIAL_ID_SIZE) {
        return -1;
    }

    if (credential_id_hex(
            credential_id,
            credential_id_len,
            id_hex,
            sizeof(id_hex)) != 0) {
        return -1;
    }

    /*
     * <base_directory>/credentials
     */
    if (build_path(
            credentials_dir,
            sizeof(credentials_dir),
            "%s/credentials",
            base_directory,
            NULL) != 0) {
        return -1;
    }

    /*
     * <base_directory>/credentials/<credential-id>
     */
    if (build_path(
            credential_dir,
            sizeof(credential_dir),
            "%s/%s",
            credentials_dir,
            id_hex) != 0) {
        return -1;
    }

    /*
     * <credential-dir>/metadata
     */
    if (build_path(
            metadata_path,
            sizeof(metadata_path),
            "%s/metadata",
            credential_dir,
            NULL) != 0) {
        return -1;
    }

    if (read_metadata(
            metadata_path,
            &metadata) != 0) {
        return -1;
    }

    /*
     * Never trust the credential directory name alone.
     * Verify that the credential ID stored in metadata matches
     * the credential ID requested by the caller.
     */
    if (memcmp(
            metadata.credential_id,
            credential_id,
            credential_id_len) != 0) {

        fprintf(
            stderr,
            "Credential ID mismatch\n");

        return -1;
    }

    credential_free(credential);
    credential_init(credential);

    memcpy(
        credential->id,
        metadata.credential_id,
        TPM_CREDENTIAL_ID_SIZE);

    credential->id_len =
        metadata.credential_id_len;

    memcpy(
        credential->user_handle,
        metadata.user_handle,
        metadata.user_handle_len);

    credential->user_handle_len =
        metadata.user_handle_len;

    strcpy(
        credential->rp_id,
        metadata.rp_id);

    strcpy(
        credential->user_name,
        metadata.user_name);

    strcpy(
        credential->display_name,
        metadata.display_name);

    credential->sign_count =
        metadata.sign_count;

    if (tpm_load_credential(
            &credential->tpm,
            credential_dir) != 0) {

        credential_free(credential);

        return -1;
    }

    return 0;
}

uint32_t credential_next_sign_count(
    WebAuthnCredential *credential)
{
    if (!credential)
        return 0;

    /*
     * WebAuthn counters are unsigned 32-bit values.
     *
     * We deliberately saturate at UINT32_MAX rather than wrapping
     * back to zero, because a decreasing counter can cause relying
     * parties to treat the authenticator as cloned.
     */
    if (credential->sign_count != UINT32_MAX)
        credential->sign_count++;

    return credential->sign_count;
}
