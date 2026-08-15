#include "tpm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#define TPM_BLOB_MAGIC 0x47575450U
#define TPM_BLOB_VERSION 1U

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t size;
} BlobHeader;

static void print_rc(const char *operation, TSS2_RC rc)
{
    fprintf(stderr, "%s failed: 0x%08x\n", operation, rc);
}

static int ensure_directory(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "%s exists but is not a directory\n", path);
            return -1;
        }

        return 0;
    }

    if (errno != ENOENT) {
        perror(path);
        return -1;
    }

    if (mkdir(path, 0700) != 0) {
        perror(path);
        return -1;
    }

    return 0;
}

static int write_blob(
    const char *path,
    const void *data,
    size_t size)
{
    FILE *fp;

    if (size > UINT32_MAX) {
        fprintf(stderr, "Blob too large\n");
        return -1;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        perror(path);
        return -1;
    }

    if (fchmod(fileno(fp), 0600) != 0) {
        perror("fchmod");
        fclose(fp);
        return -1;
    }

    BlobHeader header = {
        .magic = TPM_BLOB_MAGIC,
        .version = TPM_BLOB_VERSION,
        .size = (uint32_t)size
    };

    if (fwrite(&header, sizeof(header), 1, fp) != 1 ||
        (size > 0 && fwrite(data, size, 1, fp) != 1)) {
        fprintf(stderr, "Failed writing %s\n", path);
        fclose(fp);
        return -1;
    }

    if (fflush(fp) != 0) {
        perror("fflush");
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        perror("fclose");
        return -1;
    }

    return 0;
}

static void *read_blob(
    const char *path,
    size_t *size_out)
{
    FILE *fp;
    BlobHeader header;
    void *data = NULL;

    if (!size_out)
        return NULL;

    *size_out = 0;

    fp = fopen(path, "rb");
    if (!fp) {
        perror(path);
        return NULL;
    }

    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "Invalid TPM blob header: %s\n", path);
        fclose(fp);
        return NULL;
    }

    if (header.magic != TPM_BLOB_MAGIC ||
        header.version != TPM_BLOB_VERSION) {
        fprintf(stderr, "Invalid TPM blob format: %s\n", path);
        fclose(fp);
        return NULL;
    }

    if (header.size == 0 || header.size > 1024 * 1024) {
        fprintf(stderr, "Invalid TPM blob size: %s\n", path);
        fclose(fp);
        return NULL;
    }

    data = malloc(header.size);
    if (!data) {
        fprintf(stderr, "Out of memory reading %s\n", path);
        fclose(fp);
        return NULL;
    }

    if (fread(data, header.size, 1, fp) != 1) {
        fprintf(stderr, "Failed reading %s\n", path);
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    *size_out = header.size;
    return data;
}

static int init_parent(TpmContext *ctx)
{
    TSS2_RC rc;

    if (!ctx || !ctx->initialized)
        return -1;

    if (ctx->parent != ESYS_TR_NONE)
        return 0;

    /*
     * The WebAuthn parent is a persistent TPM object.
     *
     * Credentials created with Esys_Create() are children of
     * this parent. Their private blobs are therefore bound to
     * this specific parent.
     *
     * We deliberately do NOT create a new primary here.
     */
    rc = Esys_TR_FromTPMPublic(
        ctx->esys,
        TPM_WEBAUTHN_PARENT_HANDLE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &ctx->parent
    );

    if (rc != TSS2_RC_SUCCESS) {
        print_rc("Esys_TR_FromTPMPublic(WebAuthn parent)", rc);
        ctx->parent = ESYS_TR_NONE;
        return -1;
    }

    return 0;
}

int tpm_init(TpmContext *ctx)
{
    TSS2_RC rc;

    if (!ctx)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

    ctx->esys = NULL;
    ctx->parent = ESYS_TR_NONE;
    ctx->key = ESYS_TR_NONE;

    rc = Esys_Initialize(&ctx->esys, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        print_rc("Esys_Initialize", rc);
        return -1;
    }

    ctx->initialized = 1;
    return 0;
}

void tpm_flush_key(TpmContext *ctx)
{
    if (!ctx || !ctx->esys)
        return;

    if (ctx->key != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys, ctx->key);
        ctx->key = ESYS_TR_NONE;
    }
}

void tpm_cleanup(TpmContext *ctx)
{
    if (!ctx)
        return;

    /*
     * The WebAuthn credential key is transient and must be flushed.
     */
    tpm_flush_key(ctx);

    /*
     * The parent is a persistent TPM object at
     * TPM_WEBAUTHN_PARENT_HANDLE.
     *
     * It must NOT be flushed. We only close the ESAPI
     * bookkeeping handle associated with it.
     */
    if (ctx->esys && ctx->parent != ESYS_TR_NONE) {
        Esys_TR_Close(ctx->esys, &ctx->parent);
        ctx->parent = ESYS_TR_NONE;
    }

    if (ctx->esys)
        Esys_Finalize(&ctx->esys);

    ctx->initialized = 0;
}

void tpm_credential_free(TpmCredential *credential)
{
    if (!credential)
        return;

    if (credential->public_blob)
        Esys_Free(credential->public_blob);

    if (credential->private_blob)
        Esys_Free(credential->private_blob);

    memset(credential, 0, sizeof(*credential));
}

static int extract_public_key(TpmCredential *credential)
{
    const TPMS_ECC_POINT *ecc;

    if (!credential || !credential->public_blob)
        return -1;

    if (credential->public_blob->publicArea.type != TPM2_ALG_ECC)
        return -1;

    if (credential->public_blob->publicArea.parameters.eccDetail.curveID
        != TPM2_ECC_NIST_P256)
        return -1;

    ecc = &credential->public_blob->publicArea.unique.ecc;

    if (ecc->x.size != TPM_P256_COORDINATE_SIZE ||
        ecc->y.size != TPM_P256_COORDINATE_SIZE) {
        fprintf(stderr, "Unexpected P-256 coordinate size\n");
        return -1;
    }

    memcpy(
        credential->x,
        ecc->x.buffer,
        TPM_P256_COORDINATE_SIZE);

    memcpy(
        credential->y,
        ecc->y.buffer,
        TPM_P256_COORDINATE_SIZE);

    credential->x_len = TPM_P256_COORDINATE_SIZE;
    credential->y_len = TPM_P256_COORDINATE_SIZE;

    return 0;
}

int tpm_create_credential(
    TpmContext *ctx,
    TpmCredential *credential)
{
    TSS2_RC rc;

    TPM2B_PUBLIC in_public = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes =
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_SIGN_ENCRYPT,
            .authPolicy = {
                .size = 0
            },
            .parameters.eccDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL
                },
                .scheme = {
                    .scheme = TPM2_ALG_ECDSA,
                    .details.ecdsa = {
                        .hashAlg = TPM2_ALG_SHA256
                    }
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf = {
                    .scheme = TPM2_ALG_NULL
                }
            },
            .unique.ecc = {
                .x = { .size = 0 },
                .y = { .size = 0 }
            }
        }
    };

    TPM2B_SENSITIVE_CREATE sensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = 0 }
        }
    };

    TPM2B_DATA outside_info = {
        .size = 0
    };

    TPML_PCR_SELECTION creation_pcr = {
        .count = 0
    };

    TPM2B_PRIVATE *private_blob = NULL;
    TPM2B_PUBLIC *public_blob = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST *creation_hash = NULL;
    TPMT_TK_CREATION *creation_ticket = NULL;

    if (!ctx || !ctx->initialized || !credential)
        return -1;

    memset(credential, 0, sizeof(*credential));

    if (init_parent(ctx) != 0)
        return -1;

    rc = Esys_Create(
        ctx->esys,
        ctx->parent,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &sensitive,
        &in_public,
        &outside_info,
        &creation_pcr,
        &private_blob,
        &public_blob,
        &creation_data,
        &creation_hash,
        &creation_ticket
    );

    if (rc != TSS2_RC_SUCCESS) {
        print_rc("Esys_Create", rc);
        goto fail;
    }

    credential->private_blob = private_blob;
    credential->public_blob = public_blob;

    private_blob = NULL;
    public_blob = NULL;

    if (RAND_bytes(
            credential->credential_id,
            sizeof(credential->credential_id)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto fail;
    }

    if (extract_public_key(credential) != 0)
        goto fail;

    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    /*
     * The key has been created but is not left loaded.
     * The blobs are the persistent credential representation.
     */
    return 0;

fail:
    Esys_Free(private_blob);
    Esys_Free(public_blob);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    tpm_credential_free(credential);
    return -1;
}

int tpm_save_credential(
    const TpmCredential *credential,
    const char *directory)
{
    char public_path[4096];
    char private_path[4096];

    if (!credential ||
        !credential->public_blob ||
        !credential->private_blob ||
        !directory) {
        return -1;
    }

    if (ensure_directory(directory) != 0)
        return -1;

    snprintf(
        public_path,
        sizeof(public_path),
        "%s/public",
        directory);

    snprintf(
        private_path,
        sizeof(private_path),
        "%s/private",
        directory);

    if (write_blob(
            public_path,
            credential->public_blob,
            sizeof(*credential->public_blob)) != 0)
        return -1;

    if (write_blob(
            private_path,
            credential->private_blob,
            sizeof(*credential->private_blob)) != 0) {
        unlink(public_path);
        return -1;
    }

    return 0;
}

int tpm_load_credential(
    TpmCredential *credential,
    const char *directory)
{
    char public_path[4096];
    char private_path[4096];

    size_t public_size;
    size_t private_size;

    void *public_data;
    void *private_data;

    if (!credential || !directory)
        return -1;

    memset(credential, 0, sizeof(*credential));

    snprintf(
        public_path,
        sizeof(public_path),
        "%s/public",
        directory);

    snprintf(
        private_path,
        sizeof(private_path),
        "%s/private",
        directory);

    public_data = read_blob(public_path, &public_size);
    if (!public_data)
        return -1;

    private_data = read_blob(private_path, &private_size);
    if (!private_data) {
        free(public_data);
        return -1;
    }

    if (public_size != sizeof(TPM2B_PUBLIC) ||
        private_size != sizeof(TPM2B_PRIVATE)) {
        fprintf(stderr, "Unexpected TPM blob size\n");
        free(public_data);
        free(private_data);
        return -1;
    }

    credential->public_blob = malloc(sizeof(TPM2B_PUBLIC));
    credential->private_blob = malloc(sizeof(TPM2B_PRIVATE));

    if (!credential->public_blob || !credential->private_blob) {
        free(public_data);
        free(private_data);
        tpm_credential_free(credential);
        return -1;
    }

    memcpy(
        credential->public_blob,
        public_data,
        sizeof(TPM2B_PUBLIC));

    memcpy(
        credential->private_blob,
        private_data,
        sizeof(TPM2B_PRIVATE));

    free(public_data);
    free(private_data);

    if (extract_public_key(credential) != 0) {
        tpm_credential_free(credential);
        return -1;
    }

    return 0;
}

int tpm_load_key(
    TpmContext *ctx,
    TpmCredential *credential)
{
    TSS2_RC rc;

    if (!ctx ||
        !ctx->initialized ||
        !credential ||
        !credential->public_blob ||
        !credential->private_blob) {
        return -1;
    }

    tpm_flush_key(ctx);

    if (init_parent(ctx) != 0)
        return -1;

    rc = Esys_Load(
        ctx->esys,
        ctx->parent,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        credential->private_blob,
        credential->public_blob,
        &ctx->key
    );

    if (rc != TSS2_RC_SUCCESS) {
        print_rc("Esys_Load", rc);
        ctx->key = ESYS_TR_NONE;
        return -1;
    }

    return 0;
}

int tpm_get_public_key(
    const TpmCredential *credential,
    uint8_t x[TPM_P256_COORDINATE_SIZE],
    uint8_t y[TPM_P256_COORDINATE_SIZE])
{
    if (!credential ||
        !x ||
        !y ||
        credential->x_len != TPM_P256_COORDINATE_SIZE ||
        credential->y_len != TPM_P256_COORDINATE_SIZE) {
        return -1;
    }

    memcpy(x, credential->x, TPM_P256_COORDINATE_SIZE);
    memcpy(y, credential->y, TPM_P256_COORDINATE_SIZE);

    return 0;
}

int tpm_sign_digest(
    TpmContext *ctx,
    const uint8_t digest[32],
    uint8_t r[TPM_P256_COORDINATE_SIZE],
    uint8_t s[TPM_P256_COORDINATE_SIZE])
{
    TSS2_RC rc;

    TPM2B_DIGEST digest_blob = {
        .size = 32
    };

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details.ecdsa = {
            .hashAlg = TPM2_ALG_SHA256
        }
    };

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {
            .size = 0
        }
    };

    TPMT_SIGNATURE *signature = NULL;

    if (!ctx ||
        !ctx->initialized ||
        ctx->key == ESYS_TR_NONE ||
        !digest ||
        !r ||
        !s) {
        return -1;
    }

    memcpy(digest_blob.buffer, digest, 32);

    rc = Esys_Sign(
        ctx->esys,
        ctx->key,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digest_blob,
        &scheme,
        &validation,
        &signature
    );

    if (rc != TSS2_RC_SUCCESS) {
        print_rc("Esys_Sign", rc);
        return -1;
    }

    if (!signature ||
        signature->sigAlg != TPM2_ALG_ECDSA ||
        signature->signature.ecdsa.signatureR.size > 32 ||
        signature->signature.ecdsa.signatureS.size > 32) {
        fprintf(stderr, "Unexpected TPM ECDSA signature\n");
        Esys_Free(signature);
        return -1;
    }

    memset(r, 0, 32);
    memset(s, 0, 32);

    memcpy(
        r + (32 - signature->signature.ecdsa.signatureR.size),
        signature->signature.ecdsa.signatureR.buffer,
        signature->signature.ecdsa.signatureR.size);

    memcpy(
        s + (32 - signature->signature.ecdsa.signatureS.size),
        signature->signature.ecdsa.signatureS.buffer,
        signature->signature.ecdsa.signatureS.size);

    Esys_Free(signature);

    return 0;
}
