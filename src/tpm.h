#ifndef LINUX_WEBAUTHN_TPM_H
#define LINUX_WEBAUTHN_TPM_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_esys.h>

#define TPM_P256_COORDINATE_SIZE 32
#define TPM_CREDENTIAL_ID_SIZE 32
#define TPM_WEBAUTHN_PARENT_HANDLE 0x81020000


typedef struct {
    ESYS_CONTEXT *esys;

    /*
     * Owner hierarchy primary used to load/create child objects.
     * This is transient and is flushed during cleanup.
     */
    ESYS_TR parent;

    /*
     * Currently loaded WebAuthn signing key.
     * This is transient and is flushed after use/cleanup.
     */
    ESYS_TR key;

    int initialized;
} TpmContext;

typedef struct {
    TPM2B_PUBLIC *public_blob;
    TPM2B_PRIVATE *private_blob;

    uint8_t credential_id[TPM_CREDENTIAL_ID_SIZE];

    uint8_t x[TPM_P256_COORDINATE_SIZE];
    uint8_t y[TPM_P256_COORDINATE_SIZE];

    size_t x_len;
    size_t y_len;
} TpmCredential;

/*
 * Initialize access to the system TPM.
 */
int tpm_init(TpmContext *ctx);

/*
 * Release TPM resources and flush transient objects.
 */
void tpm_cleanup(TpmContext *ctx);

/*
 * Create a new TPM-backed P-256 ECDSA credential.
 *
 * The private key is generated inside the TPM.
 * The returned public/private blobs may be stored on disk.
 */
int tpm_create_credential(
    TpmContext *ctx,
    TpmCredential *credential);

/*
 * Save/load the TPM public/private blobs.
 */
int tpm_save_credential(
    const TpmCredential *credential,
    const char *directory);

int tpm_load_credential(
    TpmCredential *credential,
    const char *directory);

/*
 * Free memory owned by TpmCredential.
 */
void tpm_credential_free(
    TpmCredential *credential);

/*
 * Load a credential into the TPM.
 *
 * The resulting key remains TPM-resident until flushed.
 */
int tpm_load_key(
    TpmContext *ctx,
    TpmCredential *credential);

/*
 * Return the public P-256 coordinates.
 */
int tpm_get_public_key(
    const TpmCredential *credential,
    uint8_t x[TPM_P256_COORDINATE_SIZE],
    uint8_t y[TPM_P256_COORDINATE_SIZE]);

/*
 * Sign a SHA-256 digest using the TPM-resident P-256 key.
 *
 * digest must contain exactly 32 bytes.
 *
 * r and s are returned as fixed-width 32-byte big-endian values.
 */
int tpm_sign_digest(
    TpmContext *ctx,
    const uint8_t digest[32],
    uint8_t r[TPM_P256_COORDINATE_SIZE],
    uint8_t s[TPM_P256_COORDINATE_SIZE]);

/*
 * Flush the currently loaded credential key.
 */
void tpm_flush_key(
    TpmContext *ctx);

#endif
