#ifndef LINUX_WEBAUTHN_CREDENTIAL_H
#define LINUX_WEBAUTHN_CREDENTIAL_H

#include <stddef.h>
#include <stdint.h>

#include "tpm.h"

#define WEBAUTHN_RP_ID_MAX        256
#define WEBAUTHN_USER_HANDLE_MAX  64
#define WEBAUTHN_USER_NAME_MAX    256
#define WEBAUTHN_DISPLAY_NAME_MAX 256

typedef struct {
    uint8_t id[TPM_CREDENTIAL_ID_SIZE];
    size_t id_len;

    char rp_id[WEBAUTHN_RP_ID_MAX];

    uint8_t user_handle[WEBAUTHN_USER_HANDLE_MAX];
    size_t user_handle_len;

    char user_name[WEBAUTHN_USER_NAME_MAX];
    char display_name[WEBAUTHN_DISPLAY_NAME_MAX];

    uint32_t sign_count;

    TpmCredential tpm;
} WebAuthnCredential;

/*
 * Initialize a credential structure.
 */
void credential_init(WebAuthnCredential *credential);

/*
 * Release all memory owned by a credential.
 */
void credential_free(WebAuthnCredential *credential);

/*
 * Create a new TPM-backed WebAuthn credential.
 *
 * The TPM key is generated inside the TPM.
 */
int credential_create(
    TpmContext *tpm,
    WebAuthnCredential *credential,
    const char *rp_id,
    const uint8_t *user_handle,
    size_t user_handle_len,
    const char *user_name,
    const char *display_name);

/*
 * Save credential metadata and TPM blobs.
 */
int credential_save(
    const WebAuthnCredential *credential,
    const char *base_directory);

/*
 * Load a credential by credential ID.
 */
int credential_load(
    WebAuthnCredential *credential,
    const char *base_directory,
    const uint8_t *credential_id,
    size_t credential_id_len);

/*
 * Increment and return the signature counter.
 */
uint32_t credential_next_sign_count(
    WebAuthnCredential *credential);

/*
 * Find the credential directory name corresponding to an ID.
 */
int credential_id_hex(
    const uint8_t *id,
    size_t id_len,
    char *hex,
    size_t hex_size);

#endif
