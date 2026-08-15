#ifndef LINUX_WEBAUTHN_AUTHENTICATOR_H
#define LINUX_WEBAUTHN_AUTHENTICATOR_H

#include <stddef.h>
#include <stdint.h>

/*
 * Initialize the WebAuthn authenticator backend.
 *
 * This initializes the CTAP/TPM layer.
 */
int authenticator_init(void);

/*
 * Shut down the authenticator backend.
 */
void authenticator_cleanup(void);

/*
 * Process one complete CTAP2 message.
 *
 * input:
 *     CTAP command byte followed by CBOR request.
 *
 * output:
 *     CTAP status byte followed by CBOR response.
 *
 * The caller owns *output and must free() it.
 */
int authenticator_process(
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len);

#endif
