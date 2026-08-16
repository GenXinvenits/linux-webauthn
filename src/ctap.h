#ifndef LINUX_WEBAUTHN_CTAP_H
#define LINUX_WEBAUTHN_CTAP_H

#include <stddef.h>
#include <stdint.h>

#include "credential.h"

#define CTAP_CMD_MAKE_CREDENTIAL       0x01
#define CTAP_CMD_GET_ASSERTION         0x02
#define CTAP_CMD_GET_INFO              0x04
#define CTAP_CMD_CLIENT_PIN            0x06
#define CTAP_CMD_RESET                 0x07
#define CTAP_CMD_GET_NEXT_ASSERTION    0x08

#define CTAP2_OK                       0x00
#define CTAP2_ERR_INVALID_COMMAND      0x01
#define CTAP2_ERR_INVALID_PARAMETER    0x02
#define CTAP2_ERR_INVALID_LENGTH       0x03
#define CTAP2_ERR_INVALID_SEQ          0x04
#define CTAP2_ERR_TIMEOUT              0x05
#define CTAP2_ERR_CHANNEL_BUSY         0x06
#define CTAP2_ERR_LOCK_REQUIRED        0x0A
#define CTAP2_ERR_INVALID_CBOR         0x12
#define CTAP2_ERR_MISSING_PARAMETER    0x14
#define CTAP2_ERR_CREDENTIAL_EXCLUDED  0x19
#define CTAP2_ERR_PROCESSING           0x21
#define CTAP2_ERR_INVALID_CREDENTIAL   0x22
#define CTAP2_ERR_USER_ACTION_PENDING  0x23
#define CTAP2_ERR_OPERATION_PENDING    0x24
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED     0x27
#define CTAP2_ERR_KEY_STORE_FULL       0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION   0x2B
#define CTAP2_ERR_INVALID_OPTION       0x2C
#define CTAP2_ERR_NO_CREDENTIALS       0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT  0x2F
#define CTAP2_ERR_NOT_ALLOWED          0x30
#define CTAP2_ERR_REQUEST_TOO_LARGE    0x39
#define CTAP2_ERR_UP_REQUIRED          0x3B
#define CTAP2_ERR_OTHER                0x7F
#define CTAP2_ERR_UNSUPPORTED          0x7F

typedef struct {
    const char *versions[4];
    size_t version_count;
    const char *extensions[8];
    size_t extension_count;
    uint32_t options;
    uint32_t max_msg_size;
    uint8_t aaguid[16];
} CtapGetInfo;

void ctap_init(void);
void ctap_set_user_verified(int verified);
int ctap_is_user_verified(void);

/*
 * Prepare user verification for one CTAP operation.
 * Returns CTAP2_OK when UV is not requested or succeeds,
 * otherwise returns the appropriate CTAP2 error status.
 */
int ctap_prepare_user_verification(
    const uint8_t *input,
    size_t input_len);

void ctap_cleanup(void);

int ctap_process(
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len);

int ctap_get_info(
    uint8_t **output,
    size_t *output_len);

int ctap_make_credential(
    const uint8_t *request,
    size_t request_len,
    uint8_t **output,
    size_t *output_len);

int ctap_get_assertion(
    const uint8_t *request,
    size_t request_len,
    uint8_t **output,
    size_t *output_len);

int ctap_get_next_assertion(
    uint8_t **output,
    size_t *output_len);

#endif
