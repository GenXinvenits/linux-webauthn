#include "ctap.h"

#include "cbor.h"
#include "fingerprint.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * This authenticator's security policy requires fingerprint verification
 * before creating a credential or producing an assertion that can be used
 * for authentication. The only exception is CTAP's GetAssertion preflight
 * probe (up=false, uv not true): its response has UP=false and must never be
 * allowed to authorize a subsequent GetNextAssertion operation.
 */
static int request_requires_uv(
    const uint8_t *input,
    size_t input_len)
{
    CborValue *request_map = NULL;
    CborValue *options = NULL;
    CborValue *uv = NULL;
    CborValue *up = NULL;
    size_t offset = 0;
    uint64_t options_key;
    uint8_t command;
    int require_uv = 0;
    int user_present = 1;

    if (!input || input_len < 1)
        return CTAP2_ERR_INVALID_LENGTH;

    command = input[0];

    /*
     * GetNextAssertion has no options of its own. It is authorized only as
     * part of a verified GetAssertion sequence.
     */
    if (command == CTAP_CMD_GET_NEXT_ASSERTION)
        return ctap_is_user_verified() ? CTAP2_OK : CTAP2_ERR_NOT_ALLOWED;

    if (command == CTAP_CMD_MAKE_CREDENTIAL) {
        options_key = 0x07;
        require_uv = 1; /* Registration always requires a fingerprint. */
    } else if (command == CTAP_CMD_GET_ASSERTION) {
        options_key = 0x05;
        require_uv = 1; /* Default up=true means a real assertion. */
    } else {
        ctap_set_user_verified(0);
        return CTAP2_OK;
    }

    ctap_set_user_verified(0);

    if (input_len < 2 ||
        cbor_decode(
            input + 1,
            input_len - 1,
            &offset,
            &request_map) != 0 ||
        offset != input_len - 1 ||
        !request_map ||
        !cbor_is_type(request_map, CBOR_TYPE_MAP)) {
        cbor_free(request_map);
        /* The CTAP parser will return the detailed malformed-request error. */
        return CTAP2_OK;
    }

    options = cbor_map_get_uint(request_map, options_key);
    if (options && !cbor_is_type(options, CBOR_TYPE_MAP)) {
        cbor_free(request_map);
        return CTAP2_ERR_INVALID_PARAMETER;
    }

    if (options) {
        uv = cbor_map_get_text(options, "uv");
        up = cbor_map_get_text(options, "up");

        if (uv && !cbor_is_type(uv, CBOR_TYPE_BOOL)) {
            cbor_free(request_map);
            return CTAP2_ERR_INVALID_PARAMETER;
        }

        if (up && !cbor_is_type(up, CBOR_TYPE_BOOL)) {
            cbor_free(request_map);
            return CTAP2_ERR_INVALID_PARAMETER;
        }

        if (uv && uv->boolean)
            require_uv = 1;

        if (command == CTAP_CMD_GET_ASSERTION && up && !up->boolean)
            user_present = 0;
    }

    /*
     * An up=false GetAssertion is a credential-discovery preflight. Do not
     * prompt for a fingerprint unless the client explicitly requested UV.
     * The response's UP bit remains false, and GetNextAssertion is rejected
     * unless a verified assertion sequence exists.
     */
    if (command == CTAP_CMD_GET_ASSERTION &&
        !user_present &&
        !(uv && uv->boolean))
        require_uv = 0;

    cbor_free(request_map);

    if (!require_uv)
        return CTAP2_OK;

    fprintf(stderr,
            "CTAP: mandatory fingerprint verification; starting verification\n");

    if (fingerprint_verify() != 0) {
        ctap_set_user_verified(0);
        fprintf(stderr, "CTAP: fingerprint verification failed\n");
        return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }

    ctap_set_user_verified(1);
    fprintf(stderr, "CTAP: fingerprint verification SUCCESS\n");
    return CTAP2_OK;
}

int ctap_prepare_user_verification(
    const uint8_t *input,
    size_t input_len)
{
    return request_requires_uv(input, input_len);
}
