#include "ctap.h"

#include "cbor.h"
#include "fingerprint.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int request_requires_uv(
    const uint8_t *input,
    size_t input_len)
{
    CborValue *request_map = NULL;
    CborValue *options = NULL;
    CborValue *uv = NULL;
    size_t offset = 0;
    uint64_t options_key;
    uint8_t command;

    if (!input || input_len < 2)
        return 0;

    command = input[0];

    if (command == CTAP_CMD_MAKE_CREDENTIAL)
        options_key = 0x07;
    else if (command == CTAP_CMD_GET_ASSERTION)
        options_key = 0x05;
    else
        return 0;

    if (cbor_decode(
            input + 1,
            input_len - 1,
            &offset,
            &request_map) != 0 ||
        offset != input_len - 1 ||
        !request_map ||
        !cbor_is_type(request_map, CBOR_TYPE_MAP)) {
        cbor_free(request_map);
        return 0;
    }

    options = cbor_map_get_uint(request_map, options_key);

    if (options && cbor_is_type(options, CBOR_TYPE_MAP))
        uv = cbor_map_get_text(options, "uv");

    if (uv &&
        cbor_is_type(uv, CBOR_TYPE_BOOL) &&
        uv->boolean) {
        fprintf(
            stderr,
            "CTAP: user verification requested; starting fingerprint verification\n");

        if (fingerprint_verify() != 0) {
            ctap_set_user_verified(0);

            fprintf(
                stderr,
                "CTAP: fingerprint verification failed\n");

            cbor_free(request_map);
            return CTAP2_ERR_USER_ACTION_TIMEOUT;
        }

        ctap_set_user_verified(1);

        fprintf(
            stderr,
            "CTAP: fingerprint verification SUCCESS\n");
    } else {
        ctap_set_user_verified(0);
    }

    cbor_free(request_map);
    return CTAP2_OK;
}

int ctap_prepare_user_verification(
    const uint8_t *input,
    size_t input_len)
{
    return request_requires_uv(input, input_len);
}
