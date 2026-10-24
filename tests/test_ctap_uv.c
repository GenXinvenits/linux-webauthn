#include "ctap.h"
#include "cbor.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int user_verified;
static int fingerprint_result;
static unsigned fingerprint_calls;

int fingerprint_verify(void)
{
    fingerprint_calls++;
    return fingerprint_result;
}

void ctap_set_user_verified(int verified)
{
    user_verified = verified ? 1 : 0;
}

int ctap_is_user_verified(void)
{
    return user_verified;
}

static void reset_fake_fingerprint(int result)
{
    fingerprint_result = result;
    fingerprint_calls = 0;
    user_verified = 0;
}

static void add_bool(CborValue *map, const char *key, int value)
{
    assert(cbor_map_put(map, cbor_new_text(key),
                        cbor_new_bool(value != 0)) == 0);
}

static void make_request(
    uint8_t command,
    int include_up,
    int up,
    int include_uv,
    int uv,
    uint8_t **input,
    size_t *input_len)
{
    CborValue *request = cbor_new_map();
    CborValue *options = cbor_new_map();
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    uint64_t options_key = command == CTAP_CMD_MAKE_CREDENTIAL ? 0x07 : 0x05;

    assert(request != NULL);
    assert(options != NULL);

    if (include_up)
        add_bool(options, "up", up);
    if (include_uv)
        add_bool(options, "uv", uv);

    assert(cbor_map_put(request, cbor_new_uint(options_key), options) == 0);
    assert(cbor_encode(request, &encoded, &encoded_len) == 0);

    *input = malloc(encoded_len + 1);
    assert(*input != NULL);
    (*input)[0] = command;
    memcpy(*input + 1, encoded, encoded_len);
    *input_len = encoded_len + 1;

    free(encoded);
    cbor_free(request);
}

static void test_make_credential_requires_uv_even_if_option_false(void)
{
    uint8_t *input = NULL;
    size_t input_len = 0;

    make_request(CTAP_CMD_MAKE_CREDENTIAL, 0, 0, 1, 0,
                 &input, &input_len);
    reset_fake_fingerprint(0);

    assert(ctap_prepare_user_verification(input, input_len) == CTAP2_OK);
    assert(fingerprint_calls == 1);
    assert(user_verified == 1);

    free(input);
}

static void test_assertion_requires_uv_by_default(void)
{
    uint8_t *input = NULL;
    size_t input_len = 0;

    make_request(CTAP_CMD_GET_ASSERTION, 0, 0, 0, 0,
                 &input, &input_len);
    reset_fake_fingerprint(0);

    assert(ctap_prepare_user_verification(input, input_len) == CTAP2_OK);
    assert(fingerprint_calls == 1);
    assert(user_verified == 1);

    free(input);
}

static void test_preflight_does_not_authorize_followup(void)
{
    uint8_t *input = NULL;
    size_t input_len = 0;
    const uint8_t next_assertion[] = { CTAP_CMD_GET_NEXT_ASSERTION };

    make_request(CTAP_CMD_GET_ASSERTION, 1, 0, 0, 0,
                 &input, &input_len);
    reset_fake_fingerprint(0);

    assert(ctap_prepare_user_verification(input, input_len) == CTAP2_OK);
    assert(fingerprint_calls == 0);
    assert(user_verified == 0);
    assert(ctap_prepare_user_verification(next_assertion,
                                          sizeof(next_assertion)) ==
           CTAP2_ERR_NOT_ALLOWED);

    free(input);
}

static void test_explicit_uv_requires_fingerprint_even_for_preflight(void)
{
    uint8_t *input = NULL;
    size_t input_len = 0;

    make_request(CTAP_CMD_GET_ASSERTION, 1, 0, 1, 1,
                 &input, &input_len);
    reset_fake_fingerprint(0);

    assert(ctap_prepare_user_verification(input, input_len) == CTAP2_OK);
    assert(fingerprint_calls == 1);
    assert(user_verified == 1);

    free(input);
}

static void test_fingerprint_failure_fails_closed(void)
{
    uint8_t *input = NULL;
    size_t input_len = 0;

    make_request(CTAP_CMD_GET_ASSERTION, 1, 1, 0, 0,
                 &input, &input_len);
    reset_fake_fingerprint(-1);

    assert(ctap_prepare_user_verification(input, input_len) ==
           CTAP2_ERR_USER_ACTION_TIMEOUT);
    assert(fingerprint_calls == 1);
    assert(user_verified == 0);

    free(input);
}

static void test_next_assertion_requires_verified_sequence(void)
{
    const uint8_t next_assertion[] = { CTAP_CMD_GET_NEXT_ASSERTION };

    reset_fake_fingerprint(0);
    assert(ctap_prepare_user_verification(next_assertion,
                                          sizeof(next_assertion)) ==
           CTAP2_ERR_NOT_ALLOWED);
    assert(fingerprint_calls == 0);

    user_verified = 1;
    assert(ctap_prepare_user_verification(next_assertion,
                                          sizeof(next_assertion)) ==
           CTAP2_OK);
    assert(fingerprint_calls == 0);
}

int main(void)
{
    test_make_credential_requires_uv_even_if_option_false();
    test_assertion_requires_uv_by_default();
    test_preflight_does_not_authorize_followup();
    test_explicit_uv_requires_fingerprint_even_for_preflight();
    test_fingerprint_failure_fails_closed();
    test_next_assertion_requires_verified_sequence();

    puts("CTAP UV security tests passed");
    return 0;
}
