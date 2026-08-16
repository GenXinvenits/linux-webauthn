#include "ctap.h"
#include "cbor.h"

#include <openssl/sha.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CTAP_MAX_REQUEST_SIZE 1200
#define CTAP_MAX_ASSERTION_CREDENTIALS 64
#define CTAP_ASSERTION_TIMEOUT_SECONDS 30

static int ctap_initialized;
static TpmContext ctap_tpm;
static int ctap_user_verified;

typedef struct {
    uint8_t ids[CTAP_MAX_ASSERTION_CREDENTIALS][TPM_CREDENTIAL_ID_SIZE];
    size_t count;
    size_t next_index;
    char rp_id[WEBAUTHN_RP_ID_MAX];
    uint8_t client_data_hash[SHA256_DIGEST_LENGTH];
    time_t last_activity;
    int active;
} CtapAssertionState;

static CtapAssertionState ctap_assertion_state;

static void ctap_assertion_state_reset(void)
{
    memset(&ctap_assertion_state, 0, sizeof(ctap_assertion_state));
}

static int append_bytes(
    uint8_t **buffer,
    size_t *length,
    const uint8_t *data,
    size_t data_length)
{
    uint8_t *new_buffer;

    if (!buffer || !length || (!data && data_length != 0))
        return -1;

    if (data_length > SIZE_MAX - *length)
        return -1;

    new_buffer = realloc(*buffer, *length + data_length);
    if (!new_buffer)
        return -1;

    if (data_length != 0)
        memcpy(new_buffer + *length, data, data_length);

    *buffer = new_buffer;
    *length += data_length;
    return 0;
}

static int append_u16_be(uint8_t **buffer, size_t *length, uint16_t value)
{
    uint8_t bytes[2] = {(uint8_t)(value >> 8), (uint8_t)value};
    return append_bytes(buffer, length, bytes, sizeof(bytes));
}

static int append_u32_be(uint8_t **buffer, size_t *length, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)(value >> 24), (uint8_t)(value >> 16),
        (uint8_t)(value >> 8), (uint8_t)value
    };
    return append_bytes(buffer, length, bytes, sizeof(bytes));
}

static void set_error(uint8_t **output, size_t *output_len, uint8_t status)
{
    uint8_t *buffer;

    if (!output || !output_len)
        return;

    *output = NULL;
    *output_len = 0;
    buffer = malloc(1);
    if (!buffer)
        return;

    buffer[0] = status;
    *output = buffer;
    *output_len = 1;
}

static int encode_response(
    uint8_t status,
    CborValue *value,
    uint8_t **output,
    size_t *output_len)
{
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    if (!output || !output_len) {
        cbor_free(value);
        return -1;
    }

    *output = NULL;
    *output_len = 0;

    if (status != CTAP2_OK) {
        cbor_free(value);
        set_error(output, output_len, status);
        return *output ? 0 : -1;
    }

    if (!value || cbor_encode(value, &encoded, &encoded_len) != 0) {
        cbor_free(value);
        return -1;
    }

    cbor_free(value);
    *output = malloc(encoded_len + 1);
    if (!*output) {
        free(encoded);
        return -1;
    }

    (*output)[0] = CTAP2_OK;
    memcpy(*output + 1, encoded, encoded_len);
    *output_len = encoded_len + 1;
    free(encoded);
    return 0;
}

static int get_data_directory(char *path, size_t path_size)
{
    const char *xdg;
    const char *home;

    if (!path || path_size == 0)
        return -1;

    xdg = getenv("XDG_DATA_HOME");
    if (xdg && xdg[0]) {
        if (snprintf(path, path_size, "%s/linux-webauthn", xdg) >=
            (int)path_size)
            return -1;
        return 0;
    }

    home = getenv("HOME");
    if (!home || !home[0])
        return -1;

    if (snprintf(path, path_size, "%s/.local/share/linux-webauthn", home) >=
        (int)path_size)
        return -1;

    return 0;
}

static int encode_ecdsa_der(
    const uint8_t r[TPM_P256_COORDINATE_SIZE],
    const uint8_t s[TPM_P256_COORDINATE_SIZE],
    uint8_t **output,
    size_t *output_len)
{
    size_t r_offset = 0;
    size_t s_offset = 0;
    size_t r_len;
    size_t s_len;
    int r_pad;
    int s_pad;
    size_t body_len;
    uint8_t *buffer;
    size_t pos = 0;

    if (!r || !s || !output || !output_len)
        return -1;

    *output = NULL;
    *output_len = 0;

    while (r_offset < 31 && r[r_offset] == 0)
        r_offset++;
    while (s_offset < 31 && s[s_offset] == 0)
        s_offset++;

    r_len = 32 - r_offset;
    s_len = 32 - s_offset;
    r_pad = (r[r_offset] & 0x80) != 0;
    s_pad = (s[s_offset] & 0x80) != 0;

    body_len = 2 + r_len + (size_t)r_pad +
               2 + s_len + (size_t)s_pad;
    if (body_len > 127)
        return -1;

    buffer = malloc(body_len + 2);
    if (!buffer)
        return -1;

    buffer[pos++] = 0x30;
    buffer[pos++] = (uint8_t)body_len;
    buffer[pos++] = 0x02;
    buffer[pos++] = (uint8_t)(r_len + (size_t)r_pad);
    if (r_pad)
        buffer[pos++] = 0;
    memcpy(buffer + pos, r + r_offset, r_len);
    pos += r_len;

    buffer[pos++] = 0x02;
    buffer[pos++] = (uint8_t)(s_len + (size_t)s_pad);
    if (s_pad)
        buffer[pos++] = 0;
    memcpy(buffer + pos, s + s_offset, s_len);
    pos += s_len;

    *output = buffer;
    *output_len = pos;
    return 0;
}

void ctap_set_user_verified(int verified)
{
    ctap_user_verified = verified ? 1 : 0;
}

int ctap_is_user_verified(void)
{
    return ctap_user_verified;
}

void ctap_init(void)
{
    ctap_user_verified = 0;
    ctap_assertion_state_reset();
    memset(&ctap_tpm, 0, sizeof(ctap_tpm));

    if (tpm_init(&ctap_tpm) != 0) {
        fprintf(stderr, "Failed to initialize TPM for CTAP\n");
        ctap_initialized = 0;
        return;
    }

    ctap_initialized = 1;
}

void ctap_cleanup(void)
{
    ctap_user_verified = 0;
    ctap_assertion_state_reset();

    if (ctap_initialized)
        tpm_cleanup(&ctap_tpm);

    memset(&ctap_tpm, 0, sizeof(ctap_tpm));
    ctap_initialized = 0;
}

int ctap_get_info(uint8_t **output, size_t *output_len)
{
    CborValue *response = cbor_new_map();
    CborValue *versions = cbor_new_array();
    CborValue *extensions = cbor_new_array();
    CborValue *options = cbor_new_map();
    static const uint8_t aaguid[16] = {
        0x47, 0x4e, 0x57, 0x41, 0x55, 0x54, 0x48, 0x4e,
        0x2d, 0x54, 0x50, 0x4d, 0x2d, 0x30, 0x30, 0x31
    };

    if (!output || !output_len)
        return -1;

    if (!response || !versions || !extensions || !options) {
        cbor_free(response);
        cbor_free(versions);
        cbor_free(extensions);
        cbor_free(options);
        return -1;
    }

    cbor_array_append(versions, cbor_new_text("FIDO_2_0"));
    cbor_array_append(versions, cbor_new_text("FIDO_2_1"));
    cbor_map_put(response, cbor_new_uint(0x01), versions);
    cbor_map_put(response, cbor_new_uint(0x02), extensions);
    cbor_map_put(response, cbor_new_uint(0x03),
                 cbor_new_bytes(aaguid, sizeof(aaguid)));
    cbor_map_put(options, cbor_new_text("rk"), cbor_new_bool(true));
    cbor_map_put(options, cbor_new_text("up"), cbor_new_bool(true));
    cbor_map_put(options, cbor_new_text("uv"), cbor_new_bool(true));
    cbor_map_put(response, cbor_new_uint(0x04), options);
    cbor_map_put(response, cbor_new_uint(0x05), cbor_new_uint(1200));

    return encode_response(CTAP2_OK, response, output, output_len);
}

static CborValue *build_cose_public_key(const TpmCredential *tpm)
{
    CborValue *key;
    CborValue *x;
    CborValue *y;

    if (!tpm)
        return NULL;

    key = cbor_new_map();
    x = cbor_new_bytes(tpm->x, TPM_P256_COORDINATE_SIZE);
    y = cbor_new_bytes(tpm->y, TPM_P256_COORDINATE_SIZE);
    if (!key || !x || !y) {
        cbor_free(key);
        cbor_free(x);
        cbor_free(y);
        return NULL;
    }

    cbor_map_put(key, cbor_new_uint(1), cbor_new_uint(2));
    cbor_map_put(key, cbor_new_uint(3), cbor_new_int(-7));
    cbor_map_put(key, cbor_new_int(-1), cbor_new_uint(1));
    cbor_map_put(key, cbor_new_int(-2), x);
    cbor_map_put(key, cbor_new_int(-3), y);
    return key;
}

static int validate_pubkey_cred_params(const CborValue *params)
{
    if (!params || !cbor_is_type(params, CBOR_TYPE_ARRAY))
        return -1;

    for (size_t i = 0; i < params->array.count; i++) {
        CborValue *entry = params->array.items[i];
        CborValue *type;
        CborValue *alg = NULL;

        if (!entry || !cbor_is_type(entry, CBOR_TYPE_MAP))
            continue;

        type = cbor_map_get_text(entry, "type");
        for (size_t j = 0; j < entry->map.count; j++) {
            CborValue *key = entry->map.keys[j];
            if (key && cbor_is_type(key, CBOR_TYPE_TEXT) && key->text.data &&
                strcmp(key->text.data, "alg") == 0) {
                alg = entry->map.values[j];
                break;
            }
        }

        if (type && cbor_is_type(type, CBOR_TYPE_TEXT) && type->text.data &&
            strcmp(type->text.data, "public-key") == 0 &&
            alg && cbor_is_type(alg, CBOR_TYPE_NEGATIVE) && alg->int_value == -7)
            return 0;
    }

    return -1;
}

static int build_authenticator_data(
    const char *rp_id,
    const WebAuthnCredential *credential,
    uint8_t **auth_data,
    size_t *auth_data_len)
{
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    uint8_t *buffer = NULL;
    size_t length = 0;
    CborValue *cose_key = NULL;
    uint8_t *cose_encoded = NULL;
    size_t cose_length = 0;
    uint8_t flags = 0x01 | 0x40;
    static const uint8_t aaguid[16] = {
        0x47, 0x4e, 0x57, 0x41, 0x55, 0x54, 0x48, 0x4e,
        0x2d, 0x54, 0x50, 0x4d, 0x2d, 0x30, 0x30, 0x31
    };

    if (!rp_id || !credential || !auth_data || !auth_data_len)
        return -1;

    if (ctap_is_user_verified())
        flags |= 0x04;

    *auth_data = NULL;
    *auth_data_len = 0;
    SHA256((const unsigned char *)rp_id, strlen(rp_id), rp_id_hash);

    if (append_bytes(&buffer, &length, rp_id_hash, sizeof(rp_id_hash)) != 0 ||
        append_bytes(&buffer, &length, &flags, 1) != 0 ||
        append_u32_be(&buffer, &length, credential->sign_count) != 0 ||
        append_bytes(&buffer, &length, aaguid, sizeof(aaguid)) != 0 ||
        credential->id_len > UINT16_MAX ||
        append_u16_be(&buffer, &length, (uint16_t)credential->id_len) != 0 ||
        append_bytes(&buffer, &length, credential->id, credential->id_len) != 0)
        goto fail;

    cose_key = build_cose_public_key(&credential->tpm);
    if (!cose_key || cbor_encode(cose_key, &cose_encoded, &cose_length) != 0)
        goto fail;
    if (append_bytes(&buffer, &length, cose_encoded, cose_length) != 0)
        goto fail;

    cbor_free(cose_key);
    free(cose_encoded);
    *auth_data = buffer;
    *auth_data_len = length;
    return 0;

fail:
    cbor_free(cose_key);
    free(cose_encoded);
    free(buffer);
    return -1;
}

int ctap_make_credential(
    const uint8_t *request,
    size_t request_len,
    uint8_t **output,
    size_t *output_len)
{
    CborValue *request_map = NULL;
    CborValue *client_data_hash;
    CborValue *rp;
    CborValue *user;
    CborValue *pubkey_params;
    CborValue *rp_id;
    CborValue *user_id = NULL;
    CborValue *user_name;
    CborValue *display_name;
    WebAuthnCredential credential;
    char data_directory[4096];
    uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    CborValue *response = NULL;
    CborValue *att_stmt = NULL;
    size_t offset = 0;

    credential_init(&credential);
    if (!output || !output_len)
        return -1;
    *output = NULL;
    *output_len = 0;

    if (!ctap_initialized) {
        set_error(output, output_len, CTAP2_ERR_PROCESSING);
        goto fail;
    }
    if (!request || request_len == 0 || request_len > CTAP_MAX_REQUEST_SIZE) {
        set_error(output, output_len, CTAP2_ERR_INVALID_LENGTH);
        goto fail;
    }
    if (cbor_decode(request, request_len, &offset, &request_map) != 0 ||
        offset != request_len || !request_map ||
        !cbor_is_type(request_map, CBOR_TYPE_MAP)) {
        set_error(output, output_len, CTAP2_ERR_INVALID_CBOR);
        goto fail;
    }

    client_data_hash = cbor_map_get_uint(request_map, 0x01);
    rp = cbor_map_get_uint(request_map, 0x02);
    user = cbor_map_get_uint(request_map, 0x03);
    pubkey_params = cbor_map_get_uint(request_map, 0x04);

    if (!client_data_hash || !rp || !user || !pubkey_params ||
        !cbor_is_type(client_data_hash, CBOR_TYPE_BYTES) ||
        client_data_hash->bytes.length != SHA256_DIGEST_LENGTH ||
        !cbor_is_type(rp, CBOR_TYPE_MAP) ||
        !cbor_is_type(user, CBOR_TYPE_MAP) ||
        validate_pubkey_cred_params(pubkey_params) != 0) {
        set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
        goto fail;
    }

    rp_id = cbor_map_get_text(rp, "id");
    user_name = cbor_map_get_text(user, "name");
    display_name = cbor_map_get_text(user, "displayName");
    for (size_t i = 0; i < user->map.count; i++) {
        CborValue *key = user->map.keys[i];
        if (key && cbor_is_type(key, CBOR_TYPE_TEXT) && key->text.data &&
            strcmp(key->text.data, "id") == 0) {
            user_id = user->map.values[i];
            break;
        }
    }

    if (!rp_id || !cbor_is_type(rp_id, CBOR_TYPE_TEXT) || !rp_id->text.data ||
        rp_id->text.length == 0 || rp_id->text.length >= WEBAUTHN_RP_ID_MAX ||
        !user_id || !cbor_is_type(user_id, CBOR_TYPE_BYTES) ||
        user_id->bytes.length == 0 || user_id->bytes.length > WEBAUTHN_USER_HANDLE_MAX ||
        !user_name || !cbor_is_type(user_name, CBOR_TYPE_TEXT) || !user_name->text.data) {
        set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
        goto fail;
    }

    if (!display_name || !cbor_is_type(display_name, CBOR_TYPE_TEXT) ||
        !display_name->text.data)
        display_name = user_name;

    if (get_data_directory(data_directory, sizeof(data_directory)) != 0) {
        set_error(output, output_len, CTAP2_ERR_OTHER);
        goto fail;
    }

    {
        CborValue *exclude_list = cbor_map_get_uint(request_map, 0x05);
        if (exclude_list) {
            if (!cbor_is_type(exclude_list, CBOR_TYPE_ARRAY)) {
                set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
                goto fail;
            }

            for (size_t i = 0; i < exclude_list->array.count; i++) {
                CborValue *descriptor = exclude_list->array.items[i];
                CborValue *type;
                CborValue *id = NULL;

                if (!descriptor || !cbor_is_type(descriptor, CBOR_TYPE_MAP)) {
                    set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
                    goto fail;
                }
                type = cbor_map_get_text(descriptor, "type");
                for (size_t j = 0; j < descriptor->map.count; j++) {
                    CborValue *key = descriptor->map.keys[j];
                    if (key && cbor_is_type(key, CBOR_TYPE_TEXT) && key->text.data &&
                        strcmp(key->text.data, "id") == 0) {
                        id = descriptor->map.values[j];
                        break;
                    }
                }

                if (!type || !cbor_is_type(type, CBOR_TYPE_TEXT) || !type->text.data ||
                    strcmp(type->text.data, "public-key") != 0 ||
                    !id || !cbor_is_type(id, CBOR_TYPE_BYTES) || id->bytes.length == 0) {
                    set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
                    goto fail;
                }

                if (id->bytes.length == TPM_CREDENTIAL_ID_SIZE) {
                    WebAuthnCredential excluded;
                    credential_init(&excluded);
                    if (credential_load(&excluded, data_directory,
                                        id->bytes.data, id->bytes.length) == 0) {
                        credential_free(&excluded);
                        set_error(output, output_len, CTAP2_ERR_CREDENTIAL_EXCLUDED);
                        goto fail;
                    }
                    credential_free(&excluded);
                }
            }
        }
    }

    if (credential_create(&ctap_tpm, &credential, rp_id->text.data,
                          user_id->bytes.data, user_id->bytes.length,
                          user_name->text.data, display_name->text.data) != 0 ||
        credential_save(&credential, data_directory) != 0 ||
        build_authenticator_data(rp_id->text.data, &credential,
                                 &auth_data, &auth_data_len) != 0) {
        set_error(output, output_len, CTAP2_ERR_OTHER);
        goto fail;
    }

    response = cbor_new_map();
    att_stmt = cbor_new_map();
    if (!response || !att_stmt) {
        set_error(output, output_len, CTAP2_ERR_OTHER);
        goto fail;
    }

    cbor_map_put(response, cbor_new_uint(0x01), cbor_new_text("none"));
    cbor_map_put(response, cbor_new_uint(0x02),
                 cbor_new_bytes(auth_data, auth_data_len));
    cbor_map_put(response, cbor_new_uint(0x03), att_stmt);
    att_stmt = NULL;

    free(auth_data);
    auth_data = NULL;
    cbor_free(request_map);
    request_map = NULL;
    credential_free(&credential);
    return encode_response(CTAP2_OK, response, output, output_len);

fail:
    free(auth_data);
    cbor_free(att_stmt);
    cbor_free(response);
    cbor_free(request_map);
    credential_free(&credential);
    return 0;
}

typedef struct {
    const char *rp_id;
    CtapAssertionState *state;
} CtapCredentialDiscovery;

static int discover_credential_callback(
    const WebAuthnCredential *credential,
    void *user_data)
{
    CtapCredentialDiscovery *discovery = user_data;

    if (!credential || !discovery || !discovery->rp_id || !discovery->state)
        return 0;
    if (strcmp(credential->rp_id, discovery->rp_id) != 0)
        return 0;
    if (discovery->state->count >= CTAP_MAX_ASSERTION_CREDENTIALS)
        return 1;

    memcpy(discovery->state->ids[discovery->state->count],
           credential->id, TPM_CREDENTIAL_ID_SIZE);
    discovery->state->count++;
    return 0;
}

static int assertion_state_timed_out(void)
{
    time_t now;

    if (!ctap_assertion_state.active)
        return 1;

    now = time(NULL);
    if (now == (time_t)-1 ||
        now < ctap_assertion_state.last_activity ||
        difftime(now, ctap_assertion_state.last_activity) >
            CTAP_ASSERTION_TIMEOUT_SECONDS) {
        ctap_assertion_state_reset();
        return 1;
    }

    return 0;
}

static int build_assertion_response(
    WebAuthnCredential *credential,
    const char *rp_id,
    const uint8_t client_data_hash[SHA256_DIGEST_LENGTH],
    int include_user,
    int include_count,
    size_t count,
    uint8_t **output,
    size_t *output_len)
{
    uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
    uint8_t flags = 0x01;
    uint32_t sign_count;
    uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    uint8_t *signed_data = NULL;
    size_t signed_data_len = 0;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t r[TPM_P256_COORDINATE_SIZE];
    uint8_t s[TPM_P256_COORDINATE_SIZE];
    uint8_t *der = NULL;
    size_t der_len = 0;
    CborValue *response = NULL;
    CborValue *descriptor = NULL;
    char data_directory[4096];
    int result = -1;

    if (!credential || !rp_id || !client_data_hash || !output || !output_len)
        return -1;

    *output = NULL;
    *output_len = 0;
    if (ctap_is_user_verified())
        flags |= 0x04;

    SHA256((const unsigned char *)rp_id, strlen(rp_id), rp_id_hash);
    sign_count = credential_next_sign_count(credential);

    if (append_bytes(&auth_data, &auth_data_len, rp_id_hash, sizeof(rp_id_hash)) != 0 ||
        append_bytes(&auth_data, &auth_data_len, &flags, 1) != 0 ||
        append_u32_be(&auth_data, &auth_data_len, sign_count) != 0 ||
        append_bytes(&signed_data, &signed_data_len, auth_data, auth_data_len) != 0 ||
        append_bytes(&signed_data, &signed_data_len, client_data_hash,
                     SHA256_DIGEST_LENGTH) != 0)
        goto cleanup;

    SHA256(signed_data, signed_data_len, digest);
    if (tpm_load_key(&ctap_tpm, &credential->tpm) != 0)
        goto cleanup;
    if (tpm_sign_digest(&ctap_tpm, digest, r, s) != 0) {
        tpm_flush_key(&ctap_tpm);
        goto cleanup;
    }
    tpm_flush_key(&ctap_tpm);

    if (encode_ecdsa_der(r, s, &der, &der_len) != 0)
        goto cleanup;
    if (get_data_directory(data_directory, sizeof(data_directory)) != 0 ||
        credential_save(credential, data_directory) != 0)
        goto cleanup;

    descriptor = cbor_new_map();
    response = cbor_new_map();
    if (!descriptor || !response)
        goto cleanup;

    cbor_map_put(descriptor, cbor_new_text("type"), cbor_new_text("public-key"));
    cbor_map_put(descriptor, cbor_new_text("id"),
                 cbor_new_bytes(credential->id, credential->id_len));
    cbor_map_put(response, cbor_new_uint(0x01), descriptor);
    descriptor = NULL;
    cbor_map_put(response, cbor_new_uint(0x02),
                 cbor_new_bytes(auth_data, auth_data_len));
    cbor_map_put(response, cbor_new_uint(0x03),
                 cbor_new_bytes(der, der_len));

    if (include_user && ctap_is_user_verified()) {
        CborValue *user = cbor_new_map();
        if (!user)
            goto cleanup;
        cbor_map_put(user, cbor_new_text("id"),
                     cbor_new_bytes(credential->user_handle,
                                    credential->user_handle_len));
        if (credential->user_name[0])
            cbor_map_put(user, cbor_new_text("name"),
                         cbor_new_text(credential->user_name));
        if (credential->display_name[0])
            cbor_map_put(user, cbor_new_text("displayName"),
                         cbor_new_text(credential->display_name));
        cbor_map_put(response, cbor_new_uint(0x04), user);
    }

    if (include_count && count > 1)
        cbor_map_put(response, cbor_new_uint(0x05), cbor_new_uint(count));

    result = encode_response(CTAP2_OK, response, output, output_len);
    response = NULL;

cleanup:
    cbor_free(descriptor);
    cbor_free(response);
    free(auth_data);
    free(signed_data);
    free(der);
    return result;
}

static int load_assertion_credential(
    const char *data_directory,
    const uint8_t id[TPM_CREDENTIAL_ID_SIZE],
    const char *rp_id,
    WebAuthnCredential *credential)
{
    credential_init(credential);
    if (credential_load(credential, data_directory, id,
                        TPM_CREDENTIAL_ID_SIZE) != 0)
        return -1;
    if (strcmp(credential->rp_id, rp_id) != 0) {
        credential_free(credential);
        return -1;
    }
    return 0;
}

int ctap_get_assertion(
    const uint8_t *request,
    size_t request_len,
    uint8_t **output,
    size_t *output_len)
{
    CborValue *request_map = NULL;
    CborValue *rp_id_value;
    CborValue *client_data_hash;
    CborValue *allow_list;
    char data_directory[4096];
    size_t offset = 0;
    int has_allow_list;
    WebAuthnCredential credential;
    int result;

    if (!output || !output_len)
        return -1;
    *output = NULL;
    *output_len = 0;

    if (!ctap_initialized) {
        set_error(output, output_len, CTAP2_ERR_PROCESSING);
        return 0;
    }

    ctap_assertion_state_reset();
    if (!request || request_len == 0 || request_len > CTAP_MAX_REQUEST_SIZE) {
        set_error(output, output_len, CTAP2_ERR_INVALID_LENGTH);
        return 0;
    }

    if (cbor_decode(request, request_len, &offset, &request_map) != 0 ||
        offset != request_len || !request_map ||
        !cbor_is_type(request_map, CBOR_TYPE_MAP)) {
        cbor_free(request_map);
        set_error(output, output_len, CTAP2_ERR_INVALID_CBOR);
        return 0;
    }

    rp_id_value = cbor_map_get_uint(request_map, 0x01);
    client_data_hash = cbor_map_get_uint(request_map, 0x02);
    allow_list = cbor_map_get_uint(request_map, 0x03);

    if (!rp_id_value || !client_data_hash ||
        !cbor_is_type(rp_id_value, CBOR_TYPE_TEXT) || !rp_id_value->text.data ||
        rp_id_value->text.length == 0 || rp_id_value->text.length >= WEBAUTHN_RP_ID_MAX ||
        !cbor_is_type(client_data_hash, CBOR_TYPE_BYTES) ||
        client_data_hash->bytes.length != SHA256_DIGEST_LENGTH) {
        cbor_free(request_map);
        set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
        return 0;
    }

    has_allow_list = allow_list != NULL;
    if (has_allow_list &&
        (!cbor_is_type(allow_list, CBOR_TYPE_ARRAY) || allow_list->array.count == 0)) {
        cbor_free(request_map);
        set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
        return 0;
    }

    if (get_data_directory(data_directory, sizeof(data_directory)) != 0) {
        cbor_free(request_map);
        set_error(output, output_len, CTAP2_ERR_OTHER);
        return 0;
    }

    strncpy(ctap_assertion_state.rp_id, rp_id_value->text.data,
            sizeof(ctap_assertion_state.rp_id) - 1);
    memcpy(ctap_assertion_state.client_data_hash,
           client_data_hash->bytes.data, SHA256_DIGEST_LENGTH);

    if (has_allow_list) {
        for (size_t i = 0; i < allow_list->array.count; i++) {
            CborValue *descriptor = allow_list->array.items[i];
            CborValue *type;
            CborValue *id = NULL;

            if (!descriptor || !cbor_is_type(descriptor, CBOR_TYPE_MAP)) {
                cbor_free(request_map);
                ctap_assertion_state_reset();
                set_error(output, output_len, CTAP2_ERR_INVALID_PARAMETER);
                return 0;
            }

            type = cbor_map_get_text(descriptor, "type");
            for (size_t j = 0; j < descriptor->map.count; j++) {
                CborValue *key = descriptor->map.keys[j];
                if (key && cbor_is_type(key, CBOR_TYPE_TEXT) && key->text.data &&
                    strcmp(key->text.data, "id") == 0) {
                    id = descriptor->map.values[j];
                    break;
                }
            }

            if (!type || !cbor_is_type(type, CBOR_TYPE_TEXT) || !type->text.data ||
                strcmp(type->text.data, "public-key") != 0 ||
                !id || !cbor_is_type(id, CBOR_TYPE_BYTES) ||
                id->bytes.length != TPM_CREDENTIAL_ID_SIZE)
                continue;

            credential_init(&credential);
            if (credential_load(&credential, data_directory,
                                id->bytes.data, id->bytes.length) == 0 &&
                strcmp(credential.rp_id, rp_id_value->text.data) == 0 &&
                ctap_assertion_state.count < CTAP_MAX_ASSERTION_CREDENTIALS) {
                memcpy(ctap_assertion_state.ids[ctap_assertion_state.count],
                       credential.id, TPM_CREDENTIAL_ID_SIZE);
                ctap_assertion_state.count++;
            }
            credential_free(&credential);
        }
    } else {
        CtapCredentialDiscovery discovery = {
            .rp_id = rp_id_value->text.data,
            .state = &ctap_assertion_state
        };

        if (credential_enumerate(data_directory,
                                 discover_credential_callback,
                                 &discovery) != 0) {
            cbor_free(request_map);
            ctap_assertion_state_reset();
            set_error(output, output_len, CTAP2_ERR_OTHER);
            return 0;
        }
    }

    cbor_free(request_map);
    if (ctap_assertion_state.count == 0) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_NO_CREDENTIALS);
        return 0;
    }

    if (load_assertion_credential(data_directory,
                                  ctap_assertion_state.ids[0],
                                  ctap_assertion_state.rp_id,
                                  &credential) != 0) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_NO_CREDENTIALS);
        return 0;
    }

    result = build_assertion_response(
        &credential,
        ctap_assertion_state.rp_id,
        ctap_assertion_state.client_data_hash,
        !has_allow_list,
        1,
        ctap_assertion_state.count,
        output,
        output_len);
    credential_free(&credential);

    if (result != 0) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_OTHER);
        return 0;
    }

    ctap_assertion_state.next_index = 1;
    ctap_assertion_state.last_activity = time(NULL);
    ctap_assertion_state.active = ctap_assertion_state.count > 1;
    return 0;
}

int ctap_get_next_assertion(uint8_t **output, size_t *output_len)
{
    char data_directory[4096];
    WebAuthnCredential credential;
    int result;

    if (!output || !output_len)
        return -1;
    *output = NULL;
    *output_len = 0;

    if (assertion_state_timed_out() ||
        ctap_assertion_state.next_index >= ctap_assertion_state.count) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_NOT_ALLOWED);
        return 0;
    }

    if (get_data_directory(data_directory, sizeof(data_directory)) != 0) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_OTHER);
        return 0;
    }

    if (load_assertion_credential(
            data_directory,
            ctap_assertion_state.ids[ctap_assertion_state.next_index],
            ctap_assertion_state.rp_id,
            &credential) != 0) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_NO_CREDENTIALS);
        return 0;
    }

    result = build_assertion_response(
        &credential,
        ctap_assertion_state.rp_id,
        ctap_assertion_state.client_data_hash,
        1,
        0,
        0,
        output,
        output_len);
    credential_free(&credential);

    if (result != 0) {
        ctap_assertion_state_reset();
        set_error(output, output_len, CTAP2_ERR_OTHER);
        return 0;
    }

    ctap_assertion_state.next_index++;
    ctap_assertion_state.last_activity = time(NULL);
    if (ctap_assertion_state.next_index >= ctap_assertion_state.count)
        ctap_assertion_state.active = 0;

    return 0;
}

int ctap_process(
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len)
{
    uint8_t command;

    if (!output || !output_len)
        return -1;
    *output = NULL;
    *output_len = 0;

    if (!ctap_initialized) {
        set_error(output, output_len, CTAP2_ERR_PROCESSING);
        return 0;
    }
    if (!input || input_len < 1) {
        set_error(output, output_len, CTAP2_ERR_INVALID_LENGTH);
        return 0;
    }

    command = input[0];
    switch (command) {
    case CTAP_CMD_GET_INFO:
        if (input_len != 1) {
            set_error(output, output_len, CTAP2_ERR_INVALID_LENGTH);
            return 0;
        }
        return ctap_get_info(output, output_len);

    case CTAP_CMD_MAKE_CREDENTIAL:
        ctap_assertion_state_reset();
        return ctap_make_credential(input + 1, input_len - 1,
                                    output, output_len);

    case CTAP_CMD_GET_ASSERTION:
        return ctap_get_assertion(input + 1, input_len - 1,
                                  output, output_len);

    case CTAP_CMD_GET_NEXT_ASSERTION:
        return ctap_get_next_assertion(output, output_len);

    default:
        set_error(output, output_len, CTAP2_ERR_INVALID_COMMAND);
        return 0;
    }
}
