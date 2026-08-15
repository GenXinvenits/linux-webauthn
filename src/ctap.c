#include "ctap.h"

#include "cbor.h"

#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define CTAP_MAX_REQUEST_SIZE 1200

/*
 * CTAP authenticator state.
 *
 * The TPM context is kept for the lifetime of the CTAP layer.
 * Individual signing keys are flushed by the TPM backend when
 * they are no longer required.
 */
static int ctap_initialized = 0;
static TpmContext ctap_tpm;

/*
 * User verification state for the current CTAP operation.
 *
 * The D-Bus layer performs the physical fingerprint verification
 * and sets this flag only after a successful match.
 */
static int ctap_user_verified = 0;

static int encode_ecdsa_der(
    const uint8_t r[32],
    const uint8_t s[32],
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
    size_t total_len;
    uint8_t *buffer;
    size_t pos = 0;

    if (!r ||
        !s ||
        !output ||
        !output_len)
        return -1;

    *output = NULL;
    *output_len = 0;

    /*
     * Remove unnecessary leading zeroes.
     */
    while (r_offset < 31 && r[r_offset] == 0)
        r_offset++;

    while (s_offset < 31 && s[s_offset] == 0)
        s_offset++;

    r_len = 32 - r_offset;
    s_len = 32 - s_offset;

    /*
     * DER INTEGER is signed. If the high bit is set,
     * prepend a zero byte to keep the integer positive.
     */
    r_pad = (r[r_offset] & 0x80) != 0;
    s_pad = (s[s_offset] & 0x80) != 0;

    body_len =
        2 + r_len + (size_t)r_pad +
        2 + s_len + (size_t)s_pad;

    /*
     * P-256 ECDSA signatures are small enough that the
     * short-form DER length is sufficient.
     */
    if (body_len > 127)
        return -1;

    total_len = 2 + body_len;

    buffer = malloc(total_len);

    if (!buffer)
        return -1;

    buffer[pos++] = 0x30;
    buffer[pos++] = (uint8_t)body_len;

    buffer[pos++] = 0x02;
    buffer[pos++] = (uint8_t)(r_len + (size_t)r_pad);

    if (r_pad)
        buffer[pos++] = 0x00;

    memcpy(
        buffer + pos,
        r + r_offset,
        r_len);

    pos += r_len;

    buffer[pos++] = 0x02;
    buffer[pos++] = (uint8_t)(s_len + (size_t)s_pad);

    if (s_pad)
        buffer[pos++] = 0x00;

    memcpy(
        buffer + pos,
        s + s_offset,
        s_len);

    pos += s_len;

    *output = buffer;
    *output_len = pos;

    return 0;
}

static CborValue *cbor_map_find_text_key(
    CborValue *map,
    const char *name)
{
    if (!map ||
        !name ||
        !cbor_is_type(map, CBOR_TYPE_MAP))
        return NULL;

    for (size_t i = 0; i < map->map.count; i++) {
        CborValue *key = map->map.keys[i];

        if (key &&
            cbor_is_type(key, CBOR_TYPE_TEXT) &&
            key->text.data &&
            strcmp(key->text.data, name) == 0) {
            return map->map.values[i];
        }
    }

    return NULL;
}

static void set_error(
    uint8_t **output,
    size_t *output_len,
    uint8_t status)
{
    uint8_t *buffer;

    if (!output || !output_len)
        return;

    buffer = malloc(1);

    if (!buffer) {
        *output = NULL;
        *output_len = 0;
        return;
    }

    buffer[0] = status;

    *output = buffer;
    *output_len = 1;
}

static int get_data_directory(
    char *path,
    size_t path_size)
{
    const char *xdg;
    const char *home;

    if (!path || path_size == 0)
        return -1;

    xdg = getenv("XDG_DATA_HOME");

    if (xdg && xdg[0] != '\0') {
        if (snprintf(
                path,
                path_size,
                "%s/linux-webauthn",
                xdg) >= (int)path_size) {
            return -1;
        }

        return 0;
    }

    home = getenv("HOME");

    if (!home || home[0] == '\0')
        return -1;

    if (snprintf(
            path,
            path_size,
            "%s/.local/share/linux-webauthn",
            home) >= (int)path_size) {
        return -1;
    }

    return 0;
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

    if (!value)
        return -1;

    if (cbor_encode(value, &encoded, &encoded_len) != 0) {
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

    memcpy(
        *output + 1,
        encoded,
        encoded_len);

    *output_len = encoded_len + 1;

    free(encoded);

    return 0;
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

    new_buffer = realloc(
        *buffer,
        *length + data_length);

    if (!new_buffer)
        return -1;

    memcpy(
        new_buffer + *length,
        data,
        data_length);

    *buffer = new_buffer;
    *length += data_length;

    return 0;
}

static int append_u16_be(
    uint8_t **buffer,
    size_t *length,
    uint16_t value)
{
    uint8_t bytes[2];

    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xff);

    return append_bytes(
        buffer,
        length,
        bytes,
        sizeof(bytes));
}

static int append_u32_be(
    uint8_t **buffer,
    size_t *length,
    uint32_t value)
{
    uint8_t bytes[4];

    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)(value & 0xff);

    return append_bytes(
        buffer,
        length,
        bytes,
        sizeof(bytes));
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

    if (ctap_initialized)
        tpm_cleanup(&ctap_tpm);

    memset(&ctap_tpm, 0, sizeof(ctap_tpm));
    ctap_initialized = 0;
}

int ctap_get_info(
    uint8_t **output,
    size_t *output_len)
{
    CborValue *response;
    CborValue *versions;
    CborValue *extensions;
    CborValue *options;

    if (!output || !output_len)
        return -1;

    response = cbor_new_map();
    versions = cbor_new_array();
    extensions = cbor_new_array();
    options = cbor_new_map();

    if (!response || !versions || !extensions || !options) {
        cbor_free(response);
        cbor_free(versions);
        cbor_free(extensions);
        cbor_free(options);
        return -1;
    }

    cbor_array_append(
        versions,
        cbor_new_text("FIDO_2_0"));

    cbor_array_append(
        versions,
        cbor_new_text("FIDO_2_1"));

    cbor_map_put(
        response,
        cbor_new_uint(0x01),
        versions);

    cbor_map_put(
        response,
        cbor_new_uint(0x02),
        extensions);

    {
        static const uint8_t aaguid[16] = {
            0x47, 0x4e, 0x57, 0x41,
            0x55, 0x54, 0x48, 0x4e,
            0x2d, 0x54, 0x50, 0x4d,
            0x2d, 0x30, 0x30, 0x31
        };

        cbor_map_put(
            response,
            cbor_new_uint(0x03),
            cbor_new_bytes(aaguid, sizeof(aaguid)));
    }

    cbor_map_put(
        options,
        cbor_new_text("rk"),
        cbor_new_bool(true));

    cbor_map_put(
        options,
        cbor_new_text("up"),
        cbor_new_bool(true));

    /*
     * This authenticator performs user verification through the
     * system fingerprint sensor before MakeCredential/GetAssertion.
     */
    cbor_map_put(
        options,
        cbor_new_text("uv"),
        cbor_new_bool(true));

    cbor_map_put(
        response,
        cbor_new_uint(0x04),
        options);

    cbor_map_put(
        response,
        cbor_new_uint(0x05),
        cbor_new_uint(1200));

    return encode_response(
        CTAP2_OK,
        response,
        output,
        output_len);
}

/*
 * Construct the COSE_Key for an ES256 credential.
 *
 * {
 *   1: 2,       // kty = EC2
 *   3: -7,      // alg = ES256
 *  -1: 1,       // crv = P-256
 *  -2: x,
 *  -3: y
 * }
 */
static CborValue *build_cose_public_key(
    const TpmCredential *tpm)
{
    CborValue *key;
    CborValue *x;
    CborValue *y;

    if (!tpm)
        return NULL;

    key = cbor_new_map();
    x = cbor_new_bytes(
        tpm->x,
        TPM_P256_COORDINATE_SIZE);
    y = cbor_new_bytes(
        tpm->y,
        TPM_P256_COORDINATE_SIZE);

    if (!key || !x || !y) {
        cbor_free(key);
        cbor_free(x);
        cbor_free(y);
        return NULL;
    }

    cbor_map_put(
        key,
        cbor_new_uint(1),
        cbor_new_uint(2));

    cbor_map_put(
        key,
        cbor_new_uint(3),
        cbor_new_int(-7));

    cbor_map_put(
        key,
        cbor_new_int(-1),
        cbor_new_uint(1));

    cbor_map_put(
        key,
        cbor_new_int(-2),
        x);

    cbor_map_put(
        key,
        cbor_new_int(-3),
        y);

    return key;
}

static int validate_pubkey_cred_params(
    const CborValue *params)
{
    if (!params ||
        !cbor_is_type(params, CBOR_TYPE_ARRAY)) {
        return -1;
    }

    for (size_t i = 0; i < params->array.count; i++) {
        CborValue *entry = params->array.items[i];

        CborValue *type;
        CborValue *alg = NULL;

        if (!entry ||
            !cbor_is_type(entry, CBOR_TYPE_MAP)) {
            continue;
        }

        /*
         * WebAuthn pubKeyCredParams uses text keys:
         *
         * {
         *     "type": "public-key",
         *     "alg": -7
         * }
         */
        type = cbor_map_get_text(entry, "type");

        for (size_t j = 0; j < entry->map.count; j++) {
            CborValue *key = entry->map.keys[j];

            if (key &&
                cbor_is_type(key, CBOR_TYPE_TEXT) &&
                key->text.data &&
                strcmp(key->text.data, "alg") == 0) {
                alg = entry->map.values[j];
                break;
            }
        }

        if (type &&
            cbor_is_type(type, CBOR_TYPE_TEXT) &&
            type->text.data &&
            strcmp(type->text.data, "public-key") == 0 &&
            alg &&
            cbor_is_type(alg, CBOR_TYPE_NEGATIVE) &&
            alg->int_value == -7) {
            return 0;
        }
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

    /*
     * Authenticator flags:
     *
     * UP = 0x01
     * UV = 0x04, only when the current CTAP operation has
     *      successfully completed user verification.
     * AT = 0x40
     */
    uint8_t flags = 0x01; /* UP */

    if (ctap_is_user_verified())
        flags |= 0x04;    /* UV */

    flags |= 0x40;        /* AT */

    static const uint8_t aaguid[16] = {
        0x47, 0x4e, 0x57, 0x41,
        0x55, 0x54, 0x48, 0x4e,
        0x2d, 0x54, 0x50, 0x4d,
        0x2d, 0x30, 0x30, 0x31
    };

    if (!rp_id ||
        !credential ||
        !auth_data ||
        !auth_data_len) {
        return -1;
    }

    *auth_data = NULL;
    *auth_data_len = 0;

    SHA256(
        (const unsigned char *)rp_id,
        strlen(rp_id),
        rp_id_hash);

    if (append_bytes(
            &buffer,
            &length,
            rp_id_hash,
            sizeof(rp_id_hash)) != 0)
        goto fail;

    if (append_bytes(
            &buffer,
            &length,
            &flags,
            sizeof(flags)) != 0)
        goto fail;

    if (append_u32_be(
            &buffer,
            &length,
            credential->sign_count) != 0)
        goto fail;

    if (append_bytes(
            &buffer,
            &length,
            aaguid,
            sizeof(aaguid)) != 0)
        goto fail;

    if (credential->id_len > UINT16_MAX)
        goto fail;

    if (append_u16_be(
            &buffer,
            &length,
            (uint16_t)credential->id_len) != 0)
        goto fail;

    if (append_bytes(
            &buffer,
            &length,
            credential->id,
            credential->id_len) != 0)
        goto fail;

    cose_key = build_cose_public_key(&credential->tpm);

    if (!cose_key)
        goto fail;

    if (cbor_encode(
            cose_key,
            &cose_encoded,
            &cose_length) != 0)
        goto fail;

    if (append_bytes(
            &buffer,
            &length,
            cose_encoded,
            cose_length) != 0)
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
    CborValue *options;

    CborValue *rp_id;
    CborValue *user_id;
    CborValue *user_name;
    CborValue *display_name;

    WebAuthnCredential credential;

    uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;

    CborValue *response = NULL;
    CborValue *att_stmt = NULL;

    char data_directory[4096];

    if (!output || !output_len)
        return -1;

    *output = NULL;
    *output_len = 0;

    credential_init(&credential);

    /*
     * ------------------------------------------------------------
     * CTAP initialization
     * ------------------------------------------------------------
     */

    if (!ctap_initialized) {
        set_error(
            output,
            output_len,
            CTAP2_ERR_PROCESSING);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Validate request length
     * ------------------------------------------------------------
     */

    if (!request ||
        request_len == 0 ||
        request_len > CTAP_MAX_REQUEST_SIZE) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_LENGTH);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Decode exactly one CBOR request
     * ------------------------------------------------------------
     */

    {
        size_t offset = 0;

        if (cbor_decode(
                request,
                request_len,
                &offset,
                &request_map) != 0 ||
            offset != request_len ||
            !request_map ||
            !cbor_is_type(
                request_map,
                CBOR_TYPE_MAP)) {

            cbor_free(request_map);
            request_map = NULL;

            set_error(
                output,
                output_len,
                CTAP2_ERR_INVALID_CBOR);

            goto fail;
        }
    }

    /*
     * ------------------------------------------------------------
     * Required parameters
     *
     * 0x01 = clientDataHash
     * 0x02 = rp
     * 0x03 = user
     * 0x04 = pubKeyCredParams
     * ------------------------------------------------------------
     */

    client_data_hash =
        cbor_map_get_uint(
            request_map,
            0x01);

    rp =
        cbor_map_get_uint(
            request_map,
            0x02);

    user =
        cbor_map_get_uint(
            request_map,
            0x03);

    pubkey_params =
        cbor_map_get_uint(
            request_map,
            0x04);

    if (!client_data_hash ||
        !rp ||
        !user ||
        !pubkey_params) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_MISSING_PARAMETER);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Validate clientDataHash
     * ------------------------------------------------------------
     */

    if (!cbor_is_type(
            client_data_hash,
            CBOR_TYPE_BYTES) ||
        client_data_hash->bytes.length !=
            SHA256_DIGEST_LENGTH) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_PARAMETER);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Validate RP, user and algorithms
     * ------------------------------------------------------------
     */

    if (!cbor_is_type(
            rp,
            CBOR_TYPE_MAP) ||
        !cbor_is_type(
            user,
            CBOR_TYPE_MAP) ||
        validate_pubkey_cred_params(
            pubkey_params) != 0) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_PARAMETER);

        goto fail;
    }

    rp_id =
        cbor_map_get_text(
            rp,
            "id");

    user_name =
        cbor_map_get_text(
            user,
            "name");

    display_name =
        cbor_map_get_text(
            user,
            "displayName");

    /*
     * ------------------------------------------------------------
     * WebAuthn user.id is a CBOR byte string.
     * ------------------------------------------------------------
     */

    user_id = NULL;

    for (size_t i = 0;
         i < user->map.count;
         i++) {

        CborValue *key =
            user->map.keys[i];

        if (key &&
            cbor_is_type(
                key,
                CBOR_TYPE_TEXT) &&
            key->text.data &&
            strcmp(
                key->text.data,
                "id") == 0) {

            user_id =
                user->map.values[i];

            break;
        }
    }

    /*
     * ------------------------------------------------------------
     * Validate RP/user fields
     * ------------------------------------------------------------
     */

    if (!rp_id ||
        !cbor_is_type(
            rp_id,
            CBOR_TYPE_TEXT) ||
        !rp_id->text.data ||
        rp_id->text.length == 0 ||
        rp_id->text.length >=
            WEBAUTHN_RP_ID_MAX ||

        !user_id ||
        !cbor_is_type(
            user_id,
            CBOR_TYPE_BYTES) ||
        user_id->bytes.length == 0 ||
        user_id->bytes.length >
            WEBAUTHN_USER_HANDLE_MAX ||

        !user_name ||
        !cbor_is_type(
            user_name,
            CBOR_TYPE_TEXT) ||
        !user_name->text.data) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_PARAMETER);

        goto fail;
    }

    /*
     * displayName is optional from the authenticator's
     * perspective. Use user.name if it wasn't supplied.
     */

    if (!display_name ||
        !cbor_is_type(
            display_name,
            CBOR_TYPE_TEXT) ||
        !display_name->text.data) {

        display_name = user_name;
    }

    /*
     * ------------------------------------------------------------
     * Obtain credential storage directory.
     *
     * This must happen before processing excludeCredentials,
     * because excludeCredentials requires credential lookup.
     * ------------------------------------------------------------
     */

    if (get_data_directory(
            data_directory,
            sizeof(data_directory)) != 0) {

        fprintf(
            stderr,
            "WebAuthn: failed to determine credential "
            "data directory\n");

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * excludeCredentials / excludeList
     *
     * CTAP MakeCredential parameter 0x05.
     *
     * If one of the supplied credential IDs already exists,
     * authenticatorMakeCredential must return
     * CTAP2_ERR_CREDENTIAL_EXCLUDED.
     * ------------------------------------------------------------
     */

    {
        CborValue *exclude_list =
            cbor_map_get_uint(
                request_map,
                0x05);

        if (exclude_list) {

            if (!cbor_is_type(
                    exclude_list,
                    CBOR_TYPE_ARRAY)) {

                set_error(
                    output,
                    output_len,
                    CTAP2_ERR_INVALID_PARAMETER);

                goto fail;
            }

            for (size_t i = 0;
                 i < exclude_list->array.count;
                 i++) {

                CborValue *descriptor =
                    exclude_list->array.items[i];

                CborValue *type = NULL;
                CborValue *id = NULL;

                if (!descriptor ||
                    !cbor_is_type(
                        descriptor,
                        CBOR_TYPE_MAP)) {

                    set_error(
                        output,
                        output_len,
                        CTAP2_ERR_INVALID_PARAMETER);

                    goto fail;
                }

                type =
                    cbor_map_get_text(
                        descriptor,
                        "type");

                /*
                 * credentialDescriptor.id is a CBOR
                 * byte string, therefore find it directly.
                 */

                for (size_t j = 0;
                     j < descriptor->map.count;
                     j++) {

                    CborValue *key =
                        descriptor->map.keys[j];

                    if (key &&
                        cbor_is_type(
                            key,
                            CBOR_TYPE_TEXT) &&
                        key->text.data &&
                        strcmp(
                            key->text.data,
                            "id") == 0) {

                        id =
                            descriptor->map.values[j];

                        break;
                    }
                }

                /*
                 * Unsupported descriptor type.
                 */

                if (!type ||
                    !cbor_is_type(
                        type,
                        CBOR_TYPE_TEXT) ||
                    !type->text.data ||
                    strcmp(
                        type->text.data,
                        "public-key") != 0) {

                    set_error(
                        output,
                        output_len,
                        CTAP2_ERR_INVALID_PARAMETER);

                    goto fail;
                }

                /*
                 * Credential ID must be a byte string.
                 */

                if (!id ||
                    !cbor_is_type(
                        id,
                        CBOR_TYPE_BYTES) ||
                    id->bytes.length == 0) {

                    set_error(
                        output,
                        output_len,
                        CTAP2_ERR_INVALID_PARAMETER);

                    goto fail;
                }

                /*
                 * Our TPM credential IDs are fixed-size.
                 * A different-length ID cannot match one of
                 * our credentials.
                 */

                if (id->bytes.length !=
                    TPM_CREDENTIAL_ID_SIZE) {

                    continue;
                }

                WebAuthnCredential excluded;

                credential_init(
                    &excluded);

                /*
                 * credential_load() returns 0 when the
                 * credential exists and can be loaded.
                 */

                if (credential_load(
                        &excluded,
                        data_directory,
                        id->bytes.data,
                        id->bytes.length) == 0) {

                    fprintf(
                        stderr,
                        "WebAuthn: excluded credential found\n");

                    credential_free(
                        &excluded);

                    set_error(
                        output,
                        output_len,
                        CTAP2_ERR_CREDENTIAL_EXCLUDED);

                    goto fail;
                }

                credential_free(
                    &excluded);
            }
        }
    }

    /*
     * ------------------------------------------------------------
     * options (0x07)
     * ------------------------------------------------------------
     *
     * Fingerprint verification is performed by the D-Bus layer
     * before this CTAP operation is dispatched.
     *
     * ctap_user_verified is therefore consumed by
     * build_authenticator_data().
     */

    options =
        cbor_map_get_uint(
            request_map,
            0x07);

    (void)options;

    /*
     * ------------------------------------------------------------
     * Create TPM-backed credential
     * ------------------------------------------------------------
     */

    if (credential_create(
            &ctap_tpm,
            &credential,
            rp_id->text.data,
            user_id->bytes.data,
            user_id->bytes.length,
            user_name->text.data,
            display_name->text.data) != 0) {

        fprintf(
            stderr,
            "WebAuthn: credential_create() failed\n");

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Persist credential
     * ------------------------------------------------------------
     */

    if (credential_save(
            &credential,
            data_directory) != 0) {

        fprintf(
            stderr,
            "WebAuthn: failed to persist credential\n");

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Build authenticatorData
     * ------------------------------------------------------------
     *
     * This contains:
     *
     * rpIdHash
     * flags
     * signCount
     * AAGUID
     * credential ID
     * COSE public key
     */

    if (build_authenticator_data(
            rp_id->text.data,
            &credential,
            &auth_data,
            &auth_data_len) != 0) {

        fprintf(
            stderr,
            "WebAuthn: failed to build authenticatorData\n");

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * ------------------------------------------------------------
     * Construct CTAP MakeCredential response
     * ------------------------------------------------------------
     */

    response =
        cbor_new_map();

    att_stmt =
        cbor_new_map();

    if (!response ||
        !att_stmt) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * fmt = "none"
     *
     * No attestation statement is provided.
     */

    cbor_map_put(
        response,
        cbor_new_uint(0x01),
        cbor_new_text("none"));

    /*
     * authData
     */

    cbor_map_put(
        response,
        cbor_new_uint(0x02),
        cbor_new_bytes(
            auth_data,
            auth_data_len));

    /*
     * attStmt = {}
     */

    cbor_map_put(
        response,
        cbor_new_uint(0x03),
        att_stmt);

    /*
     * Ownership of attStmt has been transferred to response.
     */

    att_stmt = NULL;

    /*
     * ------------------------------------------------------------
     * Cleanup
     * ------------------------------------------------------------
     */

    free(auth_data);
    auth_data = NULL;

    credential_free(
        &credential);

    cbor_free(
        request_map);

    request_map = NULL;

    return encode_response(
        CTAP2_OK,
        response,
        output,
        output_len);

fail:

    free(auth_data);

    cbor_free(
        response);

    cbor_free(
        att_stmt);

    cbor_free(
        request_map);

    credential_free(
        &credential);

    return 0;
}

int ctap_get_assertion(
    const uint8_t *request,
    size_t request_len,
    uint8_t **output,
    size_t *output_len)
{
    CborValue *request_map = NULL;
    CborValue *client_data_hash;
    CborValue *rp_id_value;
    CborValue *allow_list;

    WebAuthnCredential credential;

    uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;

    uint8_t signature_digest[SHA256_DIGEST_LENGTH];
    uint8_t r[TPM_P256_COORDINATE_SIZE];
    uint8_t s[TPM_P256_COORDINATE_SIZE];

    uint8_t *der_signature = NULL;
    size_t der_signature_len = 0;

    uint8_t *signed_data = NULL;
    size_t signed_data_len = 0;

    CborValue *response = NULL;
    CborValue *credential_descriptor = NULL;

    char data_directory[4096];

    int credential_loaded = 0;

    if (!output || !output_len)
        return -1;

    *output = NULL;
    *output_len = 0;

    credential_init(&credential);

    if (!ctap_initialized) {
        set_error(
            output,
            output_len,
            CTAP2_ERR_PROCESSING);

        goto fail;
    }

    if (!request ||
        request_len == 0 ||
        request_len > CTAP_MAX_REQUEST_SIZE) {
        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_LENGTH);

        goto fail;
    }

    /*
     * Decode exactly one CBOR request.
     */
    {
        size_t offset = 0;

        if (cbor_decode(
                request,
                request_len,
                &offset,
                &request_map) != 0 ||
            offset != request_len ||
            !request_map ||
            !cbor_is_type(
                request_map,
                CBOR_TYPE_MAP)) {

            cbor_free(request_map);
            request_map = NULL;

            set_error(
                output,
                output_len,
                CTAP2_ERR_INVALID_CBOR);

            goto fail;
        }
    }

    /*
     * Required parameters:
     *
     * 0x01 rpId
     * 0x02 clientDataHash
     */
    rp_id_value =
        cbor_map_get_uint(request_map, 0x01);

    client_data_hash =
        cbor_map_get_uint(request_map, 0x02);

    if (!client_data_hash ||
        !rp_id_value) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_MISSING_PARAMETER);

        goto fail;
    }

    if (!cbor_is_type(
            client_data_hash,
            CBOR_TYPE_BYTES) ||
        client_data_hash->bytes.length != SHA256_DIGEST_LENGTH ||
        !cbor_is_type(
            rp_id_value,
            CBOR_TYPE_TEXT) ||
        !rp_id_value->text.data ||
        rp_id_value->text.length == 0 ||
        rp_id_value->text.length >= WEBAUTHN_RP_ID_MAX) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_PARAMETER);

        goto fail;
    }

    /*
     * allowList is optional in CTAP2.
     *
     * For this first implementation we require it because
     * credential discovery without an allowList requires
     * enumeration of all resident credentials.
     */
    allow_list =
        cbor_map_get_uint(request_map, 0x03);

    if (!allow_list ||
        !cbor_is_type(
            allow_list,
            CBOR_TYPE_ARRAY) ||
        allow_list->array.count == 0) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_NO_CREDENTIALS);

        goto fail;
    }

    /*
     * Locate a credential from allowList.
     *
     * Each descriptor is expected to look like:
     *
     * {
     *     "type": "public-key",
     *     "id": <credential ID>
     * }
     */
    if (get_data_directory(
            data_directory,
            sizeof(data_directory)) != 0) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    for (size_t i = 0;
         i < allow_list->array.count;
         i++) {

        CborValue *descriptor =
            allow_list->array.items[i];

        CborValue *type;
        CborValue *id;

        if (!descriptor ||
            !cbor_is_type(
                descriptor,
                CBOR_TYPE_MAP))
            continue;

        type =
            cbor_map_find_text_key(
                descriptor,
                "type");

        id =
            cbor_map_find_text_key(
                descriptor,
                "id");

        if (!type ||
            !cbor_is_type(
                type,
                CBOR_TYPE_TEXT) ||
            !type->text.data ||
            strcmp(
                type->text.data,
                "public-key") != 0)
            continue;

        if (!id ||
            !cbor_is_type(
                id,
                CBOR_TYPE_BYTES) ||
            id->bytes.length != TPM_CREDENTIAL_ID_SIZE)
            continue;

        credential_init(&credential);

        if (credential_load(
                &credential,
                data_directory,
                id->bytes.data,
                id->bytes.length) != 0) {

            credential_free(&credential);
            continue;
        }

        /*
         * The credential ID matched, but also make sure
         * the credential belongs to this RP.
         */
        if (strcmp(
                credential.rp_id,
                rp_id_value->text.data) != 0) {

            credential_free(&credential);
            continue;
        }

        credential_loaded = 1;
        break;
    }

    if (!credential_loaded) {
        set_error(
            output,
            output_len,
            CTAP2_ERR_NO_CREDENTIALS);

        goto fail;
    }

    /*
     * Build authenticatorData for an assertion.
     *
     * RP ID hash:
     *     SHA256(rpId)
     *
     * Flags:
     *     UP = 1
     *     UV = 1 when fingerprint verification succeeded
     *
     * Sign counter:
     *     incremented credential counter
     */
    {
        uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];

        /*
         * UP = 0x01
         * UV = 0x04 only when user verification actually
         * succeeded for this CTAP operation.
         */
        uint8_t flags = 0x01;

        if (ctap_is_user_verified())
            flags |= 0x04;

        uint32_t sign_count;

        SHA256(
            (const unsigned char *)
                rp_id_value->text.data,
            strlen(
                rp_id_value->text.data),
            rp_id_hash);

        sign_count =
            credential_next_sign_count(
                &credential);

        if (append_bytes(
                &auth_data,
                &auth_data_len,
                rp_id_hash,
                sizeof(rp_id_hash)) != 0 ||
            append_bytes(
                &auth_data,
                &auth_data_len,
                &flags,
                sizeof(flags)) != 0 ||
            append_u32_be(
                &auth_data,
                &auth_data_len,
                sign_count) != 0) {

            set_error(
                output,
                output_len,
                CTAP2_ERR_OTHER);

            goto fail;
        }
    }

    /*
     * The WebAuthn signature covers:
     *
     *     authenticatorData || clientDataHash
     */
    if (append_bytes(
            &signed_data,
            &signed_data_len,
            auth_data,
            auth_data_len) != 0 ||
        append_bytes(
            &signed_data,
            &signed_data_len,
            client_data_hash->bytes.data,
            client_data_hash->bytes.length) != 0) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    SHA256(
        signed_data,
        signed_data_len,
        signature_digest);

    free(signed_data);
    signed_data = NULL;
    signed_data_len = 0;

    /*
     * Load the persisted private key into the TPM.
     */
    if (tpm_load_key(
            &ctap_tpm,
            &credential.tpm) != 0) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * Sign the WebAuthn assertion digest inside the TPM.
     */
    if (tpm_sign_digest(
            &ctap_tpm,
            signature_digest,
            r,
            s) != 0) {

        tpm_flush_key(&ctap_tpm);

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    tpm_flush_key(&ctap_tpm);

    /*
     * WebAuthn requires DER-encoded ECDSA.
     */
    if (encode_ecdsa_der(
            r,
            s,
            &der_signature,
            &der_signature_len) != 0) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * Persist the incremented signature counter.
     */
    if (credential_save(
            &credential,
            data_directory) != 0) {

        fprintf(
            stderr,
            "Failed to persist WebAuthn signature counter\n");

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    /*
     * Build credential descriptor:
     *
     * {
     *     "type": "public-key",
     *     "id": credential ID
     * }
     */
    credential_descriptor =
        cbor_new_map();

    if (!credential_descriptor) {

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    cbor_map_put(
        credential_descriptor,
        cbor_new_text("type"),
        cbor_new_text("public-key"));

    cbor_map_put(
        credential_descriptor,
        cbor_new_text("id"),
        cbor_new_bytes(
            credential.id,
            credential.id_len));

    /*
     * Build GetAssertion response:
     *
     * 0x01 credential
     * 0x02 authenticatorData
     * 0x03 signature
     */
    response = cbor_new_map();

    if (!response) {

        cbor_free(credential_descriptor);
        credential_descriptor = NULL;

        set_error(
            output,
            output_len,
            CTAP2_ERR_OTHER);

        goto fail;
    }

    cbor_map_put(
        response,
        cbor_new_uint(0x01),
        credential_descriptor);

    credential_descriptor = NULL;

    cbor_map_put(
        response,
        cbor_new_uint(0x02),
        cbor_new_bytes(
            auth_data,
            auth_data_len));

    cbor_map_put(
        response,
        cbor_new_uint(0x03),
        cbor_new_bytes(
            der_signature,
            der_signature_len));

    free(auth_data);
    auth_data = NULL;

    free(der_signature);
    der_signature = NULL;

    cbor_free(request_map);
    request_map = NULL;

    credential_free(&credential);

    return encode_response(
        CTAP2_OK,
        response,
        output,
        output_len);

fail:

    cbor_free(credential_descriptor);
    cbor_free(response);
    cbor_free(request_map);

    free(auth_data);
    free(signed_data);
    free(der_signature);

    credential_free(&credential);

    return 0;
}

int ctap_get_next_assertion(
    uint8_t **output,
    size_t *output_len)
{
    if (!output || !output_len)
        return -1;

    set_error(
        output,
        output_len,
        CTAP2_ERR_NO_CREDENTIALS);

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
        set_error(
            output,
            output_len,
            CTAP2_ERR_PROCESSING);

        return 0;
    }

    if (!input || input_len < 1) {
        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_LENGTH);

        return 0;
    }

    command = input[0];

    switch (command) {
    case CTAP_CMD_GET_INFO:
        if (input_len != 1) {
            set_error(
                output,
                output_len,
                CTAP2_ERR_INVALID_LENGTH);

            return 0;
        }

        return ctap_get_info(
            output,
            output_len);

    case CTAP_CMD_MAKE_CREDENTIAL:
        return ctap_make_credential(
            input + 1,
            input_len - 1,
            output,
            output_len);

    case CTAP_CMD_GET_ASSERTION:
        return ctap_get_assertion(
            input + 1,
            input_len - 1,
            output,
            output_len);

    case CTAP_CMD_GET_NEXT_ASSERTION:
        return ctap_get_next_assertion(
            output,
            output_len);

    default:
        set_error(
            output,
            output_len,
            CTAP2_ERR_INVALID_COMMAND);

        return 0;
    }
}
