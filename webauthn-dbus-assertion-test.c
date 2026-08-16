#include "cbor.h"

#include <gio/gio.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUS_NAME    "org.linux.WebAuthn"
#define OBJECT_PATH "/org/linux/WebAuthn"
#define INTERFACE   "org.linux.WebAuthn.Authenticator"
#define METHOD      "Process"

#define CTAP_CMD_MAKE_CREDENTIAL 0x01
#define CTAP_CMD_GET_ASSERTION   0x02
#define CTAP2_OK                 0x00

static void print_hex(
    const char *name,
    const uint8_t *data,
    size_t length)
{
    printf("%s: ", name);

    for (size_t i = 0; i < length; i++)
        printf("%02x", data[i]);

    printf("\n");
}

static CborValue *find_map_negative_key(
    CborValue *map,
    int64_t key)
{
    if (!map ||
        !cbor_is_type(map, CBOR_TYPE_MAP))
        return NULL;

    for (size_t i = 0; i < map->map.count; i++) {
        CborValue *k = map->map.keys[i];

        if (k &&
            cbor_is_type(k, CBOR_TYPE_NEGATIVE) &&
            k->int_value == key)
            return map->map.values[i];
    }

    return NULL;
}

static int dbus_process(
    GDBusConnection *bus,
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len)
{
    GError *error = NULL;
    GVariant *reply = NULL;
    GVariant *bytes = NULL;

    if (!bus ||
        !input ||
        input_len == 0 ||
        !output ||
        !output_len)
        return -1;

    *output = NULL;
    *output_len = 0;

    reply = g_dbus_connection_call_sync(
        bus,
        BUS_NAME,
        OBJECT_PATH,
        INTERFACE,
        METHOD,
        g_variant_new("(@ay)",
            g_variant_new_fixed_array(
                G_VARIANT_TYPE_BYTE,
                input,
                input_len,
                sizeof(uint8_t))),
        G_VARIANT_TYPE("(ay)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &error);

    if (!reply) {
        fprintf(stderr,
                "D-Bus Process() failed: %s\n",
                error ? error->message : "unknown error");
        g_clear_error(&error);
        return -1;
    }

    g_variant_get(reply, "(@ay)", &bytes);

    gsize n = 0;
    const guint8 *data = g_variant_get_fixed_array(
        bytes, &n, sizeof(guint8));

    if (!data || n == 0) {
        fprintf(stderr, "D-Bus returned empty response\n");
        g_variant_unref(bytes);
        g_variant_unref(reply);
        return -1;
    }

    *output = malloc(n);
    if (!*output) {
        g_variant_unref(bytes);
        g_variant_unref(reply);
        return -1;
    }

    memcpy(*output, data, n);
    *output_len = n;

    g_variant_unref(bytes);
    g_variant_unref(reply);
    return 0;
}

static int decode_response(
    const uint8_t *output,
    size_t output_len,
    CborValue **response)
{
    size_t offset = 0;

    if (!output || output_len < 2 || !response)
        return -1;

    *response = NULL;

    if (output[0] != CTAP2_OK)
        return -1;

    if (cbor_decode(output + 1, output_len - 1, &offset, response) != 0)
        return -1;

    if (!*response ||
        !cbor_is_type(*response, CBOR_TYPE_MAP) ||
        offset != output_len - 1) {
        cbor_free(*response);
        *response = NULL;
        return -1;
    }

    return 0;
}

static int extract_credential_data(
    CborValue *auth_data,
    uint8_t **credential_id,
    size_t *credential_id_len,
    CborValue **cose_key)
{
    const uint8_t *data;
    size_t length;
    size_t offset;
    uint16_t id_len;

    if (!auth_data || !credential_id || !credential_id_len ||
        !cose_key || !cbor_is_type(auth_data, CBOR_TYPE_BYTES))
        return -1;

    *credential_id = NULL;
    *credential_id_len = 0;
    *cose_key = NULL;

    data = auth_data->bytes.data;
    length = auth_data->bytes.length;

    if (!data || length < 55)
        return -1;

    offset = 32 + 1 + 4 + 16;
    id_len = ((uint16_t)data[offset] << 8) | data[offset + 1];
    offset += 2;

    if (id_len == 0 || offset + id_len > length)
        return -1;

    *credential_id = malloc(id_len);
    if (!*credential_id)
        return -1;

    memcpy(*credential_id, data + offset, id_len);
    *credential_id_len = id_len;
    offset += id_len;

    if (offset >= length) {
        free(*credential_id);
        *credential_id = NULL;
        *credential_id_len = 0;
        return -1;
    }

    size_t cbor_offset = 0;
    if (cbor_decode(data + offset, length - offset, &cbor_offset, cose_key) != 0 ||
        !*cose_key || cbor_offset != length - offset) {
        free(*credential_id);
        *credential_id = NULL;
        *credential_id_len = 0;
        cbor_free(*cose_key);
        *cose_key = NULL;
        return -1;
    }

    return 0;
}

static int verify_es256_signature(
    CborValue *cose_key,
    const uint8_t digest[SHA256_DIGEST_LENGTH],
    const uint8_t *signature,
    size_t signature_len)
{
    CborValue *kty;
    CborValue *alg;
    CborValue *crv;
    CborValue *x;
    CborValue *y;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EC_KEY *ec_key = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    int result = -1;

    if (!cose_key || !digest || !signature || signature_len == 0 ||
        !cbor_is_type(cose_key, CBOR_TYPE_MAP))
        return -1;

    kty = cbor_map_get_uint(cose_key, 1);
    alg = cbor_map_get_uint(cose_key, 3);
    crv = find_map_negative_key(cose_key, -1);
    x = find_map_negative_key(cose_key, -2);
    y = find_map_negative_key(cose_key, -3);

    if (!kty || !alg || !crv || !x || !y)
        goto cleanup;
    if (!cbor_is_type(kty, CBOR_TYPE_UNSIGNED) || kty->uint_value != 2)
        goto cleanup;
    if (!cbor_is_type(alg, CBOR_TYPE_NEGATIVE) || alg->int_value != -7)
        goto cleanup;
    if (!cbor_is_type(crv, CBOR_TYPE_UNSIGNED) || crv->uint_value != 1)
        goto cleanup;
    if (!cbor_is_type(x, CBOR_TYPE_BYTES) || !cbor_is_type(y, CBOR_TYPE_BYTES) ||
        x->bytes.length != 32 || y->bytes.length != 32)
        goto cleanup;

    printf("    Public key: ES256 / P-256\n");

    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key)
        goto cleanup;

    group = EC_KEY_get0_group(ec_key);
    point = EC_POINT_new(group);
    bx = BN_bin2bn(x->bytes.data, x->bytes.length, NULL);
    by = BN_bin2bn(y->bytes.data, y->bytes.length, NULL);

    if (!point || !bx || !by)
        goto cleanup;
    if (EC_POINT_set_affine_coordinates(group, point, bx, by, NULL) != 1)
        goto cleanup;
    if (EC_KEY_set_public_key(ec_key, point) != 1)
        goto cleanup;

    pkey = EVP_PKEY_new();
    if (!pkey)
        goto cleanup;
    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1)
        goto cleanup;
    ec_key = NULL;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto cleanup;
    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto cleanup;
    if (EVP_PKEY_verify(ctx, signature, signature_len,
                        digest, SHA256_DIGEST_LENGTH) == 1)
        result = 0;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (ec_key) EC_KEY_free(ec_key);
    if (point) EC_POINT_free(point);
    if (bx) BN_free(bx);
    if (by) BN_free(by);
    return result;
}

static int build_makecredential_request(
    uint8_t **input,
    size_t *input_len,
    uint8_t client_data_hash[32])
{
    CborValue *request = NULL;
    CborValue *rp = NULL;
    CborValue *user = NULL;
    CborValue *params = NULL;
    CborValue *param = NULL;
    uint8_t user_id[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    for (size_t i = 0; i < 32; i++)
        client_data_hash[i] = (uint8_t)i;

    request = cbor_new_map();
    rp = cbor_new_map();
    user = cbor_new_map();
    params = cbor_new_array();
    param = cbor_new_map();
    if (!request || !rp || !user || !params || !param)
        goto fail;

    cbor_map_put(request, cbor_new_uint(1), cbor_new_bytes(client_data_hash, 32));
    cbor_map_put(rp, cbor_new_text("id"), cbor_new_text("example.com"));
    cbor_map_put(rp, cbor_new_text("name"), cbor_new_text("GNOME WebAuthn Test"));
    cbor_map_put(request, cbor_new_uint(2), rp);
    rp = NULL;
    cbor_map_put(user, cbor_new_text("id"), cbor_new_bytes(user_id, sizeof(user_id)));
    cbor_map_put(user, cbor_new_text("name"), cbor_new_text("test@example.com"));
    cbor_map_put(user, cbor_new_text("displayName"), cbor_new_text("GNOME WebAuthn Test User"));
    cbor_map_put(request, cbor_new_uint(3), user);
    user = NULL;
    cbor_map_put(param, cbor_new_text("type"), cbor_new_text("public-key"));
    cbor_map_put(param, cbor_new_text("alg"), cbor_new_int(-7));
    cbor_array_append(params, param);
    param = NULL;
    cbor_map_put(request, cbor_new_uint(4), params);
    params = NULL;

    if (cbor_encode(request, &encoded, &encoded_len) != 0)
        goto fail;

    *input = malloc(encoded_len + 1);
    if (!*input)
        goto fail;
    (*input)[0] = CTAP_CMD_MAKE_CREDENTIAL;
    memcpy(*input + 1, encoded, encoded_len);
    *input_len = encoded_len + 1;

    free(encoded);
    cbor_free(request);
    cbor_free(rp);
    cbor_free(user);
    cbor_free(params);
    cbor_free(param);
    return 0;

fail:
    free(encoded);
    cbor_free(request);
    cbor_free(rp);
    cbor_free(user);
    cbor_free(params);
    cbor_free(param);
    return -1;
}

static int build_getassertion_request(
    const uint8_t client_data_hash[32],
    const uint8_t *credential_id,
    size_t credential_id_len,
    uint8_t **input,
    size_t *input_len)
{
    CborValue *request = NULL;
    CborValue *allow = NULL;
    CborValue *entry = NULL;
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    request = cbor_new_map();
    allow = cbor_new_array();
    entry = cbor_new_map();
    if (!request || !allow || !entry)
        goto fail;

    cbor_map_put(request, cbor_new_uint(1), cbor_new_text("example.com"));
    cbor_map_put(request, cbor_new_uint(2), cbor_new_bytes(client_data_hash, 32));
    cbor_map_put(entry, cbor_new_text("type"), cbor_new_text("public-key"));
    cbor_map_put(entry, cbor_new_text("id"), cbor_new_bytes(credential_id, credential_id_len));
    cbor_array_append(allow, entry);
    entry = NULL;
    cbor_map_put(request, cbor_new_uint(3), allow);
    allow = NULL;

    if (cbor_encode(request, &encoded, &encoded_len) != 0)
        goto fail;

    *input = malloc(encoded_len + 1);
    if (!*input)
        goto fail;
    (*input)[0] = CTAP_CMD_GET_ASSERTION;
    memcpy(*input + 1, encoded, encoded_len);
    *input_len = encoded_len + 1;

    free(encoded);
    cbor_free(request);
    cbor_free(allow);
    cbor_free(entry);
    return 0;

fail:
    free(encoded);
    cbor_free(request);
    cbor_free(allow);
    cbor_free(entry);
    return -1;
}

int main(void)
{
    GError *error = NULL;
    GDBusConnection *bus = NULL;
    uint8_t *input = NULL;
    size_t input_len = 0;
    uint8_t *output = NULL;
    size_t output_len = 0;
    uint8_t client_data_hash[32];
    CborValue *response = NULL;
    CborValue *auth_data = NULL;
    CborValue *cose_key = NULL;
    uint8_t *credential_id = NULL;
    size_t credential_id_len = 0;
    int result = 1;

    bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!bus) {
        fprintf(stderr, "D-Bus connection failed: %s\n",
                error ? error->message : "unknown error");
        g_clear_error(&error);
        return 1;
    }

    if (build_makecredential_request(&input, &input_len, client_data_hash) != 0) {
        fprintf(stderr, "Failed to build makeCredential request\n");
        goto cleanup;
    }

    printf("Sending makeCredential request...\n");
    if (dbus_process(bus, input, input_len, &output, &output_len) != 0)
        goto cleanup;

    if (decode_response(output, output_len, &response) != 0) {
        fprintf(stderr, "makeCredential failed: CTAP status 0x%02x\n",
                output_len ? output[0] : 0xff);
        goto cleanup;
    }

    auth_data = cbor_map_get_uint(response, 2);
    if (!auth_data || !cbor_is_type(auth_data, CBOR_TYPE_BYTES)) {
        fprintf(stderr, "makeCredential response has no authData\n");
        goto cleanup;
    }

    if (auth_data->bytes.length < 37) {
        fprintf(stderr, "authData too short\n");
        goto cleanup;
    }

    print_hex("makeCredential authData flags", auth_data->bytes.data + 32, 1);
    if (!(auth_data->bytes.data[32] & 0x01)) {
        fprintf(stderr, "FAIL: UP flag is not set\n");
        goto cleanup;
    }
    if (!(auth_data->bytes.data[32] & 0x04)) {
        fprintf(stderr, "FAIL: UV flag is not set\n");
        goto cleanup;
    }

    if (extract_credential_data(auth_data, &credential_id,
                                &credential_id_len, &cose_key) != 0) {
        fprintf(stderr, "Failed to extract credential data\n");
        goto cleanup;
    }

    printf("makeCredential succeeded with UV\n");
    print_hex("credential ID", credential_id, credential_id_len);

    cbor_free(response);
    response = NULL;
    free(output);
    output = NULL;
    free(input);
    input = NULL;
    input_len = 0;

    if (build_getassertion_request(client_data_hash, credential_id,
                                   credential_id_len, &input, &input_len) != 0) {
        fprintf(stderr, "Failed to build getAssertion request\n");
        goto cleanup;
    }

    printf("Sending getAssertion request...\n");
    if (dbus_process(bus, input, input_len, &output, &output_len) != 0)
        goto cleanup;

    if (decode_response(output, output_len, &response) != 0) {
        fprintf(stderr, "getAssertion failed: CTAP status 0x%02x\n",
                output_len ? output[0] : 0xff);
        goto cleanup;
    }

    auth_data = cbor_map_get_uint(response, 2);
    if (!auth_data || !cbor_is_type(auth_data, CBOR_TYPE_BYTES) ||
        auth_data->bytes.length < 37) {
        fprintf(stderr, "getAssertion response has invalid authData\n");
        goto cleanup;
    }

    print_hex("getAssertion authData flags", auth_data->bytes.data + 32, 1);
    if (!(auth_data->bytes.data[32] & 0x01)) {
        fprintf(stderr, "FAIL: getAssertion UP flag is not set\n");
        goto cleanup;
    }
    if (!(auth_data->bytes.data[32] & 0x04)) {
        fprintf(stderr, "FAIL: getAssertion UV flag is not set\n");
        goto cleanup;
    }

    printf("getAssertion succeeded with UV\n");
    result = 0;

cleanup:
    cbor_free(response);
    cbor_free(cose_key);
    free(credential_id);
    free(input);
    free(output);
    if (bus)
        g_object_unref(bus);
    return result;
}
