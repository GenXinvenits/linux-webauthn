#include "../../src/cbor.h"

#include <gio/gio.h>
#include <glib.h>
#include <json-glib/json-glib.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define BUS_NAME       "org.linux.WebAuthn"
#define OBJECT_PATH    "/org/linux/WebAuthn"
#define INTERFACE_NAME "org.linux.WebAuthn.Authenticator"

#define MAX_MESSAGE_SIZE 65536


static GDBusConnection *bus = NULL;


/*
 * ------------------------------------------------------------
 * Native Messaging framing helpers
 * ------------------------------------------------------------
 */


static int
read_exact(
    void *buffer,
    size_t length)
{
    return fread(
        buffer,
        1,
        length,
        stdin) == length ? 0 : -1;
}



static int
write_exact(
    const void *buffer,
    size_t length)
{
    return fwrite(
        buffer,
        1,
        length,
        stdout) == length ? 0 : -1;
}



static uint32_t
read_u32_le(
    const uint8_t b[4])
{
    return ((uint32_t)b[0]) |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}



static void
write_u32_le(
    uint8_t b[4],
    uint32_t value)
{
    b[0] = value & 0xff;
    b[1] = (value >> 8) & 0xff;
    b[2] = (value >> 16) & 0xff;
    b[3] = (value >> 24) & 0xff;
}



static int
send_json(
    const char *json)
{
    uint8_t header[4];

    size_t length =
        strlen(json);


    if (length > MAX_MESSAGE_SIZE)
        return -1;


    write_u32_le(
        header,
        (uint32_t)length);


    if (write_exact(
            header,
            sizeof(header)) != 0)
        return -1;


    if (write_exact(
            json,
            length) != 0)
        return -1;


    fflush(stdout);


    return 0;
}



/*
 * ------------------------------------------------------------
 * JSON response helpers
 * ------------------------------------------------------------
 */


static char *
make_error_response(
    gint64 request_id,
    const char *message)
{
    JsonBuilder *builder =
        json_builder_new();


    json_builder_begin_object(builder);


    json_builder_set_member_name(
        builder,
        "id");


    json_builder_add_int_value(
        builder,
        request_id);



    json_builder_set_member_name(
        builder,
        "ok");


    json_builder_add_boolean_value(
        builder,
        FALSE);



    json_builder_set_member_name(
        builder,
        "error");


    json_builder_add_string_value(
        builder,
        message);



    json_builder_end_object(builder);



    JsonGenerator *generator =
        json_generator_new();



    JsonNode *root =
        json_builder_get_root(builder);



    json_generator_set_root(
        generator,
        root);



    char *json =
        json_generator_to_data(
            generator,
            NULL);



    json_node_free(root);

    g_object_unref(generator);

    g_object_unref(builder);


    return json;
}





static char *
make_success_response(
    gint64 request_id,
    const uint8_t *data,
    size_t data_len)
{
    JsonBuilder *builder =
        json_builder_new();



    json_builder_begin_object(builder);



    json_builder_set_member_name(
        builder,
        "id");


    json_builder_add_int_value(
        builder,
        request_id);



    json_builder_set_member_name(
        builder,
        "ok");


    json_builder_add_boolean_value(
        builder,
        TRUE);



    json_builder_set_member_name(
        builder,
        "data");


    json_builder_begin_array(builder);



    for (size_t i = 0;
         i < data_len;
         i++) {

        json_builder_add_int_value(
            builder,
            data[i]);
    }



    json_builder_end_array(builder);


    json_builder_end_object(builder);



    JsonGenerator *generator =
        json_generator_new();



    JsonNode *root =
        json_builder_get_root(builder);



    json_generator_set_root(
        generator,
        root);



    char *json =
        json_generator_to_data(
            generator,
            NULL);



    json_node_free(root);

    g_object_unref(generator);

    g_object_unref(builder);



    return json;
}





static char *
make_ping_response(
    gint64 request_id)
{
    JsonBuilder *builder =
        json_builder_new();



    json_builder_begin_object(builder);



    json_builder_set_member_name(
        builder,
        "id");


    json_builder_add_int_value(
        builder,
        request_id);



    json_builder_set_member_name(
        builder,
        "ok");


    json_builder_add_boolean_value(
        builder,
        TRUE);



    json_builder_set_member_name(
        builder,
        "operation");


    json_builder_add_string_value(
        builder,
        "ping");



    json_builder_end_object(builder);



    JsonGenerator *generator =
        json_generator_new();



    JsonNode *root =
        json_builder_get_root(builder);



    json_generator_set_root(
        generator,
        root);



    char *json =
        json_generator_to_data(
            generator,
            NULL);



    json_node_free(root);

    g_object_unref(generator);

    g_object_unref(builder);



    return json;
}

/*
 * ------------------------------------------------------------
 * Convert WebAuthn makeCredential JSON into CTAP2 CBOR
 *
 * Firefox bridge sends:
 *
 * {
 *   "operation":"makeCredential",
 *   "data":{
 *      "challenge":[...],
 *      "rp":{},
 *      "user":{},
 *      "pubKeyCredParams":[]
 *   }
 * }
 *
 * CTAP2:
 *
 * {
 *   1: clientDataHash,
 *   2: rp,
 *   3: user,
 *   4: pubKeyCredParams
 * }
 *
 * ------------------------------------------------------------
 */


static int
build_makecredential_cbor(
    const char *json,
    uint8_t **output,
    size_t *output_len)
{
    JsonParser *parser =
        json_parser_new();


    GError *error = NULL;


    if (!json_parser_load_from_data(
            parser,
            json,
            -1,
            &error)) {

        fprintf(
            stderr,
            "linux-webauthn-native: JSON parse failed: %s\n",
            error ? error->message : "unknown");


        g_clear_error(&error);
        g_object_unref(parser);

        return -1;
    }



    JsonNode *root_node =
        json_parser_get_root(parser);


    if (!JSON_NODE_HOLDS_OBJECT(root_node)) {

        g_object_unref(parser);

        return -1;
    }



    JsonObject *root =
        json_node_get_object(root_node);



    JsonObject *data =
        json_object_get_object_member(
            root,
            "data");



    if (!data) {

        fprintf(
            stderr,
            "linux-webauthn-native: missing data object\n");

        g_object_unref(parser);

        return -1;
    }



    CborValue *map =
        cbor_new_map();



    /*
     * --------------------------------------------------------
     * key 1: clientDataHash
     * --------------------------------------------------------
     */


    JsonArray *challenge =
        json_object_get_array_member(
            data,
            "challenge");



    if (!challenge) {

        fprintf(
            stderr,
            "linux-webauthn-native: missing challenge\n");

        cbor_free(map);
        g_object_unref(parser);

        return -1;
    }



    guint challenge_len =
        json_array_get_length(
            challenge);



    uint8_t *challenge_bytes =
        malloc(challenge_len);



    if (!challenge_bytes) {

        cbor_free(map);
        g_object_unref(parser);

        return -1;
    }



    for (guint i = 0;
         i < challenge_len;
         i++) {

        challenge_bytes[i] =
            (uint8_t)
            json_array_get_int_element(
                challenge,
                i);
    }



    cbor_map_put(
        map,
        cbor_new_uint(1),
        cbor_new_bytes(
            challenge_bytes,
            challenge_len));



    free(challenge_bytes);



    /*
     * --------------------------------------------------------
     * key 2: rp
     * --------------------------------------------------------
     */


    JsonObject *rp =
        json_object_get_object_member(
            data,
            "rp");



    if (!rp) {

        cbor_free(map);
        g_object_unref(parser);

        return -1;
    }



    CborValue *rp_map =
        cbor_new_map();



    if (json_object_has_member(
            rp,
            "id")) {


        cbor_map_put(
            rp_map,
            cbor_new_text("id"),
            cbor_new_text(
                json_object_get_string_member(
                    rp,
                    "id")));
    }



    if (json_object_has_member(
            rp,
            "name")) {


        cbor_map_put(
            rp_map,
            cbor_new_text("name"),
            cbor_new_text(
                json_object_get_string_member(
                    rp,
                    "name")));
    }



    cbor_map_put(
        map,
        cbor_new_uint(2),
        rp_map);




    /*
     * --------------------------------------------------------
     * key 3: user
     * --------------------------------------------------------
     */


    JsonObject *user =
        json_object_get_object_member(
            data,
            "user");



    if (!user) {

        cbor_free(map);
        g_object_unref(parser);

        return -1;
    }



    CborValue *user_map =
        cbor_new_map();



    if (json_object_has_member(
            user,
            "id")) {


        cbor_map_put(
            user_map,
            cbor_new_text("id"),
            cbor_new_text(
                json_object_get_string_member(
                    user,
                    "id")));
    }



    if (json_object_has_member(
            user,
            "name")) {


        cbor_map_put(
            user_map,
            cbor_new_text("name"),
            cbor_new_text(
                json_object_get_string_member(
                    user,
                    "name")));
    }



    if (json_object_has_member(
            user,
            "displayName")) {


        cbor_map_put(
            user_map,
            cbor_new_text("displayName"),
            cbor_new_text(
                json_object_get_string_member(
                    user,
                    "displayName")));
    }



    cbor_map_put(
        map,
        cbor_new_uint(3),
        user_map);




    /*
     * --------------------------------------------------------
     * key 4: pubKeyCredParams
     * --------------------------------------------------------
     */


    JsonArray *params =
        json_object_get_array_member(
            data,
            "pubKeyCredParams");



    if (!params) {

        fprintf(
            stderr,
            "linux-webauthn-native: missing pubKeyCredParams\n");


        cbor_free(map);
        g_object_unref(parser);

        return -1;
    }



    CborValue *param_array =
        cbor_new_array();



    guint param_count =
        json_array_get_length(
            params);



    for (guint i = 0;
         i < param_count;
         i++) {


        JsonObject *item =
            json_array_get_object_element(
                params,
                i);



        CborValue *entry =
            cbor_new_map();



        cbor_map_put(
            entry,
            cbor_new_text("type"),
            cbor_new_text(
                "public-key"));



        gint64 alg =
            json_object_get_int_member(
                item,
                "alg");



        cbor_map_put(
            entry,
            cbor_new_text("alg"),
            cbor_new_int(alg));



        cbor_array_append(
            param_array,
            entry);
    }



    cbor_map_put(
        map,
        cbor_new_uint(4),
        param_array);



    /*
     * --------------------------------------------------------
     * Encode CBOR
     * --------------------------------------------------------
     */


    int rc =
        cbor_encode(
            map,
            output,
            output_len);



    fprintf(
        stderr,
        "linux-webauthn-native: generated CTAP CBOR %zu bytes\n",
        *output_len);



    cbor_free(map);

    g_object_unref(parser);



    return rc;
}

/*
 * ------------------------------------------------------------
 * Process one Native Messaging request
 * ------------------------------------------------------------
 */


static int
process_request(
    const char *json,
    char **response_json)
{
    uint8_t *request = NULL;
    size_t request_len = 0;


    *response_json = NULL;



    /*
     * Extract request id
     */

    JsonParser *parser =
        json_parser_new();


    GError *error = NULL;


    if (!json_parser_load_from_data(
            parser,
            json,
            -1,
            &error)) {


        *response_json =
            make_error_response(
                0,
                "Invalid JSON");


        g_clear_error(&error);

        g_object_unref(parser);

        return -1;
    }



    JsonObject *root =
        json_node_get_object(
            json_parser_get_root(parser));



    if (!root ||
        !json_object_has_member(
            root,
            "id")) {


        *response_json =
            make_error_response(
                0,
                "Missing request id");


        g_object_unref(parser);

        return -1;
    }



    gint64 request_id =
        json_object_get_int_member(
            root,
            "id");



    g_object_unref(parser);



    fprintf(
        stderr,
        "linux-webauthn-native: request id %" G_GINT64_FORMAT "\n",
        request_id);




    /*
     * Ping test
     */

    parser =
        json_parser_new();


    if (json_parser_load_from_data(
            parser,
            json,
            -1,
            NULL)) {


        root =
            json_node_get_object(
                json_parser_get_root(parser));


        if (root &&
            json_object_has_member(
                root,
                "operation")) {


            const char *operation =
                json_object_get_string_member(
                    root,
                    "operation");



            if (g_strcmp0(
                    operation,
                    "ping") == 0) {


                *response_json =
                    make_ping_response(
                        request_id);


                g_object_unref(parser);

                return 0;
            }
        }
    }


    g_object_unref(parser);




    /*
     * Convert WebAuthn request -> CTAP CBOR
     */

    if (build_makecredential_cbor(
        json,
        &request,
        &request_len) != 0) {


    JsonBuilder *builder =
        json_builder_new();

    json_builder_begin_object(builder);

    json_builder_set_member_name(builder, "id");
    json_builder_add_int_value(builder, request_id);

    json_builder_set_member_name(builder, "ok");
    json_builder_add_boolean_value(builder, FALSE);

    json_builder_set_member_name(builder, "error");
    json_builder_add_string_value(
        builder,
        "Invalid request data");

    json_builder_set_member_name(builder, "debug");
    json_builder_add_string_value(
        builder,
        json);

    json_builder_end_object(builder);


    JsonGenerator *generator =
        json_generator_new();

    JsonNode *root =
        json_builder_get_root(builder);

    json_generator_set_root(
        generator,
        root);


    *response_json =
        json_generator_to_data(
            generator,
            NULL);


    json_node_free(root);
    g_object_unref(generator);
    g_object_unref(builder);


    return -1;
}



    fprintf(
        stderr,
        "linux-webauthn-native: CTAP request %zu bytes\n",
        request_len);



    if (request_len > 0) {

        fprintf(
            stderr,
            "linux-webauthn-native: command 0x%02x\n",
            request[0]);
    }




    /*
     * Convert to GVariant ay
     */

    GVariant *input =
        g_variant_new_fixed_array(
            G_VARIANT_TYPE_BYTE,
            request,
            request_len,
            sizeof(uint8_t));




    /*
     * Call linux authenticator
     */

    fprintf(
        stderr,
        "linux-webauthn-native: calling MakeCredential()\n");



    GVariant *result =
        g_dbus_connection_call_sync(
            bus,
            BUS_NAME,
            OBJECT_PATH,
            INTERFACE_NAME,
            "MakeCredential",
            g_variant_new(
                "(@ay)",
                input),
            G_VARIANT_TYPE("(ay)"),
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            &error);



    free(request);

    request = NULL;



    if (!result) {


        char *msg =
            g_strdup_printf(
                "D-Bus MakeCredential failed: %s",
                error
                ? error->message
                : "unknown");



        *response_json =
            make_error_response(
                request_id,
                msg);



        g_free(msg);

        g_clear_error(&error);


        return -1;
    }




    GVariant *output_variant =
        NULL;



    g_variant_get(
        result,
        "(@ay)",
        &output_variant);



    gsize output_len = 0;



    const uint8_t *output =
        g_variant_get_fixed_array(
            output_variant,
            &output_len,
            sizeof(uint8_t));



    fprintf(
        stderr,
        "linux-webauthn-native: response %zu bytes\n",
        (size_t)output_len);



    *response_json =
        make_success_response(
            request_id,
            output,
            output_len);



    g_variant_unref(output_variant);

    g_variant_unref(result);



    return 0;
}





/*
 * ------------------------------------------------------------
 * MAIN
 * ------------------------------------------------------------
 */


int
main(void)
{
    GError *error = NULL;



    const char *address =
        g_getenv(
            "DBUS_SESSION_BUS_ADDRESS");



    if (!address) {

        fprintf(
            stderr,
            "linux-webauthn-native: no session bus\n");

        return 1;
    }



    fprintf(
        stderr,
        "linux-webauthn-native: connecting to session D-Bus\n");



    bus =
        g_dbus_connection_new_for_address_sync(
            address,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
            G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
            NULL,
            NULL,
            &error);



    if (!bus) {


        fprintf(
            stderr,
            "linux-webauthn-native: D-Bus error %s\n",
            error
            ? error->message
            : "unknown");



        g_clear_error(&error);

        return 1;
    }



    fprintf(
        stderr,
        "linux-webauthn-native: native host ready\n");




    while (TRUE) {


        uint8_t header[4];



        if (read_exact(
                header,
                4) != 0)
            break;



        uint32_t length =
            read_u32_le(header);



        if (length == 0 ||
            length > MAX_MESSAGE_SIZE)
            break;




        char *json =
            malloc(length + 1);



        if (!json)
            break;




        if (read_exact(
                json,
                length) != 0) {


            free(json);

            break;
        }



        json[length] = '\0';



        fprintf(
            stderr,
            "linux-webauthn-native: received %u bytes\n",
            length);

        fprintf(
            stderr,
            "linux-webauthn-native: JSON:\n%s\n",
            json);



        char *response = NULL;



        process_request(
            json,
            &response);



        free(json);




        if (!response) {


            response =
                make_error_response(
                    0,
                    "No response");
        }




        send_json(response);



        free(response);
    }




    g_clear_object(&bus);



    fprintf(
        stderr,
        "linux-webauthn-native: exiting\n");



    return 0;
}

