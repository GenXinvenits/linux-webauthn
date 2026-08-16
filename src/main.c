#include "fingerprint.h"
#include "authenticator.h"
#include "ctap.h"
#include "fido_hid.h"

#include <gio/gio.h>
#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUS_NAME       "org.linux.WebAuthn"
#define OBJECT_PATH    "/org/linux/WebAuthn"
#define INTERFACE_NAME "org.linux.WebAuthn.Authenticator"

static GMainLoop *main_loop = NULL;
static guint registration_id = 0;
static GThread *fido_hid_thread = NULL;

static const gchar introspection_xml[] =
    "<node>"
    "  <interface name='org.linux.WebAuthn.Authenticator'>"
    "    <method name='Process'>"
    "      <arg name='input' type='ay' direction='in'/>"
    "      <arg name='output' type='ay' direction='out'/>"
    "    </method>"
    "    <method name='GetInfo'>"
    "      <arg name='output' type='ay' direction='out'/>"
    "    </method>"
    "    <method name='GetAssertion'>"
    "      <arg name='request' type='ay' direction='in'/>"
    "      <arg name='output' type='ay' direction='out'/>"
    "    </method>"
    "    <method name='MakeCredential'>"
    "      <arg name='request' type='ay' direction='in'/>"
    "      <arg name='output' type='ay' direction='out'/>"
    "    </method>"
    "  </interface>"
    "</node>";

static GDBusNodeInfo *introspection_data = NULL;

static gpointer fido_hid_thread_func(gpointer user_data)
{
    int rc;

    (void)user_data;

    rc = fido_hid_run();

    if (rc != 0) {
        fprintf(stderr,
                "LINUX WebAuthn: FIDO HID transport stopped with an error\n");
    } else {
        fprintf(stderr,
                "LINUX WebAuthn: FIDO HID transport stopped\n");
    }

    return NULL;
}

static GVariant *bytes_to_variant(const uint8_t *data, size_t length)
{
    GVariantBuilder builder;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("ay"));

    for (size_t i = 0; i < length; i++)
        g_variant_builder_add(&builder, "y", data[i]);

    return g_variant_builder_end(&builder);
}

static int variant_to_bytes(GVariant *variant, uint8_t **data, size_t *length)
{
    gsize n = 0;
    const guint8 *raw;

    if (!variant || !data || !length)
        return -1;

    *data = NULL;
    *length = 0;

    raw = g_variant_get_fixed_array(variant, &n, sizeof(guint8));

    if (!raw && n != 0)
        return -1;

    if (n == 0)
        return 0;

    *data = malloc(n);
    if (!*data)
        return -1;

    memcpy(*data, raw, n);
    *length = n;

    return 0;
}

static int require_fingerprint(void)
{
    if (fingerprint_verify() != 0) {
        ctap_set_user_verified(0);
        return -1;
    }

    ctap_set_user_verified(1);
    return 0;
}

static void method_call(
    GDBusConnection *connection,
    const gchar *sender,
    const gchar *object_path,
    const gchar *interface_name,
    const gchar *method_name,
    GVariant *parameters,
    GDBusMethodInvocation *invocation,
    gpointer user_data)
{
    uint8_t *input = NULL;
    size_t input_len = 0;
    uint8_t *output = NULL;
    size_t output_len = 0;
    int rc;

    (void)connection;
    (void)sender;
    (void)object_path;
    (void)interface_name;
    (void)user_data;

    if (strcmp(method_name, "Process") == 0) {
        GVariant *input_variant = NULL;

        g_variant_get(parameters, "(@ay)", &input_variant);

        if (variant_to_bytes(input_variant, &input, &input_len) != 0) {
            g_variant_unref(input_variant);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                "Invalid CTAP input");
            return;
        }

        g_variant_unref(input_variant);

        if (input_len > 0 &&
            (input[0] == CTAP_CMD_MAKE_CREDENTIAL ||
             input[0] == CTAP_CMD_GET_ASSERTION)) {
            fprintf(stderr,
                    "WebAuthn: CTAP command 0x%02x requires fingerprint verification\n",
                    input[0]);

            if (require_fingerprint() != 0) {
                free(input);
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "org.linux.WebAuthn.Error.UserVerificationFailed",
                    "Fingerprint verification failed");
                return;
            }
        }

        rc = authenticator_process(input, input_len, &output, &output_len);
        ctap_set_user_verified(0);
        free(input);

        if (rc != 0) {
            free(output);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Authenticator processing failed");
            return;
        }

        GVariant *response = bytes_to_variant(output, output_len);
        free(output);

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(@ay)", response));
        return;
    }

    if (strcmp(method_name, "GetInfo") == 0) {
        rc = ctap_get_info(&output, &output_len);

        if (rc != 0) {
            free(output);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_FAILED,
                "GetInfo failed");
            return;
        }

        GVariant *response = bytes_to_variant(output, output_len);
        free(output);

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(@ay)", response));
        return;
    }

    if (strcmp(method_name, "MakeCredential") == 0) {
        GVariant *request_variant = NULL;

        g_variant_get(parameters, "(@ay)", &request_variant);

        if (variant_to_bytes(request_variant, &input, &input_len) != 0) {
            g_variant_unref(request_variant);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                "Invalid MakeCredential request");
            return;
        }

        g_variant_unref(request_variant);

        fprintf(stderr,
                "WebAuthn: MakeCredential requires fingerprint verification\n");

        if (require_fingerprint() != 0) {
            free(input);
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.linux.WebAuthn.Error.UserVerificationFailed",
                "Fingerprint verification failed");
            return;
        }

        rc = ctap_make_credential(input, input_len, &output, &output_len);
        ctap_set_user_verified(0);
        free(input);

        if (rc != 0) {
            free(output);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_FAILED,
                "MakeCredential failed");
            return;
        }

        GVariant *response = bytes_to_variant(output, output_len);
        free(output);

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(@ay)", response));
        return;
    }

    if (strcmp(method_name, "GetAssertion") == 0) {
        GVariant *request_variant = NULL;

        g_variant_get(parameters, "(@ay)", &request_variant);

        if (variant_to_bytes(request_variant, &input, &input_len) != 0) {
            g_variant_unref(request_variant);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                "Invalid GetAssertion request");
            return;
        }

        g_variant_unref(request_variant);

        fprintf(stderr,
                "WebAuthn: GetAssertion requires fingerprint verification\n");

        if (require_fingerprint() != 0) {
            free(input);
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.linux.WebAuthn.Error.UserVerificationFailed",
                "Fingerprint verification failed");
            return;
        }

        rc = ctap_get_assertion(input, input_len, &output, &output_len);
        ctap_set_user_verified(0);
        free(input);

        if (rc != 0) {
            free(output);
            g_dbus_method_invocation_return_error(
                invocation, G_IO_ERROR, G_IO_ERROR_FAILED,
                "GetAssertion failed");
            return;
        }

        GVariant *response = bytes_to_variant(output, output_len);
        free(output);

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(@ay)", response));
        return;
    }

    g_dbus_method_invocation_return_error(
        invocation, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
        "Unknown WebAuthn method: %s", method_name);
}

static const GDBusInterfaceVTable interface_vtable = {
    .method_call = method_call,
    .get_property = NULL,
    .set_property = NULL
};

static void on_bus_acquired(
    GDBusConnection *connection,
    const gchar *name,
    gpointer user_data)
{
    GError *error = NULL;

    (void)name;
    (void)user_data;

    registration_id = g_dbus_connection_register_object(
        connection,
        OBJECT_PATH,
        introspection_data->interfaces[0],
        &interface_vtable,
        NULL,
        NULL,
        &error);

    if (registration_id == 0) {
        fprintf(stderr,
                "Failed to register D-Bus object: %s\n",
                error ? error->message : "unknown error");
        g_clear_error(&error);
        g_main_loop_quit(main_loop);
        return;
    }

    fprintf(stderr, "LINUX WebAuthn: D-Bus object registered\n");
    fprintf(stderr, "  Bus:       %s\n", BUS_NAME);
    fprintf(stderr, "  Object:    %s\n", OBJECT_PATH);
    fprintf(stderr, "  Interface: %s\n", INTERFACE_NAME);
}

static void on_name_acquired(
    GDBusConnection *connection,
    const gchar *name,
    gpointer user_data)
{
    (void)connection;
    (void)user_data;
    fprintf(stderr, "LINUX WebAuthn: acquired bus name %s\n", name);
}

static void on_name_lost(
    GDBusConnection *connection,
    const gchar *name,
    gpointer user_data)
{
    (void)connection;
    (void)user_data;

    /*
     * Do not tear down the FIDO HID transport here. A session-bus name can
     * be lost because another instance/service activation owns the name.
     * The HID authenticator is an independent transport and must remain
     * alive while its worker is running. The D-Bus connection lifecycle is
     * handled independently.
     */
    fprintf(stderr,
            "LINUX WebAuthn: lost bus name %s (HID transport remains active)\n",
            name);
}

int main(void)
{
    GError *error = NULL;
    guint owner_id;

    fprintf(stderr, "LINUX WebAuthn authenticator service\n");
    fprintf(stderr, "====================================\n");

    if (authenticator_init() != 0) {
        fprintf(stderr, "Failed to initialize authenticator\n");
        return EXIT_FAILURE;
    }

    introspection_data = g_dbus_node_info_new_for_xml(
        introspection_xml, &error);

    if (!introspection_data) {
        fprintf(stderr,
                "Failed to parse D-Bus introspection: %s\n",
                error ? error->message : "unknown error");
        g_clear_error(&error);
        authenticator_cleanup();
        return EXIT_FAILURE;
    }

    main_loop = g_main_loop_new(NULL, FALSE);

    owner_id = g_bus_own_name(
        G_BUS_TYPE_SESSION,
        BUS_NAME,
        G_BUS_NAME_OWNER_FLAGS_NONE,
        on_bus_acquired,
        on_name_acquired,
        on_name_lost,
        NULL,
        NULL);

    fprintf(stderr, "LINUX WebAuthn: service running\n");

    fido_hid_thread = g_thread_new(
        "fido-hid",
        fido_hid_thread_func,
        NULL);

    if (!fido_hid_thread) {
        fprintf(stderr, "Failed to start FIDO HID transport\n");
        g_bus_unown_name(owner_id);
        g_main_loop_unref(main_loop);
        main_loop = NULL;
        g_dbus_node_info_unref(introspection_data);
        introspection_data = NULL;
        authenticator_cleanup();
        return EXIT_FAILURE;
    }

    g_main_loop_run(main_loop);

    g_bus_unown_name(owner_id);

    fido_hid_stop();

    if (fido_hid_thread) {
        g_thread_join(fido_hid_thread);
        fido_hid_thread = NULL;
    }

    registration_id = 0;

    g_main_loop_unref(main_loop);
    main_loop = NULL;

    g_dbus_node_info_unref(introspection_data);
    introspection_data = NULL;

    authenticator_cleanup();

    return EXIT_SUCCESS;
}
