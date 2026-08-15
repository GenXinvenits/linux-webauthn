#include "fingerprint.h"

#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>

#define FPRINT_SERVICE "net.reactivated.Fprint"
#define FPRINT_DEVICE "/net/reactivated/Fprint/Device/0"
#define FPRINT_INTERFACE "net.reactivated.Fprint.Device"

#define MAX_ATTEMPTS 5

typedef struct {
    GMainLoop *loop;
    gboolean matched;
    gboolean finished;
    GDBusConnection *bus;
} VerifyContext;

static void on_verify_status(
    GDBusConnection *connection,
    const gchar *sender_name,
    const gchar *object_path,
    const gchar *interface_name,
    const gchar *signal_name,
    GVariant *parameters,
    gpointer user_data)
{
    VerifyContext *ctx = user_data;

    if (g_strcmp0(signal_name, "VerifyStatus") != 0)
        return;

    const gchar *result = NULL;
    gboolean done = FALSE;

    g_variant_get(
        parameters,
        "(&sb)",
        &result,
        &done);

    fprintf(
        stderr,
        "WebAuthn: fingerprint status: %s%s\n",
        result,
        done ? " (done)" : "");

    if (g_strcmp0(result, "verify-match") == 0) {
        ctx->matched = TRUE;
        ctx->finished = TRUE;

        if (ctx->loop)
            g_main_loop_quit(ctx->loop);

        return;
    }

    if (g_strcmp0(result, "verify-no-match") == 0) {
        ctx->finished = TRUE;

        if (ctx->loop)
            g_main_loop_quit(ctx->loop);

        return;
    }

    /*
     * These statuses mean the user should continue scanning.
     * Do not terminate verification for them.
     */
    if (g_strcmp0(result, "verify-retry-scan") == 0 ||
        g_strcmp0(result, "verify-swipe-too-short") == 0 ||
        g_strcmp0(result, "verify-finger-not-centered") == 0 ||
        g_strcmp0(result, "verify-remove-and-retry") == 0 ||
        g_strcmp0(result, "verify-too-fast") == 0) {

        fprintf(
            stderr,
            "WebAuthn: please retry your finger...\n");

        return;
    }

    if (g_strcmp0(result, "verify-disconnected") == 0 ||
        g_strcmp0(result, "verify-unknown-error") == 0) {

        ctx->finished = TRUE;

        if (ctx->loop)
            g_main_loop_quit(ctx->loop);
    }
}

static int verify_once(void)
{
    GError *error = NULL;

    GDBusConnection *bus =
        g_bus_get_sync(
            G_BUS_TYPE_SYSTEM,
            NULL,
            &error);

    if (!bus) {
        fprintf(
            stderr,
            "WebAuthn fingerprint: unable to connect to system D-Bus: %s\n",
            error ? error->message : "unknown error");

        g_clear_error(&error);
        return -1;
    }

    VerifyContext ctx = {
        .loop = g_main_loop_new(NULL, FALSE),
        .matched = FALSE,
        .finished = FALSE,
        .bus = bus
    };

    guint signal_id =
        g_dbus_connection_signal_subscribe(
            bus,
            FPRINT_SERVICE,
            FPRINT_INTERFACE,
            "VerifyStatus",
            FPRINT_DEVICE,
            NULL,
            G_DBUS_SIGNAL_FLAGS_NONE,
            on_verify_status,
            &ctx,
            NULL);

    /*
     * Claim the fingerprint device for the current user.
     *
     * Empty username means "the user running this process".
     */
    GVariant *reply =
        g_dbus_connection_call_sync(
            bus,
            FPRINT_SERVICE,
            FPRINT_DEVICE,
            FPRINT_INTERFACE,
            "Claim",
            g_variant_new("(s)", ""),
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            &error);

    if (!reply) {
        fprintf(
            stderr,
            "WebAuthn fingerprint: unable to claim device: %s\n",
            error ? error->message : "unknown error");

        g_clear_error(&error);

        g_dbus_connection_signal_unsubscribe(
            bus,
            signal_id);

        g_main_loop_unref(ctx.loop);
        g_object_unref(bus);

        return -1;
    }

    g_variant_unref(reply);

    /*
     * IMPORTANT:
     *
     * "any" tells fprintd to accept ANY enrolled fingerprint.
     *
     * This is the key difference from:
     *
     *     fprintd-verify
     *
     * which may select a particular enrolled finger.
     */
    fprintf(
        stderr,
        "WebAuthn: waiting for any enrolled fingerprint...\n");

    reply =
        g_dbus_connection_call_sync(
            bus,
            FPRINT_SERVICE,
            FPRINT_DEVICE,
            FPRINT_INTERFACE,
            "VerifyStart",
            g_variant_new("(s)", "any"),
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            &error);

    if (!reply) {
        fprintf(
            stderr,
            "WebAuthn fingerprint: VerifyStart failed: %s\n",
            error ? error->message : "unknown error");

        g_clear_error(&error);

        g_dbus_connection_signal_unsubscribe(
            bus,
            signal_id);

        /*
         * Best effort cleanup.
         */
        g_dbus_connection_call_sync(
            bus,
            FPRINT_SERVICE,
            FPRINT_DEVICE,
            FPRINT_INTERFACE,
            "Release",
            NULL,
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            -1,
            NULL,
            NULL);

        g_main_loop_unref(ctx.loop);
        g_object_unref(bus);

        return -1;
    }

    g_variant_unref(reply);

    /*
     * Wait for VerifyStatus.
     *
     * fprintd/libfprint tells us which enrolled fingerprint matched.
     */
    g_main_loop_run(ctx.loop);

    /*
     * Stop the verification operation.
     */
    g_dbus_connection_call_sync(
        bus,
        FPRINT_SERVICE,
        FPRINT_DEVICE,
        FPRINT_INTERFACE,
        "VerifyStop",
        NULL,
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        NULL);

    /*
     * Release device.
     */
    g_dbus_connection_call_sync(
        bus,
        FPRINT_SERVICE,
        FPRINT_DEVICE,
        FPRINT_INTERFACE,
        "Release",
        NULL,
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        NULL);

    g_dbus_connection_signal_unsubscribe(
        bus,
        signal_id);

    g_main_loop_unref(ctx.loop);
    g_object_unref(bus);

    return ctx.matched ? 0 : -1;
}

int fingerprint_verify(void)
{
    fprintf(
        stderr,
        "WebAuthn: fingerprint verification required\n");

    fprintf(
        stderr,
        "WebAuthn: up to %d attempts; any enrolled finger may be used\n",
        MAX_ATTEMPTS);

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {

        fprintf(
            stderr,
            "\nWebAuthn: fingerprint attempt %d/%d\n",
            attempt,
            MAX_ATTEMPTS);

        if (verify_once() == 0) {

            fprintf(
                stderr,
                "WebAuthn: fingerprint verification SUCCESS\n");

            return 0;
        }

        if (attempt < MAX_ATTEMPTS) {

            fprintf(
                stderr,
                "WebAuthn: fingerprint did not match; retrying...\n");
        }
    }

    fprintf(
        stderr,
        "WebAuthn: fingerprint verification FAILED after %d attempts\n",
        MAX_ATTEMPTS);

    return -1;
}
