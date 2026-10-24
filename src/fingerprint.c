#include "fingerprint.h"

#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>

#define FPRINT_SERVICE "net.reactivated.Fprint"
#define FPRINT_DEVICE "/net/reactivated/Fprint/Device/0"
#define FPRINT_INTERFACE "net.reactivated.Fprint.Device"

#define MAX_ATTEMPTS 5

#define VERIFY_RESULT_MATCH 0
#define VERIFY_RESULT_FAILED (-1)
#define VERIFY_RESULT_TERMINAL_ERROR (-2)
#define VERIFY_RESULT_DEVICE_DISCONNECTED (-3)

static int fingerprint_device_disconnected;

static guint show_fingerprint_notification(void)
{
    GDBusConnection *bus;
    GError *error = NULL;
    GVariant *reply;
    guint notification_id = 0;

    bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!bus) {
        fprintf(stderr, "WebAuthn: desktop notification unavailable: %s\n",
                error ? error->message : "unknown error");
        g_clear_error(&error);
        return 0;
    }

    reply = g_dbus_connection_call_sync(
        bus,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "Notify",
        g_variant_new("(susss@as@a{sv}i)",
                      "LINUX WebAuthn", 0u, "",
                      "Fingerprint verification",
                      "Touch an enrolled finger on your fingerprint sensor to continue.",
                      g_variant_new_strv(NULL, 0),
                      g_variant_new_array(G_VARIANT_TYPE("{sv}"), NULL, 0),
                      60000),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        NULL,
        &error);

    if (!reply) {
        fprintf(stderr, "WebAuthn: unable to show fingerprint notification: %s\n",
                error ? error->message : "unknown error");
        g_clear_error(&error);
    } else {
        g_variant_get(reply, "(u)", &notification_id);
        g_variant_unref(reply);
    }

    g_object_unref(bus);
    return notification_id;
}

static void close_fingerprint_notification(guint notification_id)
{
    GDBusConnection *bus;

    if (!notification_id)
        return;

    bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, NULL);
    if (!bus)
        return;

    g_dbus_connection_call(
        bus,
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "CloseNotification",
        g_variant_new("(u)", notification_id),
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        NULL,
        NULL,
        NULL);
    g_object_unref(bus);
}

typedef struct {
    GMainLoop *loop;
    gboolean matched;
    gboolean finished;
    gboolean terminal_error;
    gboolean device_disconnected;
    guint timeout_source_id;
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

    if (g_strcmp0(result, "verify-disconnected") == 0) {
        ctx->device_disconnected = TRUE;
        ctx->finished = TRUE;

        if (ctx->loop)
            g_main_loop_quit(ctx->loop);

        return;
    }

    if (g_strcmp0(result, "verify-unknown-error") == 0) {
        ctx->terminal_error = TRUE;
        ctx->finished = TRUE;

        if (ctx->loop)
            g_main_loop_quit(ctx->loop);
    }
}

static gboolean on_verify_timeout(gpointer user_data)
{
    VerifyContext *ctx = user_data;

    if (!ctx)
        return G_SOURCE_REMOVE;

    ctx->finished = TRUE;
    ctx->timeout_source_id = 0;
    fprintf(stderr, "WebAuthn fingerprint: verification timed out\n");
    if (ctx->loop)
        g_main_loop_quit(ctx->loop);

    return G_SOURCE_REMOVE;
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
        .terminal_error = FALSE,
        .device_disconnected = FALSE,
        .timeout_source_id = 0,
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
            5000,
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
            5000,
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
            5000,
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
    ctx.timeout_source_id = g_timeout_add_seconds(30, on_verify_timeout, &ctx);
    if (ctx.timeout_source_id != 0) {
        g_main_loop_run(ctx.loop);
    } else {
        /* Fail closed if the timeout could not be installed. */
        ctx.finished = TRUE;
        fprintf(stderr, "WebAuthn fingerprint: unable to install verification timeout\n");
    }

    if (ctx.timeout_source_id != 0) {
        g_source_remove(ctx.timeout_source_id);
        ctx.timeout_source_id = 0;
    }

    /* A disconnected device must not receive any further D-Bus operations. */
    if (!ctx.device_disconnected) {
        /* Stop the verification operation. */
        g_dbus_connection_call_sync(
            bus,
            FPRINT_SERVICE,
            FPRINT_DEVICE,
            FPRINT_INTERFACE,
            "VerifyStop",
            NULL,
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            5000,
            NULL,
            NULL);

        /* Release device. */
        g_dbus_connection_call_sync(
            bus,
            FPRINT_SERVICE,
            FPRINT_DEVICE,
            FPRINT_INTERFACE,
            "Release",
            NULL,
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            5000,
            NULL,
            NULL);
    }

    g_dbus_connection_signal_unsubscribe(
        bus,
        signal_id);

    g_main_loop_unref(ctx.loop);
    g_object_unref(bus);

    if (ctx.matched)
        return VERIFY_RESULT_MATCH;
    if (ctx.device_disconnected)
        return VERIFY_RESULT_DEVICE_DISCONNECTED;
    if (ctx.terminal_error)
        return VERIFY_RESULT_TERMINAL_ERROR;
    return VERIFY_RESULT_FAILED;
}

int fingerprint_verify(void)
{
    guint notification_id;

    if (fingerprint_device_disconnected) {
        fprintf(
            stderr,
            "WebAuthn fingerprint: device is disconnected; restart the service after reconnecting it\n");
        return -1;
    }

    notification_id = show_fingerprint_notification();

    fprintf(
        stderr,
        "WebAuthn: fingerprint verification required\n");

    fprintf(
        stderr,
        "WebAuthn: up to %d attempts; any enrolled finger may be used\n",
        MAX_ATTEMPTS);

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        int result;

        fprintf(
            stderr,
            "\nWebAuthn: fingerprint attempt %d/%d\n",
            attempt,
            MAX_ATTEMPTS);

        result = verify_once();
        if (result == VERIFY_RESULT_MATCH) {

            fprintf(
                stderr,
                "WebAuthn: fingerprint verification SUCCESS\n");

            close_fingerprint_notification(notification_id);
            return 0;
        }

        if (result == VERIFY_RESULT_TERMINAL_ERROR) {
            fprintf(
                stderr,
                "WebAuthn fingerprint: terminal device error; stopping retries\n");
            close_fingerprint_notification(notification_id);
            return -1;
        }

        if (result == VERIFY_RESULT_DEVICE_DISCONNECTED) {
            fingerprint_device_disconnected = 1;
            fprintf(
                stderr,
                "WebAuthn fingerprint: device disconnected; stopping retries\n");
            close_fingerprint_notification(notification_id);
            return -1;
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

    close_fingerprint_notification(notification_id);
    return -1;
}
