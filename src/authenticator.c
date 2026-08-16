#include "authenticator.h"
#include "ctap.h"
#include "fido_hid.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int initialized = 0;
static GThread *fido_hid_thread = NULL;
static GMutex process_mutex = G_MUTEX_INIT;

static gpointer fido_hid_thread_main(gpointer user_data)
{
    (void)user_data;

    if (fido_hid_run() != 0)
        fprintf(stderr, "LINUX WebAuthn: FIDO HID transport stopped with an error\n");

    return NULL;
}

int authenticator_init(void)
{
    if (initialized)
        return 0;

    fprintf(
        stderr,
        "LINUX WebAuthn: initializing authenticator\n");

    ctap_init();

    fido_hid_thread = g_thread_new(
        "fido-hid",
        fido_hid_thread_main,
        NULL);

    if (!fido_hid_thread) {
        fprintf(stderr, "LINUX WebAuthn: failed to start FIDO HID thread\n");
        ctap_cleanup();
        return -1;
    }

    initialized = 1;

    return 0;
}

void authenticator_cleanup(void)
{
    if (!initialized)
        return;

    fprintf(
        stderr,
        "LINUX WebAuthn: shutting down authenticator\n");

    fido_hid_stop();

    if (fido_hid_thread) {
        g_thread_join(fido_hid_thread);
        fido_hid_thread = NULL;
    }

    ctap_cleanup();

    initialized = 0;
}

int authenticator_process(
    const uint8_t *input,
    size_t input_len,
    uint8_t **output,
    size_t *output_len)
{
    int uv_status;
    int rc;

    if (!initialized)
        return -1;

    /*
     * Only one CTAP operation may touch the authenticator state at a time.
     * FIDO HID runs on its own thread while D-Bus requests are dispatched
     * from the GLib main thread. Serializing here prevents concurrent
     * operations from racing on the TPM context and per-operation UV state.
     */
    g_mutex_lock(&process_mutex);

    /*
     * CTAP owns the user-verification policy. The transport layer
     * only carries the request and must not decide when fingerprint
     * verification is required.
     */
    if (ctap_is_user_verified()) {
        uv_status = CTAP2_OK;
    } else {
        uv_status = ctap_prepare_user_verification(
            input,
            input_len);
    }

    if (uv_status != CTAP2_OK) {
        if (!output || !output_len) {
            g_mutex_unlock(&process_mutex);
            return -1;
        }

        *output = malloc(1);

        if (!*output) {
            *output_len = 0;
            g_mutex_unlock(&process_mutex);
            return -1;
        }

        (*output)[0] = (uint8_t)uv_status;
        *output_len = 1;
        g_mutex_unlock(&process_mutex);
        return 0;
    }

    rc = ctap_process(
        input,
        input_len,
        output,
        output_len);

    /*
     * UV is strictly per-operation. Never allow a successful fingerprint
     * verification to authorize a later CTAP request.
     */
    ctap_set_user_verified(0);

    g_mutex_unlock(&process_mutex);

    return rc;
}