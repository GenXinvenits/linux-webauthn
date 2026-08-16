#include "authenticator.h"
#include "ctap.h"
#include "fido_hid.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int initialized = 0;
static GThread *fido_hid_thread = NULL;

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

    if (!initialized)
        return -1;

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
        if (!output || !output_len)
            return -1;

        *output = malloc(1);

        if (!*output) {
            *output_len = 0;
            return -1;
        }

        (*output)[0] = (uint8_t)uv_status;
        *output_len = 1;

        return 0;
    }

    return ctap_process(
        input,
        input_len,
        output,
        output_len);
}
