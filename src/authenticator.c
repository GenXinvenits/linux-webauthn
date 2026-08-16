#include "authenticator.h"
#include "ctap.h"
#include "fido_hid.h"

#include <glib.h>
#include <stdio.h>

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
    if (!initialized)
        return -1;

    return ctap_process(
        input,
        input_len,
        output,
        output_len);
}
