#include "authenticator.h"
#include "ctap.h"

#include <stdio.h>

static int initialized = 0;

int authenticator_init(void)
{
    if (initialized)
        return 0;

    fprintf(
        stderr,
        "LINUX WebAuthn: initializing authenticator\n");

    ctap_init();

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
