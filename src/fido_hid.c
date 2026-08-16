#include "fido_hid.h"

#include "authenticator.h"
#include "ctap.h"
#include "fingerprint.h"
#include "uhid.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HID_REPORT_SIZE 64
#define FIDO_BROADCAST_CID 0xffffffffU
#define FIDO_CMD_MASK 0x80U

#define CTAPHID_PING       0x81
#define CTAPHID_MSG        0x83
#define CTAPHID_LOCK       0x84
#define CTAPHID_INIT       0x86
#define CTAPHID_WINK       0x88
#define CTAPHID_CBOR       0x90
#define CTAPHID_CANCEL     0x91
#define CTAPHID_KEEPALIVE  0xBB
#define CTAPHID_ERROR      0xBF

#define CTAPHID_ERR_INVALID_CMD 0x01
#define CTAPHID_ERR_INVALID_PAR 0x02
#define CTAPHID_ERR_INVALID_LEN 0x03
#define CTAPHID_ERR_INVALID_SEQ 0x04
#define CTAPHID_ERR_CHANNEL_BUSY 0x06
#define CTAPHID_ERR_OTHER 0x7f

#define CTAPHID_CAPABILITY_WINK 0x01
#define CTAPHID_CAPABILITY_CBOR 0x04
#define CTAPHID_CAPABILITY_NMSG 0x08

static volatile int running = 1;
static uint32_t next_channel = 0x01020304U;

static const uint8_t fido_report_descriptor[] = {
    0x06, 0xD0, 0xF1,
    0x09, 0x01,
    0xA1, 0x01,
    0x09, 0x20,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x81, 0x02,
    0x09, 0x21,
    0x15, 0x00,
    0x26, 0xFF, 0x00,
    0x75, 0x08,
    0x95, 0x40,
    0x91, 0x02,
    0xC0
};

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t get_be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           p[3];
}

static uint32_t allocate_channel(void)
{
    uint32_t cid = next_channel++;

    if (cid == FIDO_BROADCAST_CID || cid == 0)
        cid = next_channel++;

    return cid;
}

static int send_packet(uint32_t cid, uint8_t cmd,
                       const uint8_t *data, size_t len)
{
    uint8_t report[HID_REPORT_SIZE];
    size_t offset = 0;
    uint8_t seq = 0;

    if (len > 0xffff)
        return -1;

    while (offset < len || (offset == 0 && len == 0)) {
        size_t chunk;

        memset(report, 0, sizeof(report));
        put_be32(report, cid);

        if (offset == 0) {
            report[4] = cmd | FIDO_CMD_MASK;
            put_be16(report + 5, (uint16_t)len);
            chunk = len > 57 ? 57 : len;
            if (chunk)
                memcpy(report + 7, data, chunk);
        } else {
            report[4] = seq++;
            chunk = len - offset > 59 ? 59 : len - offset;
            memcpy(report + 5, data + offset, chunk);
        }

        if (uhid_send_input(report, sizeof(report)) != 0)
            return -1;

        offset += chunk;
    }

    return 0;
}

static int send_error(uint32_t cid, uint8_t error)
{
    return send_packet(cid, CTAPHID_ERROR & 0x7f, &error, 1);
}

static int handle_init(uint32_t cid, const uint8_t *data, size_t len)
{
    uint8_t response[17] = {0};
    uint32_t new_cid;

    if (len != 8)
        return send_error(cid, CTAPHID_ERR_INVALID_LEN);

    new_cid = allocate_channel();
    memcpy(response, data, 8);
    put_be32(response + 8, new_cid);
    response[12] = 2; /* CTAPHID protocol version */
    response[13] = 1; /* major */
    response[14] = 0; /* minor */
    response[15] = 0; /* build */
    response[16] = CTAPHID_CAPABILITY_CBOR | CTAPHID_CAPABILITY_WINK;

    return send_packet(cid, CTAPHID_INIT & 0x7f, response, sizeof(response));
}

static int handle_cbor(uint32_t cid, const uint8_t *data, size_t len)
{
    uint8_t *output = NULL;
    size_t output_len = 0;
    int rc;

    if (len == 0)
        return send_error(cid, CTAPHID_ERR_INVALID_LEN);

    /* CTAPHID_CBOR payload starts with the CTAP2 command byte. */
    if (data[0] == CTAP_CMD_MAKE_CREDENTIAL ||
        data[0] == CTAP_CMD_GET_ASSERTION) {
        fprintf(stderr, "FIDO HID: fingerprint verification required\n");
        if (fingerprint_verify() != 0) {
            ctap_set_user_verified(0);
            return send_error(cid, CTAPHID_ERR_OTHER);
        }
        ctap_set_user_verified(1);
    }

    rc = authenticator_process(data, len, &output, &output_len);
    ctap_set_user_verified(0);

    if (rc != 0 || !output) {
        free(output);
        return send_error(cid, CTAPHID_ERR_OTHER);
    }

    rc = send_packet(cid, CTAPHID_CBOR & 0x7f, output, output_len);
    free(output);
    return rc;
}

static int handle_message(uint32_t cid, uint8_t cmd,
                          const uint8_t *data, size_t len)
{
    switch (cmd | FIDO_CMD_MASK) {
    case CTAPHID_PING:
        return send_packet(cid, CTAPHID_PING & 0x7f, data, len);

    case CTAPHID_INIT:
        return handle_init(cid, data, len);

    case CTAPHID_CBOR:
        return handle_cbor(cid, data, len);

    case CTAPHID_CANCEL:
        return 0;

    case CTAPHID_WINK:
        return send_packet(cid, CTAPHID_WINK & 0x7f, NULL, 0);

    case CTAPHID_LOCK:
        return send_packet(cid, CTAPHID_LOCK & 0x7f, NULL, 0);

    default:
        return send_error(cid, CTAPHID_ERR_INVALID_CMD);
    }
}

static int receive_message(uint8_t *report, size_t report_len,
                           uint32_t *cid_out, uint8_t *cmd_out,
                           uint8_t **payload_out, size_t *payload_len_out)
{
    uint32_t cid;
    uint8_t cmd;
    uint16_t expected;
    size_t received;
    uint8_t *payload;
    uint8_t seq = 0;

    if (report_len < 7 || !cid_out || !cmd_out ||
        !payload_out || !payload_len_out)
        return -1;

    cid = get_be32(report);
    cmd = report[4];

    if (!(cmd & FIDO_CMD_MASK))
        return -1;

    expected = get_be16(report + 5);
    if (expected > 65535)
        return -1;

    payload = expected ? malloc(expected) : NULL;
    if (expected && !payload)
        return -1;

    received = report_len > 7 ? report_len - 7 : 0;
    if (received > expected)
        received = expected;
    if (received)
        memcpy(payload, report + 7, received);

    while (received < expected) {
        uint8_t next[HID_REPORT_SIZE];
        size_t next_len = 0;

        if (uhid_read_output(next, sizeof(next), &next_len) != 0 ||
            next_len < 5 || get_be32(next) != cid ||
            next[4] != seq++) {
            free(payload);
            return -1;
        }

        size_t chunk = expected - received;
        if (chunk > 59)
            chunk = 59;
        if (next_len - 5 < chunk) {
            free(payload);
            return -1;
        }
        memcpy(payload + received, next + 5, chunk);
        received += chunk;
    }

    *cid_out = cid;
    *cmd_out = cmd & 0x7f;
    *payload_out = payload;
    *payload_len_out = expected;
    return 0;
}

int fido_hid_run(void)
{
    uint8_t report[HID_REPORT_SIZE];
    size_t report_len;

    running = 1;

    if (uhid_open(fido_report_descriptor,
                  sizeof(fido_report_descriptor)) != 0)
        return -1;

    fprintf(stderr, "FIDO HID: virtual authenticator ready\n");

    while (running) {
        uint32_t cid;
        uint8_t cmd;
        uint8_t *payload = NULL;
        size_t payload_len = 0;

        if (uhid_read_output(report, sizeof(report), &report_len) != 0)
            break;

        if (receive_message(report, report_len, &cid, &cmd,
                            &payload, &payload_len) != 0)
            continue;

        (void)handle_message(cid, cmd, payload, payload_len);
        free(payload);
    }

    uhid_close();
    return 0;
}

void fido_hid_stop(void)
{
    running = 0;
    uhid_close();
}
