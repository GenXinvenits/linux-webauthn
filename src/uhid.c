#define _GNU_SOURCE

#include "uhid.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/uhid.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define UHID_DEVICE "/dev/uhid"
#define FIDO_REPORT_SIZE 64

static int uhid_fd = -1;

static void dump_bytes(const char *prefix, const uint8_t *data, size_t len)
{
    size_t n = len > FIDO_REPORT_SIZE ? FIDO_REPORT_SIZE : len;

    fprintf(stderr, "%s len=%zu", prefix, len);
    for (size_t i = 0; i < n; i++)
        fprintf(stderr, " %02x", data[i]);
    fprintf(stderr, "\n");
}

static int uhid_send_get_report_error(uint32_t id)
{
    struct uhid_event event;
    ssize_t n;

    memset(&event, 0, sizeof(event));
    event.type = UHID_GET_REPORT_REPLY;
    event.u.get_report_reply.id = id;
    event.u.get_report_reply.err = EIO;
    event.u.get_report_reply.size = 0;

    n = write(uhid_fd, &event,
              offsetof(struct uhid_event, u.get_report_reply.data));

    if (n < 0) {
        fprintf(stderr, "UHID_GET_REPORT_REPLY: write failed: %s\n",
                strerror(errno));
        return -1;
    }

    if ((size_t)n != offsetof(struct uhid_event, u.get_report_reply.data)) {
        fprintf(stderr,
                "UHID_GET_REPORT_REPLY: short write (%zd)\n", n);
        return -1;
    }

    fprintf(stderr,
            "UHID: GET_REPORT id=%u -> EIO\n", id);
    return 0;
}

static int uhid_send_set_report_error(uint32_t id)
{
    struct uhid_event event;
    ssize_t n;

    memset(&event, 0, sizeof(event));
    event.type = UHID_SET_REPORT_REPLY;
    event.u.set_report_reply.id = id;
    event.u.set_report_reply.err = EIO;

    n = write(uhid_fd, &event, sizeof(event.type) +
              sizeof(event.u.set_report_reply));

    if (n < 0) {
        fprintf(stderr, "UHID_SET_REPORT_REPLY: write failed: %s\n",
                strerror(errno));
        return -1;
    }

    if ((size_t)n != sizeof(event.type) + sizeof(event.u.set_report_reply)) {
        fprintf(stderr,
                "UHID_SET_REPORT_REPLY: short write (%zd)\n", n);
        return -1;
    }

    fprintf(stderr,
            "UHID: SET_REPORT id=%u -> EIO\n", id);
    return 0;
}

int uhid_open(const uint8_t *report_descriptor, size_t report_descriptor_len)
{
    struct uhid_event event;

    if (!report_descriptor || report_descriptor_len == 0 ||
        report_descriptor_len > sizeof(event.u.create2.rd_data))
        return -1;

    if (uhid_fd >= 0)
        return 0;

    uhid_fd = open(UHID_DEVICE, O_RDWR | O_CLOEXEC);
    if (uhid_fd < 0) {
        fprintf(stderr, "UHID: open %s failed: %s\n",
                UHID_DEVICE, strerror(errno));
        return -1;
    }

    memset(&event, 0, sizeof(event));
    event.type = UHID_CREATE2;

    snprintf((char *)event.u.create2.name,
             sizeof(event.u.create2.name),
             "Linux WebAuthn FIDO2 Authenticator");
    snprintf((char *)event.u.create2.phys,
             sizeof(event.u.create2.phys),
             "linux-webauthn/fido-hid");
    snprintf((char *)event.u.create2.uniq,
             sizeof(event.u.create2.uniq),
             "linux-webauthn");

    event.u.create2.rd_size = report_descriptor_len;
    memcpy(event.u.create2.rd_data,
           report_descriptor,
           report_descriptor_len);
    event.u.create2.bus = BUS_USB;
    event.u.create2.vendor = 0x1d50;
    event.u.create2.product = 0x615e;
    event.u.create2.version = 1;

    if (write(uhid_fd, &event, sizeof(event)) != sizeof(event)) {
        fprintf(stderr, "UHID_CREATE2: write failed: %s\n",
                strerror(errno));
        close(uhid_fd);
        uhid_fd = -1;
        return -1;
    }

    fprintf(stderr,
            "UHID: CREATE2 descriptor=%zu bytes\n",
            report_descriptor_len);

    return 0;
}

int uhid_read_output(uint8_t *data, size_t data_size, size_t *data_len)
{
    struct uhid_event event;
    ssize_t n;

    if (!data || !data_len || data_size < FIDO_REPORT_SIZE || uhid_fd < 0)
        return -1;

    *data_len = 0;

    for (;;) {
        memset(&event, 0, sizeof(event));

        n = read(uhid_fd, &event, sizeof(event));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "UHID: read failed: errno=%d (%s)\n",
                    errno, strerror(errno));
            return -1;
        }

        if (n == 0) {
            fprintf(stderr, "UHID: read EOF\n");
            return -1;
        }

        if (n < (ssize_t)sizeof(event.type)) {
            fprintf(stderr,
                    "UHID: short event (%zd bytes)\n", n);
            return -1;
        }

        fprintf(stderr,
                "UHID: event type=%u read=%zd bytes\n",
                event.type, n);

        switch (event.type) {
        case UHID_OUTPUT: {
            size_t output_size;

            if ((size_t)n < offsetof(struct uhid_event, u.output.size) +
                             sizeof(event.u.output.size)) {
                fprintf(stderr,
                        "UHID_OUTPUT: truncated event (%zd bytes)\n", n);
                return -1;
            }

            output_size = event.u.output.size;

            fprintf(stderr,
                    "UHID_OUTPUT: size=%zu rtype=%u\n",
                    output_size,
                    event.u.output.rtype);

            if (output_size > data_size) {
                fprintf(stderr,
                        "UHID_OUTPUT: report too large (%zu > %zu)\n",
                        output_size, data_size);
                return -1;
            }

            if ((size_t)n < offsetof(struct uhid_event, u.output.data) +
                             output_size) {
                fprintf(stderr,
                        "UHID_OUTPUT: truncated payload (%zd bytes, need %zu)\n",
                        n,
                        offsetof(struct uhid_event, u.output.data) + output_size);
                return -1;
            }

            memcpy(data, event.u.output.data, output_size);
            *data_len = output_size;
            dump_bytes("UHID_OUTPUT: RX", data, output_size);
            return 0;
        }

        case UHID_GET_REPORT:
            fprintf(stderr,
                    "UHID: GET_REPORT id=%u rnum=%u rtype=%u\n",
                    event.u.get_report.id,
                    event.u.get_report.rnum,
                    event.u.get_report.rtype);
            if (uhid_send_get_report_error(event.u.get_report.id) != 0)
                return -1;
            break;

        case UHID_SET_REPORT:
            fprintf(stderr,
                    "UHID: SET_REPORT id=%u rnum=%u rtype=%u size=%u\n",
                    event.u.set_report.id,
                    event.u.set_report.rnum,
                    event.u.set_report.rtype,
                    event.u.set_report.size);
            if (uhid_send_set_report_error(event.u.set_report.id) != 0)
                return -1;
            break;

        case UHID_OPEN:
            fprintf(stderr, "UHID: OPEN\n");
            break;

        case UHID_CLOSE:
            fprintf(stderr, "UHID: CLOSE\n");
            break;

        case UHID_START:
            fprintf(stderr,
                    "UHID: START flags=0x%llx\n",
                    (unsigned long long)event.u.start.dev_flags);
            break;

        case UHID_STOP:
            fprintf(stderr, "UHID: STOP\n");
            break;

        default:
            fprintf(stderr,
                    "UHID: ignoring event type %u\n",
                    event.type);
            break;
        }
    }
}

int uhid_send_input(const uint8_t *data, size_t data_len)
{
    struct uhid_event event;
    ssize_t n;
    size_t event_len;

    if (!data || data_len > sizeof(event.u.input2.data) || uhid_fd < 0)
        return -1;

    memset(&event, 0, sizeof(event));
    event.type = UHID_INPUT2;
    event.u.input2.size = data_len;
    memcpy(event.u.input2.data, data, data_len);

    event_len = offsetof(struct uhid_event, u.input2.data) + data_len;
    n = write(uhid_fd, &event, event_len);

    if (n < 0) {
        fprintf(stderr, "UHID_INPUT2: write failed: %s\n",
                strerror(errno));
        return -1;
    }

    if ((size_t)n != event_len) {
        fprintf(stderr,
                "UHID_INPUT2: short write (%zd/%zu)\n",
                n, event_len);
        return -1;
    }

    dump_bytes("UHID_INPUT2: TX", data, data_len);
    return 0;
}

void uhid_close(void)
{
    struct uhid_event event;

    if (uhid_fd < 0)
        return;

    memset(&event, 0, sizeof(event));
    event.type = UHID_DESTROY;
    if (write(uhid_fd, &event, sizeof(event.type)) < 0)
        fprintf(stderr, "UHID_DESTROY: write failed: %s\n",
                strerror(errno));

    close(uhid_fd);
    uhid_fd = -1;

    fprintf(stderr, "UHID: closed\n");
}
