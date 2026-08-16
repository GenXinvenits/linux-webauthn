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
        perror("open /dev/uhid");
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
        perror("UHID_CREATE2");
        close(uhid_fd);
        uhid_fd = -1;
        return -1;
    }

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
        n = read(uhid_fd, &event, sizeof(event));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if ((size_t)n != sizeof(event))
            return -1;

        switch (event.type) {
        case UHID_OUTPUT:
            if (event.u.output.size > data_size)
                return -1;
            memcpy(data, event.u.output.data, event.u.output.size);
            *data_len = event.u.output.size;
            return 0;

        case UHID_OUTPUT2:
            if (event.u.output2.size > data_size)
                return -1;
            memcpy(data, event.u.output2.data, event.u.output2.size);
            *data_len = event.u.output2.size;
            return 0;

        case UHID_OPEN:
        case UHID_CLOSE:
        case UHID_START:
        case UHID_STOP:
        case UHID_OUTPUT_EV:
            break;

        default:
            break;
        }
    }
}

int uhid_send_input(const uint8_t *data, size_t data_len)
{
    struct uhid_event event;

    if (!data || data_len > sizeof(event.u.input.data) || uhid_fd < 0)
        return -1;

    memset(&event, 0, sizeof(event));
    event.type = UHID_INPUT2;
    event.u.input2.size = data_len;
    memcpy(event.u.input2.data, data, data_len);

    if (write(uhid_fd, &event, sizeof(event)) != sizeof(event))
        return -1;

    return 0;
}

void uhid_close(void)
{
    struct uhid_event event;

    if (uhid_fd < 0)
        return;

    memset(&event, 0, sizeof(event));
    event.type = UHID_DESTROY;
    (void)write(uhid_fd, &event, sizeof(event));

    close(uhid_fd);
    uhid_fd = -1;
}
