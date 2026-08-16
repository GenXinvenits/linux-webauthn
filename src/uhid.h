#ifndef LINUX_WEBAUTHN_UHID_H
#define LINUX_WEBAUTHN_UHID_H

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal Linux UHID wrapper used by the virtual FIDO HID authenticator.
 */
int uhid_open(const uint8_t *report_descriptor, size_t report_descriptor_len);
int uhid_read_output(uint8_t *data, size_t data_size, size_t *data_len);
int uhid_send_input(const uint8_t *data, size_t data_len);
void uhid_close(void);

#endif
