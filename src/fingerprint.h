#ifndef LINUX_WEBAUTHN_FINGERPRINT_H
#define LINUX_WEBAUTHN_FINGERPRINT_H

/*
 * Verify the current user's enrolled fingerprint.
 *
 * Returns:
 *   0  = fingerprint matched
 *  -1  = verification failed/cancelled/error
 */
int fingerprint_verify(void);

#endif
