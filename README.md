# Linux WebAuthn

A Linux-native FIDO2/WebAuthn authenticator that brings local Linux authentication hardware into the standard browser WebAuthn stack.

The project implements a virtual FIDO HID authenticator backed by the existing Linux fingerprint authentication stack and TPM-based credential/key handling. It exposes the authenticator through D-Bus for native integration and through Linux UHID/FIDO HID so WebAuthn-capable browsers can use it as a normal FIDO2 authenticator.

## Current status

**Production integration is implemented.** The current `main` branch contains the working authenticator, automatic user-session startup, D-Bus integration, virtual FIDO HID transport, fingerprint-backed user verification, resident credentials, browser test coverage, and Debian packaging support.

The project is intended to run as the logged-in user's service. It does **not** need to run as root and does not replace the existing Linux fingerprint/PAM stack.

## Functionality

### FIDO2 / CTAP2

- CTAP2 command processing.
- `authenticatorGetInfo` support.
- `authenticatorMakeCredential` support.
- `authenticatorGetAssertion` support.
- `authenticatorGetNextAssertion` support.
- CTAP user-verification policy handling.
- Correct assertion sequencing and UV lifetime handling.
- Authenticator data generation with WebAuthn flags.
- Resident/discoverable credential support.
- Resident credential discovery during assertions.
- Persistent credential registry.

### Fingerprint authentication

User verification is performed using the existing Linux fingerprint stack rather than implementing a second biometric stack.

The authenticator integrates with `fprintd`/`libfprint` and uses the enrolled fingerprint of the current Linux user when a CTAP operation requires user verification.

This means the same fingerprint enrollment already used for Linux authentication can be used to authorize WebAuthn operations.

### TPM-backed credentials

- TPM 2.0 ESAPI integration through `tss2-esys`.
- TPM-backed credential/key operations.
- Persistent credential metadata and storage.
- Cryptographic operations using OpenSSL where required by the WebAuthn/FIDO2 implementation.

### Virtual FIDO HID

The project exposes a virtual FIDO authenticator through Linux UHID.

The transport implements the FIDO HID protocol needed by the authenticator and allows WebAuthn-capable applications to communicate with the authenticator through the normal Linux FIDO HID path.

The authenticator is therefore usable without requiring a physical USB security key.

### D-Bus interface

The service exposes:

```text
Bus name:   org.linux.WebAuthn
Object:     /org/linux/WebAuthn
Interface:  org.linux.WebAuthn.Authenticator
```

Current methods include:

- `GetInfo`
- `Process`
- `MakeCredential`
- `GetAssertion`

The D-Bus methods use the same authenticator/CTAP processing path as the FIDO HID transport so the two interfaces share the same credential, UV, and authenticator state.

## Automatic user-session startup

The production service is installed as a **systemd user service**:

```text
linux-webauthn.service
```

It is associated with the user's `default.target` and starts automatically in the user's graphical session.

The service:

- runs as the logged-in user;
- acquires the `org.linux.WebAuthn` D-Bus name;
- starts the virtual FIDO HID authenticator;
- restarts automatically after failure;
- does not require root privileges.

The installed service is intentionally a user service because fingerprint verification and desktop authentication belong to the active user's session.

## Architecture

```text
                    WebAuthn-capable browser
                              │
                              │ FIDO HID
                              ▼
                    ┌─────────────────────┐
                    │    Linux UHID       │
                    │  Virtual FIDO HID   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   linux-webauthn    │
                    │  Authenticator core │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
          CTAP2/FIDO2      Credential       User
           processing         store        verification
              │                │                │
              │                │                ▼
              │                │        fprintd / libfprint
              │                │                │
              │                │                ▼
              │                │       Fingerprint sensor
              │                │
              │                ▼
              │             TPM 2.0
              │
              ▼
        WebAuthn authenticator data

                     ▲
                     │
                     │ D-Bus
                     │
        org.linux.WebAuthn.Authenticator
```

## Project components

The production authenticator is built from the following major components:

- `main.c` — D-Bus service and application lifecycle.
- `authenticator.c` — common authenticator processing and CTAP user-verification policy.
- `ctap.c` — CTAP2 command implementation and WebAuthn authenticator behavior.
- `ctap_uv.c` — CTAP user-verification handling.
- `credential.c` — credential generation and credential operations.
- `credential_store.c` — persistent credential registry.
- `fingerprint.c` — Linux fingerprint verification integration.
- `tpm.c` — TPM 2.0 integration.
- `fido_hid.c` — FIDO HID transport.
- `uhid.c` — Linux UHID virtual-device implementation.
- `cbor.c` — CBOR encoding/decoding used by CTAP2.

## Installation

### Build from source

Dependencies include:

- GLib 2.x / GIO
- json-glib
- OpenSSL
- TPM 2.0 TSS ESAPI (`tss2-esys`)
- Meson
- Ninja

Build and install:

```bash
meson setup build
ninja -C build
sudo ninja -C build install
```

The installation provides the authenticator binary, D-Bus service, systemd user service, automatic-start symlink, and udev rules.

### Debian package

A Debian package is provided for production installation on compatible Debian/Ubuntu systems.

Install a locally built package with:

```bash
sudo apt install ./linux-webauthn_*.deb
```

The package installs the same production components as the source installation, including:

```text
/usr/bin/linux-webauthn
/usr/lib/systemd/user/linux-webauthn.service
/usr/lib/systemd/user/default.target.wants/linux-webauthn.service
/usr/share/dbus-1/services/org.linux.WebAuthn.service
/usr/lib/udev/rules.d/70-linux-webauthn.rules
```

After installation, the service is intended to run automatically in the user's session.

## Verifying the installation

Check the user service:

```bash
systemctl --user status linux-webauthn.service
```

Check the D-Bus service:

```bash
busctl --user status org.linux.WebAuthn
```

Inspect the authenticator interface:

```bash
busctl --user introspect \
    org.linux.WebAuthn \
    /org/linux/WebAuthn \
    org.linux.WebAuthn.Authenticator
```

A running installation should expose the `linux-webauthn` process, the `org.linux.WebAuthn` bus name, and the virtual FIDO HID authenticator.

## Testing

The repository contains development and integration tests for the authenticator, including:

- D-Bus CTAP processing tests.
- WebAuthn registration tests.
- WebAuthn authentication/assertion tests.
- Cryptographic assertion verification.
- Resident credential registration and discovery.
- Persistent resident credential handling.
- Browser-based WebAuthn test flows.

The test programs and test server are development/integration tooling and are not installed as production runtime components.

## Security model

The project deliberately reuses the Linux system's existing biometric authentication path instead of maintaining a separate fingerprint database.

The high-level security flow is:

```text
Browser WebAuthn request
        │
        ▼
CTAP2 authenticator operation
        │
        ▼
Fingerprint user verification
        │
        ▼
TPM-backed credential/key operation
        │
        ▼
FIDO2/WebAuthn authenticator response
```

The authenticator runs inside the user's session and is protected by the existing Linux user/session permissions. No root daemon is required for normal operation.

## Scope

The current project focuses on providing a Linux-native virtual FIDO2/WebAuthn authenticator backed by local fingerprint authentication and TPM-based credentials.

It is **not** a replacement for `fprintd`, `libfprint`, PAM, or the Linux TPM stack. Those components remain the underlying platform services used by the authenticator.

## License

See the repository license and individual source files for licensing information.
