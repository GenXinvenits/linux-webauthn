# Linux WebAuthn

A Linux-native WebAuthn authenticator bridge for Linux desktops.

Linux WebAuthn aims to bring a Windows Hello–like authentication experience to Linux by integrating system authentication hardware (fingerprint sensors, TPM-backed credentials, and other local authenticators) with modern WebAuthn/FIDO2 browser authentication.

The project provides a bridge between:

- Web browsers (Firefox/Chromium WebAuthn API)
- Linux desktop services
- Linux authentication hardware
- Native FIDO2 credential handling

---

## Features

### Browser Integration

- Firefox WebExtension support
- Native Messaging Host communication
- WebAuthn request forwarding from browser to Linux services
- Registration and authentication flow handling

### Linux Integration

- Native Linux desktop integration
- D-Bus communication layer
- Linux-friendly authentication workflow
- Designed for Linux Shell environments

### Authentication Hardware Support

The project is designed to support:

- Fingerprint sensors through Linux biometric frameworks
- TPM-backed credential storage
- Hardware-backed FIDO2/WebAuthn credentials
- Future expansion for additional authenticators

---

# Architecture

                    WebAuthn application
                           │
                           │ WebAuthn API
                           ▼
                ┌──────────────────────┐
                │   linux-webauthn     │
                │  WebAuthn service    │
                └──────────┬───────────┘
                           │
                    authenticator logic
                           │
              ┌────────────┴────────────┐
              │                         │
       Credential store            User presence/
       + key management             verification
              │                         │
              └────────────┬────────────┘
                           │
                           ▼
                 Existing Linux stack
                           │
                    fprintd / PAM
                           │
                           ▼
                  libfprint / TOD
                           │
                           ▼
                   Fingerprint sensor
                   
                   
                   
