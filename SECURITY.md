# Security policy

## Authentication policy

The authenticator's default policy is to require a successful fingerprint check before credential registration and before producing a normal WebAuthn assertion. A CTAP `GetAssertion` preflight probe with `up=false` may be processed without prompting, but its response is not a verified user-presence operation and must not authorize `GetNextAssertion`.

Fingerprint verification failure, timeout, or unavailable verification hardware must fail closed. TPM-backed keys are an additional key-protection layer; TPM storage does not replace user-verification enforcement.

## D-Bus attack surface

The normal browser path is the FIDO HID/UHID transport. Direct CTAP calls over the user's session D-Bus are disabled by default because the service cannot reliably distinguish trusted browser-originated requests from arbitrary processes on the same session bus.

For deliberate development diagnostics only, launch the service with:

```sh
LINUX_WEBAUTHN_ENABLE_DBUS_CTAP=1 linux-webauthn
```

Do not enable this option in a normal production session. It re-enables raw CTAP methods and should be treated as a debugging interface, not an authenticated application API. `GetInfo` remains available without this option. D-Bus byte-array inputs are size-limited before the service copies them.

## Credential storage

Credential metadata and TPM blobs are stored as private files. The implementation rejects symlinked credential files, requires regular files owned by the service user with private permissions, validates persisted metadata and exact file sizes, uses atomic file replacement, and checks/tightens credential directory permissions. These checks protect storage integrity and reduce accidental disclosure; they do not isolate the TPM from other processes running as the same user.

## Release-blocking security limitation: TPM isolation

**This project is not yet production-hardened.** Credential keys are currently created with an empty TPM `userAuth` and without a PCR-bound authorization policy. A process able to access both the credential blobs and the TPM interface may be able to load and use those keys without going through this service's fingerprint-verification path.

Do not attempt to fix this merely by adding a secret to the user service or placing a secret next to the credential blobs: another process running as the same user could read or reuse it. A valid fix needs a documented threat model and an enforced TPM access boundary or authorization design that survives restart, and must prove that untrusted same-user processes cannot directly request signing. Existing credentials may need a migration strategy if key attributes or parent policy change.

Before removing this release blocker, review and test:
- The persistent TPM parent handle, hierarchy authorization, attributes, and provisioning/recovery behavior.
- Whether non-service processes can reach the TPM device/resource manager and use credential blobs.
- The authorization path for every signing operation, including after service restart and system reboot.
- Credential migration, failure recovery, and compatibility with already registered WebAuthn credentials.

## Required validation before production

Automated CI covers hardened compilation and unit tests on Ubuntu 22.04 and 24.04, and builds/inspects/lints the Debian package on pushes and pull requests targeting `staging` or `main`. Green CI is not a substitute for the following checks, which have not been established by those jobs:

- **Real hardware:** use the supported TPM 2.0 and fingerprint sensor. Test successful and failed scans, repeated mismatches, sensor disconnect during verification, TPM unavailable at startup, TPM errors during signing, timeout, service restart, and reboot.
- **Browser end-to-end:** test WebAuthn registration and authentication in each supported browser. Confirm registration and assertion are rejected after fingerprint mismatch, timeout, disconnection, and unavailable verification hardware. Confirm a `GetAssertion` preflight response cannot be used as an assertion or authorize `GetNextAssertion`.
- **CTAP/FIDO2 conformance:** independently validate every protocol version, algorithm, extension, and option advertised by `authenticatorGetInfo`; test malformed requests, resident credential discovery, assertion sequencing, and authenticator data/flags against the applicable specification.
- **Service lifecycle and sandbox:** test D-Bus name acquisition/loss, UHID startup/teardown, restart behavior, and all systemd restrictions on supported desktop environments.
- **TPM isolation:** resolve the blocker above and add a regression test for the enforced authorization boundary.

The current CI and unit tests are useful regression checks, not certification or a complete security audit. Until the TPM isolation blocker and hardware/browser/conformance checks are closed with recorded results, do not describe this project as certified or fully production-ready.

## Reporting vulnerabilities

Please do not publish details of an exploitable security issue in a public issue before the maintainer has had an opportunity to investigate. Use GitHub's private vulnerability reporting feature for this repository if it is enabled; otherwise contact the repository maintainer privately.
