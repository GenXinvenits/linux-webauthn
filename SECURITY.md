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

## Reporting vulnerabilities

Please do not publish details of an exploitable security issue in a public issue before the maintainer has had an opportunity to investigate. Use GitHub's private vulnerability reporting feature for this repository if it is enabled; otherwise contact the repository maintainer privately.

## Current assurance and limitations

This policy and the regression tests are not a certification or a complete security audit. Before a production deployment, the project still needs:

- Build and test results from the supported Ubuntu/Debian environments.
- Hardware tests with the actual TPM 2.0 and fingerprint sensor, including failed scans, disconnects, and timeouts.
- End-to-end browser tests proving that no assertion can be accepted without the required fingerprint verification.
- A review of credential file handling, TPM parent/policy configuration, D-Bus lifecycle and service sandboxing.
- Review of CTAP/FIDO2 conformance, including all advertised protocol versions and options.

Do not treat this project as certified or fully production-hardened until those checks have been completed.
