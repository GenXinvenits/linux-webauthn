linux_webauthn_sources = files(
  'main.c',
  'authenticator.c',
  'credential.c',
  'credential_store.c',
  'ctap.c',
  'ctap_uv.c',
  'cbor.c',
  'fingerprint.c',
  'tpm.c',
  'uhid.c',
  'fido_hid.c'
)

executable(
  'linux-webauthn',
  linux_webauthn_sources,
  dependencies: [
    glib_dep,
    gio_dep,
    json_dep,
    openssl_dep,
    tss2_esys_dep
  ],
  install: true
)

executable(
  'webauthn-dbus-assertion-test',
  '../webauthn-dbus-assertion-test.c',
  'cbor.c',
  dependencies: [
    glib_dep,
    gio_dep,
    openssl_dep
  ],
  install: false
)

ctap_uv_test = executable(
  'test-ctap-uv',
  '../tests/test_ctap_uv.c',
  'ctap_uv.c',
  'cbor.c',
  include_directories: include_directories('.'),
  install: false
)

test('ctap-uv-security', ctap_uv_test)

credential_storage_test = executable(
  'test-credential-storage',
  '../tests/test_credential_storage.c',
  'credential.c',
  include_directories: include_directories('.'),
  install: false
)

test('credential-storage-security', credential_storage_test)
