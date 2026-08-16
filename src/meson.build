linux_webauthn_sources = files(
  'main.c',
  'authenticator.c',
  'credential.c',
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
