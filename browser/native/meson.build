native_sources = files(
  'linux-webauthn-native.c',
  '../../src/cbor.c'
)


executable(
  'linux-webauthn-native',
  native_sources,
  include_directories: include_directories('../../src'),
  dependencies: [
    glib_dep,
    gio_dep,
    json_dep
  ],
  install: true
)
