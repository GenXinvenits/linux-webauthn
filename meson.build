project(
  'linux-webauthn',
  'c',
  version: '0.1',
  default_options: [
    'c_std=c11',
    'warning_level=2'
  ]
)


glib_dep = dependency('glib-2.0')
gio_dep = dependency('gio-2.0')
json_dep = dependency('json-glib-1.0')

openssl_dep = dependency('openssl')
tss2_esys_dep = dependency('tss2-esys')

subdir('src')
subdir('browser/native')
subdir('data')
