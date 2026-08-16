service_file = configure_file(
  input: 'org.linux.WebAuthn.service.in',
  output: 'org.linux.WebAuthn.service',
  configuration: {
    'bindir': get_option('prefix') / get_option('bindir')
  }
)

install_data(
  service_file,
  install_dir: get_option('datadir') / 'dbus-1/services'
)

install_data(
  '70-linux-webauthn.rules',
  install_dir: get_option('prefix') / 'lib/udev/rules.d'
)
