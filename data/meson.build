service_file = configure_file(
  input: 'org.linux.WebAuthn.service.in',
  output: 'org.linux.WebAuthn.service',
  configuration: {
    'bindir': get_option('prefix') / get_option('bindir')
  }
)

user_service_file = configure_file(
  input: 'linux-webauthn.service.in',
  output: 'linux-webauthn.service',
  configuration: {
    'bindir': get_option('prefix') / get_option('bindir')
  }
)

install_data(
  service_file,
  install_dir: get_option('datadir') / 'dbus-1/services'
)

user_unit_dir = get_option('prefix') / 'lib/systemd/user'

install_data(
  user_service_file,
  install_dir: user_unit_dir
)

install_symlink(
  'linux-webauthn.service',
  install_dir: user_unit_dir / 'default.target.wants',
  pointing_to: '../linux-webauthn.service'
)

install_data(
  '70-linux-webauthn.rules',
  install_dir: get_option('prefix') / 'lib/udev/rules.d'
)

install_data(
  'linux-webauthn.conf',
  install_dir: '/usr/lib/modules-load.d'
)
