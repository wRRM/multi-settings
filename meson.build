project('multi-settings', version: '0.3.0', meson_version: '>= 1.3.0')

if get_option('prefix') != '/usr'
  error('Multi Settings is a system application; configure Meson with --prefix=/usr')
endif

gnome = import('gnome')
python = import('python').find_installation('python3')
dependency('gtk4', version: '>= 4.14')
dependency('libadwaita-1', version: '>= 1.5')

python.install_sources(
  'src/multi_settings/__init__.py',
  'src/multi_settings/__main__.py',
  'src/multi_settings/application.py',
  'src/multi_settings/config.py',
  'src/multi_settings/helper.py',
  'src/multi_settings/i18n.py',
  subdir: 'multi_settings',
)

python.install_sources(
  'src/multi_settings/domain/__init__.py',
  'src/multi_settings/domain/models.py',
  'src/multi_settings/domain/validation.py',
  subdir: 'multi_settings/domain',
)

python.install_sources(
  'src/multi_settings/privileged/__init__.py',
  'src/multi_settings/privileged/hardening.py',
  'src/multi_settings/privileged/pam.py',
  'src/multi_settings/privileged/protocol.py',
  'src/multi_settings/privileged/state.py',
  'src/multi_settings/privileged/users.py',
  'src/multi_settings/privileged/yubikeys.py',
  subdir: 'multi_settings/privileged',
)

python.install_sources(
  'src/multi_settings/services/__init__.py',
  'src/multi_settings/services/desktop_shortcut.py',
  'src/multi_settings/services/hardening.py',
  'src/multi_settings/services/hardening_results.py',
  'src/multi_settings/services/privileged.py',
  'src/multi_settings/services/settings.py',
  'src/multi_settings/services/system_users.py',
  'src/multi_settings/services/yubikeys.py',
  subdir: 'multi_settings/services',
)

python.install_sources(
  'src/multi_settings/views/__init__.py',
  'src/multi_settings/views/common.py',
  'src/multi_settings/views/hardening.py',
  'src/multi_settings/views/overview.py',
  'src/multi_settings/views/users.py',
  'src/multi_settings/views/window.py',
  'src/multi_settings/views/yubikeys.py',
  subdir: 'multi_settings/views',
)

install_data('bin/multi-settings', install_dir: get_option('bindir'), install_mode: 'rwxr-xr-x')
install_data('bin/multi-settings-helper', install_dir: get_option('libexecdir'), install_mode: 'rwxr-xr-x')
install_data('data/io.github.wrrm.multisettings.desktop', install_dir: get_option('datadir') / 'applications')
install_data('data/io.github.wrrm.multisettings.metainfo.xml', install_dir: get_option('datadir') / 'metainfo')
install_data('data/io.github.wrrm.multisettings.svg', install_dir: get_option('datadir') / 'icons/hicolor/scalable/apps')
install_data('data/io.github.wrrm.multisettings.policy', install_dir: get_option('datadir') / 'polkit-1/actions')
install_data('data/ansible/site.yml', install_dir: get_option('datadir') / 'multi-settings/ansible')
install_data('data/ansible/requirements.yml', install_dir: get_option('datadir') / 'multi-settings/ansible')
install_data('data/ansible/callback_plugins/multi_settings_jsonl.py', install_dir: get_option('datadir') / 'multi-settings/ansible/callback_plugins')
gnome.post_install(gtk_update_icon_cache: true, update_desktop_database: true)
