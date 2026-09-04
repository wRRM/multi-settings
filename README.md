# Multi Settings

Multi Settings is a native GTK 4/libadwaita application for preparing and
hardening Ubuntu 26.04 workstations. It provides:

- local user creation;
- primary and secondary YubiKey enrollment for administrator and standard
  accounts;
- password + YubiKey enforcement for graphical/console login and `sudo`;
- audit and application of the DevSec `os_hardening` and `ssh_hardening`
  Ansible roles;
- import of a `custom-settings.yml` file whose values have highest precedence;
- task-by-task hardening results with success, skipped, and failed states.

The GTK process always runs as the signed-in user. Read-only discovery is done
without elevation. Mutations go through a small, allow-listed helper launched
by PolicyKit. The policy uses `auth_admin_keep`, which lets the desktop's
authentication agent retain authorization briefly (normally five minutes)
without this application ever seeing or caching an administrator password.

## Development

Runtime packages on Ubuntu 26.04:

```sh
sudo apt install gir1.2-adw-1 gir1.2-gtk-4.0 meson ninja-build \
  python3-gi python3-yaml policykit-1 libpam-u2f yubikey-manager \
  ansible-core
```

Run from the checkout:

```sh
PYTHONPATH=src python3 -m multi_settings
```

The source-tree run can perform read-only discovery. Privileged operations
require an installed helper and policy:

```sh
meson setup build --prefix=/usr
meson compile -C build
sudo meson install -C build
sudo scripts/install-hardening-content
```

The collection installer pins `devsec.hardening` 10.6.0 beneath
`/usr/share/multi-settings/collections`; it does not execute either role.

Run the headless unit tests with:

```sh
python3 -m unittest discover -s tests -v
```

## Debian package

GitHub Actions builds an Ubuntu 26.04 `Architecture: all` package after every
push to `main`. The package and its SHA-256 checksum are available on the
workflow run's **Artifacts** page for 30 days. Pushing a tag matching the Debian
version, such as `v0.1.0`, also publishes the `.deb` and checksum on a GitHub
Release.

The package embeds the checksum-pinned DevSec hardening collection, so an
installed application does not download executable content at runtime. To
build the same package locally on Ubuntu 26.04:

```sh
sudo apt build-dep .
./scripts/fetch-hardening-content
dpkg-buildpackage --build=binary --unsigned-changes
```

## Safety and recovery

Multi Settings never edits `/etc/pam.d/common-auth`. It adds a clearly marked
second-factor line to the individual `gdm-password`, `login`, `sudo`, and
`sudo-i` service stacks. A required `pam_unix` check reuses the primary password
token and is followed by required `pam_u2f`, so alternate primary methods cannot
silently replace the password requirement. Originals are backed up once under
`/var/lib/multi-settings/pam-backups`. Credential material stays in a root-only
state file; the ordinary-user GUI reads a separate public status file containing
only usernames, slots, serial numbers, and policy state. The helper refuses to enable login or
sudo enforcement unless every affected interactive account has at least one
enrolled key. Disabling the corresponding switch removes only the managed
block.

An audit is an Ansible check-mode run. Applying hardening changes the local
machine and can affect SSH access, so review the audit and imported settings
before selecting **Apply hardening**.
