# Onboarding

Onboarding is a native GTK 4/libadwaita application for preparing and
hardening Ubuntu 26.04 workstations. It provides:

- local user creation and removal of non-administrator accounts;
- primary and secondary YubiKey enrollment, including PIN-protected keys, for
  administrator and standard accounts;
- password + YubiKey enforcement for graphical/console login, `sudo`, and
  PolicyKit administrator prompts;
- independent or combined audit and application of the DevSec `os_hardening`
  and `ssh_hardening` Ansible roles;
- automatic loading of optional package settings followed by
  `~/.config/multi-settings/custom-settings.yaml`, whose values have highest
  precedence;
- task-by-task hardening results with success, skipped, and failed states,
  including visible failure/skip reasons and export as a private CSV file;
- a root-only pre-apply configuration backup with targeted restore of the paths
  changed by that hardening run.

The application interface defaults to Swedish. The header button switches the
entire interface between Swedish and English and remembers that preference for
the signed-in user.

The GTK process always runs as the signed-in user. Read-only discovery is done
without elevation. Mutations go through a small, allow-listed helper launched
by PolicyKit. The policy uses `auth_admin_keep`, which lets the desktop's
authentication agent retain authorization briefly (normally five minutes)
without this application ever seeing or caching an administrator password.

## Development

Runtime packages on Ubuntu 26.04:

```sh
sudo apt install gir1.2-adw-1 gir1.2-gtk-4.0 meson ninja-build \
  python3-gi python3-yaml polkitd pkexec libpam-u2f yubikey-manager \
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
./scripts/fetch-hardening-content
sudo meson install -C build
sudo scripts/install-hardening-content
```

The collection installer imports the checksum-pinned `devsec.hardening` 10.6.0
archive beneath `/usr/share/multi-settings/collections`; it does not download or
execute either role. To use a previously downloaded archive, import it with:

```sh
./scripts/fetch-hardening-content /path/to/devsec-hardening-10.6.0.tar.gz
```

Archives for other versions or archives whose checksum differs are rejected.

To inject organization-specific hardening settings into a manual build, stage
the YAML file before configuring or building the package:

```sh
./scripts/import-custom-settings /path/to/custom-settings.yaml
```

The importer validates the YAML, rejects duplicate keys and Jinja expressions,
and writes `vendor/custom-settings.yaml`. That file is ignored by Git and is
included in the package as `/usr/share/multi-settings/custom-settings.yaml`.
Do not put passwords or other secrets in it: packaged settings are readable by
local users. A signed-in user's private settings file overrides matching
top-level values from the package.

Settings use a flat Ansible variable mapping, for example
`os_auth_uid_min: 1100`. Every safe top-level variable is forwarded to the
pinned playbook as an extra variable: matching DevSec variables override role
defaults, while additional names are available to the playbook and collection
if referenced there. Ansible control variables and Jinja expressions are
rejected. For individual sysctl changes, use `sysctl_overwrite` as documented
by DevSec rather than replacing `sysctl_config`.

Run the headless unit tests with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Debian package

GitHub Actions builds an Ubuntu 26.04 `Architecture: all` package after every
push to `main`. The package and its SHA-256 checksum are available on the
workflow run's **Artifacts** page for 30 days. Pushing a tag matching the Debian
version, such as `v0.3.6`, also publishes the `.deb` and checksum on a GitHub
Release.

The package embeds the checksum-pinned DevSec hardening collection, so an
installed application does not download executable content at runtime. The CI
workflow caches that exact archive and downloads it only when the verified cache
is unavailable. To build the same package locally on Ubuntu 26.04:

```sh
sudo apt build-dep .
./scripts/fetch-hardening-content
# Optional: ./scripts/import-custom-settings /path/to/custom-settings.yaml
dpkg-buildpackage --build=binary --unsigned-changes
```

## Safety and recovery

Onboarding never edits `/etc/pam.d/common-auth`. It adds a clearly marked
second-factor line to the individual `gdm-password`, `login`, `sudo`, `sudo-i`,
and `polkit-1` service stacks. When `sudo-i` includes `sudo`, only `sudo` is
changed so the factor is not evaluated twice. A required `pam_unix` check reuses
the primary password token and is followed by required `pam_u2f`, so alternate
primary methods cannot silently replace the password requirement. For a PAM
profile supplied under `/usr/lib/pam.d`, Onboarding creates a reversible local
override under `/etc/pam.d` instead of editing the package-owned file. Originals
are backed up once under `/var/lib/multi-settings/pam-backups`. Credential material stays in a root-only
state file; the ordinary-user GUI reads a separate public status file containing
only usernames, slots, serial numbers, and policy state. The helper refuses to
enable login, sudo, or PolicyKit enforcement unless every affected account has
at least one enrolled key. Disabling the corresponding switch removes only the
managed block.

An audit is an Ansible check-mode run. Applying hardening changes the local
machine and can affect SSH access, so review the audit and imported settings
before selecting **Apply hardening**. Immediately before an apply, Onboarding
copies the relevant configuration into
`/var/lib/multi-settings/hardening-backups` and records which paths Ansible
actually changed. **Revert from backup** restores only those paths, then reloads
system configuration and SSH. The backup does not remove packages installed by
the role and is not a replacement for a full filesystem snapshot.
