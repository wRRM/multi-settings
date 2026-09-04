from __future__ import annotations

import os
from pathlib import Path

APP_ID = "io.github.wrrm.multisettings"
APP_NAME = "Multi Settings"
POLKIT_ACTION = f"{APP_ID}.manage"
HELPER_PATH = Path(os.environ.get("MULTI_SETTINGS_HELPER", "/usr/libexec/multi-settings-helper"))

STATE_DIR = Path("/var/lib/multi-settings")
STATE_FILE = STATE_DIR / "state.json"
PRIVATE_STATE_FILE = STATE_DIR / "private-state.json"
MAPPING_FILE = Path("/etc/u2f_mappings")
PAM_BACKUP_DIR = STATE_DIR / "pam-backups"

DATA_DIR = Path(os.environ.get("MULTI_SETTINGS_DATA_DIR", "/usr/share/multi-settings"))
PLAYBOOK_PATH = DATA_DIR / "ansible/site.yml"
CALLBACK_DIR = DATA_DIR / "ansible/callback_plugins"
COLLECTIONS_PATH = DATA_DIR / "collections"
HARDENING_COLLECTION_VERSION = "10.6.0"
ANSIBLE_COLLECTIONS_PATH = ":".join(
    (
        str(COLLECTIONS_PATH),
        "/usr/share/ansible/collections",
        "/usr/lib/python3/dist-packages",
    )
)

PAM_ORIGIN = "pam://multi-settings"
PAM_MARKER_START = "# BEGIN MULTI SETTINGS YUBIKEY"
PAM_MARKER_END = "# END MULTI SETTINGS YUBIKEY"
PAM_PASSWORD_LINE = "auth required pam_unix.so try_first_pass"
PAM_LINE = (
    "auth required pam_u2f.so authfile=/etc/u2f_mappings cue "
    f"origin={PAM_ORIGIN} appid={PAM_ORIGIN}"
)

LOGIN_PAM_SERVICES = ("gdm-password", "login")
# Ubuntu's sudo-i PAM service includes sudo, so changing sudo covers both and
# avoids evaluating the second-factor module twice.
SUDO_PAM_SERVICES = ("sudo",)


def user_config_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "multi-settings"
