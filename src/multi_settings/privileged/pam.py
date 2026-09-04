from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

from multi_settings.config import (
    LOGIN_PAM_SERVICES,
    PAM_BACKUP_DIR,
    PAM_LINE,
    PAM_MARKER_END,
    PAM_MARKER_START,
    PAM_PASSWORD_LINE,
    SUDO_PAM_SERVICES,
)
from multi_settings.domain.validation import ValidationError
from multi_settings.privileged.protocol import atomic_write, emit
from multi_settings.privileged.state import load_state, save_state
from multi_settings.privileged.users import administrator_names, interactive_user_names

PAM_DIRECTORY = Path("/etc/pam.d")
PAM_MODULE_CANDIDATES = (
    Path("/lib/x86_64-linux-gnu/security/pam_u2f.so"),
    Path("/usr/lib/x86_64-linux-gnu/security/pam_u2f.so"),
    Path("/lib/security/pam_u2f.so"),
)


def without_managed_pam_block(content: str) -> str:
    pattern = re.compile(
        rf"(?m)^\s*{re.escape(PAM_MARKER_START)}\n.*?^\s*{re.escape(PAM_MARKER_END)}\n?",
        re.DOTALL,
    )
    return pattern.sub("", content)


def with_managed_pam_block(content: str) -> str:
    clean = without_managed_pam_block(content)
    lines = clean.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if re.match(r"^\s*@include\s+common-auth\s*$", line):
            block = (
                f"{PAM_MARKER_START}\n{PAM_PASSWORD_LINE}\n{PAM_LINE}\n{PAM_MARKER_END}\n"
            )
            lines.insert(index + 1, block)
            return "".join(lines)
    raise ValidationError("PAM service does not include common-auth; refusing an unsafe edit.")


def write_pam_service(service: str, enabled: bool) -> None:
    path = PAM_DIRECTORY / service
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"PAM service {service!r} is unavailable.")
    content = path.read_text(encoding="utf-8")
    updated = with_managed_pam_block(content) if enabled else without_managed_pam_block(content)
    if updated == content:
        return
    PAM_BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = PAM_BACKUP_DIR / f"{service}.original"
    if not backup.exists():
        atomic_write(backup, content, 0o600)
    atomic_write(path, updated, stat.S_IMODE(path.stat().st_mode))


def configure_pam(payload: dict[str, Any]) -> None:
    login_enabled = payload.get("login") is True
    sudo_enabled = payload.get("sudo") is True
    if (login_enabled or sudo_enabled) and not any(path.exists() for path in PAM_MODULE_CANDIDATES):
        raise ValidationError("libpam-u2f is not installed.")
    state = load_state()
    enrolled_users = {item.get("username") for item in state.get("enrollments", [])}
    required_users: set[str] = set()
    if login_enabled:
        required_users.update(interactive_user_names())
    if sudo_enabled:
        required_users.update(administrator_names())
    missing = sorted(required_users - enrolled_users)
    if missing:
        raise ValidationError(
            "Refusing to enable a lockout-prone PAM policy. Enroll a key for: " + ", ".join(missing)
        )

    login_services = [service for service in LOGIN_PAM_SERVICES if (PAM_DIRECTORY / service).is_file()]
    sudo_services = [service for service in SUDO_PAM_SERVICES if (PAM_DIRECTORY / service).is_file()]
    if login_enabled and not login_services:
        raise ValidationError("No supported Ubuntu login PAM service was found.")
    if sudo_enabled and not sudo_services:
        raise ValidationError("The Ubuntu sudo PAM service was not found.")

    for service in login_services if login_enabled else ():
        with_managed_pam_block((PAM_DIRECTORY / service).read_text(encoding="utf-8"))
    for service in sudo_services if sudo_enabled else ():
        with_managed_pam_block((PAM_DIRECTORY / service).read_text(encoding="utf-8"))
    for service in login_services:
        write_pam_service(service, login_enabled)
    for service in sudo_services:
        write_pam_service(service, sudo_enabled)
    state["pam"] = {"login": login_enabled, "sudo": sudo_enabled}
    save_state(state)
    emit("complete", message="Updated password + YubiKey requirements.")
