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
    POLKIT_PAM_SERVICES,
    SUDO_PAM_SERVICES,
)
from multi_settings.domain.validation import ValidationError
from multi_settings.i18n import _
from multi_settings.privileged.protocol import atomic_write, emit
from multi_settings.privileged.state import load_state, save_state
from multi_settings.privileged.users import administrator_names, interactive_user_names

PAM_DIRECTORY = Path("/etc/pam.d")
PAM_VENDOR_DIRECTORIES = (Path("/usr/lib/pam.d"),)
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
        if pam_auth_includes(line, "common-auth"):
            block = (
                f"{PAM_MARKER_START}\n{PAM_PASSWORD_LINE}\n{PAM_LINE}\n{PAM_MARKER_END}\n"
            )
            lines.insert(index + 1, block)
            return "".join(lines)
    raise ValidationError(_("PAM service does not include common-auth; refusing an unsafe edit."))


def pam_auth_includes(content: str, service: str) -> bool:
    target = re.escape(service)
    patterns = (
        rf"^\s*@include\s+{target}\s*(?:#.*)?$",
        rf"^\s*auth\s+(?:include|substack)\s+{target}\s*(?:#.*)?$",
    )
    return any(
        re.match(pattern, line) is not None
        for line in content.splitlines()
        for pattern in patterns
    )


def sudo_service_policy(enabled: bool) -> dict[str, bool]:
    available = {
        service: read_pam_service(service)
        for service in SUDO_PAM_SERVICES
        if pam_service_available(service)
    }
    if enabled and "sudo" not in available:
        raise ValidationError(_("The Ubuntu sudo PAM service was not found."))

    policy = {service: False for service in available}
    if not enabled:
        return policy

    policy["sudo"] = True
    sudo_i = available.get("sudo-i")
    if sudo_i is not None and not pam_auth_includes(sudo_i, "sudo"):
        if not pam_auth_includes(sudo_i, "common-auth"):
            raise ValidationError(
                _("The Ubuntu sudo-i PAM service has an unsupported authentication stack.")
            )
        policy["sudo-i"] = True
    return policy


def pam_service_source(service: str) -> Path | None:
    local_path = PAM_DIRECTORY / service
    if local_path.exists():
        if not local_path.is_file() or local_path.is_symlink():
            raise ValidationError(
                _("PAM service {service!r} is unavailable.").format(service=service)
            )
        return local_path
    for directory in PAM_VENDOR_DIRECTORIES:
        candidate = directory / service
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def pam_service_available(service: str) -> bool:
    return pam_service_source(service) is not None


def read_pam_service(service: str) -> str:
    source = pam_service_source(service)
    if source is None:
        raise ValidationError(
            _("PAM service {service!r} is unavailable.").format(service=service)
        )
    return source.read_text(encoding="utf-8")


def write_pam_service(service: str, enabled: bool) -> None:
    path = PAM_DIRECTORY / service
    source = pam_service_source(service)
    if source is None:
        if not enabled:
            return
        raise ValidationError(_("PAM service {service!r} is unavailable.").format(service=service))
    content = source.read_text(encoding="utf-8")
    updated = with_managed_pam_block(content) if enabled else without_managed_pam_block(content)
    if updated == content:
        return
    PAM_BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    absent_marker = PAM_BACKUP_DIR / f"{service}.local-absent"
    using_vendor_profile = source != path
    managed_vendor_override = using_vendor_profile or absent_marker.exists()
    backup = PAM_BACKUP_DIR / (
        f"{service}.vendor-original"
        if managed_vendor_override
        else f"{service}.original"
    )
    if not backup.exists():
        atomic_write(backup, content, 0o600)
    if using_vendor_profile:
        atomic_write(absent_marker, "", 0o600)
        PAM_DIRECTORY.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(path, updated, stat.S_IMODE(source.stat().st_mode))

    if not enabled and absent_marker.exists():
        vendor_backup = PAM_BACKUP_DIR / f"{service}.vendor-original"
        try:
            original_vendor_content = vendor_backup.read_text(encoding="utf-8")
        except OSError:
            original_vendor_content = None
        if updated == original_vendor_content:
            path.unlink()
        absent_marker.unlink(missing_ok=True)
        vendor_backup.unlink(missing_ok=True)


def configure_pam(payload: dict[str, Any]) -> None:
    login_enabled = payload.get("login") is True
    sudo_enabled = payload.get("sudo") is True
    polkit_enabled = payload.get("polkit") is True
    if (login_enabled or sudo_enabled or polkit_enabled) and not any(path.exists() for path in PAM_MODULE_CANDIDATES):
        raise ValidationError(_("libpam-u2f is not installed."))
    state = load_state()
    enrolled_users = {item.get("username") for item in state.get("enrollments", [])}
    required_users: set[str] = set()
    if login_enabled:
        required_users.update(interactive_user_names())
    if sudo_enabled or polkit_enabled:
        required_users.update(administrator_names())
    missing = sorted(required_users - enrolled_users)
    if missing:
        raise ValidationError(
            _("Refusing to enable a lockout-prone PAM policy. Enroll a key for: {users}").format(users=", ".join(missing))
        )

    login_services = [service for service in LOGIN_PAM_SERVICES if pam_service_available(service)]
    sudo_policy = sudo_service_policy(sudo_enabled)
    polkit_services = [service for service in POLKIT_PAM_SERVICES if pam_service_available(service)]
    if login_enabled and not login_services:
        raise ValidationError(_("No supported Ubuntu login PAM service was found."))
    if polkit_enabled and not polkit_services:
        raise ValidationError(_("The Ubuntu PolicyKit PAM service was not found."))

    for service in login_services if login_enabled else ():
        with_managed_pam_block(read_pam_service(service))
    for service, service_enabled in sudo_policy.items():
        if not service_enabled:
            continue
        with_managed_pam_block(read_pam_service(service))
    for service in polkit_services if polkit_enabled else ():
        with_managed_pam_block(read_pam_service(service))
    for service in login_services:
        write_pam_service(service, login_enabled)
    for service, service_enabled in sudo_policy.items():
        write_pam_service(service, service_enabled)
    for service in polkit_services:
        write_pam_service(service, polkit_enabled)
    state["pam"] = {
        "login": login_enabled,
        "sudo": sudo_enabled,
        "polkit": polkit_enabled,
    }
    save_state(state)
    emit("complete", message=_("Updated password + YubiKey requirements."))
