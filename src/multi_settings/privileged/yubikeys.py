from __future__ import annotations

from typing import Any

from multi_settings.config import MAPPING_FILE
from multi_settings.domain.models import KeySlot
from multi_settings.domain.validation import ValidationError, validate_serial, validate_username
from multi_settings.i18n import _
from multi_settings.privileged.protocol import atomic_write, emit
from multi_settings.privileged.state import load_state, save_state
from multi_settings.privileged.users import administrator_names, ensure_known_user


def rebuild_mapping_file(state: dict[str, Any]) -> None:
    by_user: dict[str, list[str]] = {}
    for enrollment in state.get("enrollments", []):
        credential = enrollment.get("credential", "")
        username = enrollment.get("username", "")
        prefix = f"{username}:"
        if isinstance(credential, str) and credential.startswith(prefix):
            by_user.setdefault(username, []).append(credential[len(prefix) :])
    lines = [f"{username}:{':'.join(credentials)}" for username, credentials in sorted(by_user.items())]
    atomic_write(MAPPING_FILE, "\n".join(lines) + ("\n" if lines else ""), 0o600)


def validate_credential(username: str, credential: str) -> str:
    if len(credential) > 16_384 or "\n" in credential or "\r" in credential:
        raise ValidationError(_("The generated credential has an invalid format."))
    if not credential.startswith(f"{username}:"):
        raise ValidationError(_("The generated credential belongs to a different account."))
    fields = credential.split(":", maxsplit=1)[1].split(",")
    if len(fields) < 3 or any(not field.strip() for field in fields[:3]):
        raise ValidationError(_("The generated credential is incomplete."))
    return credential


def enroll_yubikey(payload: dict[str, Any]) -> None:
    username = validate_username(str(payload.get("username", "")))
    ensure_known_user(username)
    serial = validate_serial(str(payload.get("serial", "")))
    try:
        slot = KeySlot(str(payload.get("slot", "")))
    except ValueError as error:
        raise ValidationError(_("Choose the primary or secondary slot.")) from error
    credential = validate_credential(username, str(payload.get("credential", "")))
    state = load_state()
    enrollments = state.setdefault("enrollments", [])
    if any(item.get("serial") == serial for item in enrollments):
        raise ValidationError(_("YubiKey {serial} is already enrolled.").format(serial=serial))
    if any(item.get("username") == username and item.get("slot") == slot.value for item in enrollments):
        raise ValidationError(_("{username} already has a {slot} YubiKey.").format(username=username, slot=_(slot.value.title()).lower()))
    enrollments.append(
        {"username": username, "serial": serial, "slot": slot.value, "credential": credential}
    )
    rebuild_mapping_file(state)
    save_state(state)
    emit("complete", message=_("Enrolled YubiKey {serial} as {username}'s {slot} key.").format(serial=serial, username=username, slot=_(slot.value.title()).lower()))


def unenroll_yubikey(payload: dict[str, Any]) -> None:
    username = validate_username(str(payload.get("username", "")))
    try:
        slot = KeySlot(str(payload.get("slot", "")))
    except ValueError as error:
        raise ValidationError(_("Choose the primary or secondary slot.")) from error
    state = load_state()
    existing = state.get("enrollments", [])
    remaining = [
        item
        for item in existing
        if not (item.get("username") == username and item.get("slot") == slot.value)
    ]
    if len(existing) == len(remaining):
        raise ValidationError(_("{username} has no {slot} YubiKey enrollment.").format(username=username, slot=_(slot.value.title()).lower()))
    still_enrolled = any(item.get("username") == username for item in remaining)
    pam = state.get("pam", {})
    account_needs_key = pam.get("login") is True or (
        (pam.get("sudo") is True or pam.get("polkit") is True)
        and username in administrator_names()
    )
    if account_needs_key and not still_enrolled:
        raise ValidationError(
            _("Disable the affected password + YubiKey requirement before removing this account's last key.")
        )
    state["enrollments"] = remaining
    rebuild_mapping_file(state)
    save_state(state)
    emit("complete", message=_("Removed {username}'s {slot} YubiKey enrollment.").format(username=username, slot=_(slot.value.title()).lower()))
