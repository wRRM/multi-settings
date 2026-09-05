from __future__ import annotations

import grp
import pwd
import subprocess
from typing import Any

from multi_settings.domain.validation import (
    ValidationError,
    validate_full_name,
    validate_password,
    validate_username,
)
from multi_settings.i18n import _
from multi_settings.privileged.protocol import SAFE_ENVIRONMENT, emit
from multi_settings.privileged.state import load_state


def administrator_names() -> set[str]:
    try:
        group = grp.getgrnam("sudo")
    except KeyError:
        return set()
    names = set(group.gr_mem)
    names.update(record.pw_name for record in pwd.getpwall() if record.pw_gid == group.gr_gid)
    return names


def interactive_user_names() -> set[str]:
    return {
        record.pw_name
        for record in pwd.getpwall()
        if record.pw_uid >= 1_000
        and record.pw_uid != 65_534
        and not record.pw_shell.endswith(("/nologin", "/false"))
    }


def ensure_known_user(username: str) -> pwd.struct_passwd:
    try:
        record = pwd.getpwnam(username)
    except KeyError as error:
        raise ValidationError(_("The account {username!r} does not exist.").format(username=username)) from error
    if record.pw_uid < 1_000 or record.pw_uid == 65_534:
        raise ValidationError(_("YubiKey enrollment is limited to interactive user accounts."))
    return record


def create_user(payload: dict[str, Any]) -> None:
    username = validate_username(str(payload.get("username", "")))
    full_name = validate_full_name(str(payload.get("full_name", "")))
    password = validate_password(str(payload.get("password", "")))
    administrator = payload.get("administrator") is True
    pam_state = load_state().get("pam", {})
    if pam_state.get("login") is True or (administrator and pam_state.get("sudo") is True):
        raise ValidationError(
            _("Disable the affected YubiKey requirement before creating an account, then enroll its key before re-enabling it.")
        )
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise ValidationError(_("The account {username!r} already exists.").format(username=username))

    command = ["/usr/sbin/useradd", "--create-home", "--shell", "/bin/bash"]
    if full_name:
        command.extend(("--comment", full_name))
    if administrator:
        command.extend(("--groups", "sudo"))
    command.append(username)
    subprocess.run(command, check=True, env=SAFE_ENVIRONMENT)
    try:
        subprocess.run(
            ["/usr/sbin/chpasswd"],
            input=f"{username}:{password}\n",
            text=True,
            check=True,
            env=SAFE_ENVIRONMENT,
        )
    except BaseException:
        subprocess.run(["/usr/sbin/userdel", "--remove", username], check=False, env=SAFE_ENVIRONMENT)
        raise
    emit("complete", message=_("Created account {username}.").format(username=username))
