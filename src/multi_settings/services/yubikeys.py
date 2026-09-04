from __future__ import annotations

import json
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path

from multi_settings.config import PAM_ORIGIN, STATE_FILE
from multi_settings.domain.models import ConnectedKey, Enrollment, KeySlot
from multi_settings.domain.validation import ValidationError, validate_serial, validate_username
from multi_settings.services.privileged import PrivilegedClient, PrivilegedResponse


class YubiKeyService:
    def __init__(self, privileged: PrivilegedClient | None = None, state_file: Path = STATE_FILE) -> None:
        self.privileged = privileged or PrivilegedClient()
        self.state_file = state_file

    def connected_keys(self) -> list[ConnectedKey]:
        executable = shutil.which("ykman")
        if executable is None:
            return []
        completed = subprocess.run(
            [executable, "list", "--serials"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if completed.returncode != 0:
            return []
        enrollments_by_serial = {item.serial: item for item in self.enrollments()}
        serials = {
            validate_serial(line)
            for line in completed.stdout.splitlines()
            if line.strip().isdigit()
        }
        return [ConnectedKey(serial, enrollments_by_serial.get(serial)) for serial in sorted(serials)]

    def enrollments(self) -> list[Enrollment]:
        try:
            state = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
            return []
        found: list[Enrollment] = []
        for item in state.get("enrollments", []):
            try:
                found.append(
                    Enrollment(
                        username=item["username"],
                        serial=item["serial"],
                        slot=KeySlot(item["slot"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return sorted(found, key=lambda item: (item.username, item.slot.value))

    def enroll_async(
        self,
        username: str,
        serial: str,
        slot: KeySlot,
        callback: Callable[[PrivilegedResponse], None],
    ) -> None:
        username = validate_username(username)
        serial = validate_serial(serial)

        def generate_and_store() -> None:
            connected_serials = [key.serial for key in self.connected_keys()]
            if connected_serials != [serial]:
                callback(
                    PrivilegedResponse(
                        False,
                        "Connect only the YubiKey being enrolled so its serial and credential cannot be mismatched.",
                    )
                )
                return
            executable = shutil.which("pamu2fcfg")
            if executable is None:
                callback(PrivilegedResponse(False, "pamu2fcfg is not installed."))
                return
            try:
                completed = subprocess.run(
                    [
                        executable,
                        "-u",
                        username,
                        "-o",
                        PAM_ORIGIN,
                        "-i",
                        PAM_ORIGIN,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=90,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                callback(PrivilegedResponse(False, f"Enrollment failed: {error}"))
                return
            credential = completed.stdout.strip()
            if completed.returncode != 0 or not credential:
                message = completed.stderr.strip() or "The key did not complete enrollment."
                callback(PrivilegedResponse(False, message))
                return
            if [key.serial for key in self.connected_keys()] != [serial]:
                callback(
                    PrivilegedResponse(
                        False,
                        "The connected YubiKey changed during enrollment; no credential was stored.",
                    )
                )
                return
            self.privileged.run_async(
                "yubikey.enroll",
                {
                    "username": username,
                    "serial": serial,
                    "slot": slot.value,
                    "credential": credential,
                },
                callback,
            )

        threading.Thread(target=generate_and_store, daemon=True).start()

    def unenroll_async(
        self,
        username: str,
        slot: KeySlot,
        callback: Callable[[PrivilegedResponse], None],
    ) -> None:
        self.privileged.run_async(
            "yubikey.unenroll",
            {"username": validate_username(username), "slot": slot.value},
            callback,
        )
