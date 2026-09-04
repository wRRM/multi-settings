from __future__ import annotations

import json
import os
import subprocess
import sys

from multi_settings.domain.validation import ValidationError
from multi_settings.privileged.hardening import hardening_run
from multi_settings.privileged.pam import configure_pam
from multi_settings.privileged.protocol import MAX_REQUEST_BYTES, fail
from multi_settings.privileged.users import create_user
from multi_settings.privileged.yubikeys import enroll_yubikey, unenroll_yubikey

ACTIONS = {
    "user.create": create_user,
    "yubikey.enroll": enroll_yubikey,
    "yubikey.unenroll": unenroll_yubikey,
    "pam.configure": configure_pam,
    "hardening.run": hardening_run,
}


def main() -> int:
    if os.geteuid() != 0:
        print("multi-settings-helper must be run through PolicyKit", file=sys.stderr)
        return 77
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        fail("The request is too large.")
    try:
        request = json.loads(raw.decode("utf-8"))
        action = request["action"]
        payload = request.get("payload", {})
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        fail("The request is invalid.")
    if not isinstance(action, str) or action not in ACTIONS or not isinstance(payload, dict):
        fail("The requested operation is not allowed.")
    try:
        ACTIONS[action](payload)
    except ValidationError as error:
        fail(str(error))
    except subprocess.CalledProcessError as error:
        fail(f"System command failed with exit code {error.returncode}.")
    except OSError as error:
        fail(f"System operation failed: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
