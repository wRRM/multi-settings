from __future__ import annotations

import json
from typing import Any

from multi_settings.config import PRIVATE_STATE_FILE, STATE_DIR, STATE_FILE
from multi_settings.i18n import _
from multi_settings.privileged.protocol import atomic_write, fail


def load_state() -> dict[str, Any]:
    try:
        source = PRIVATE_STATE_FILE if PRIVATE_STATE_FILE.exists() else STATE_FILE
        loaded = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": 1, "enrollments": [], "pam": {"login": False, "sudo": False}}
    except (OSError, json.JSONDecodeError) as error:
        fail(_("The Onboarding state is unreadable: {error}").format(error=error))
    if not isinstance(loaded, dict) or not isinstance(loaded.get("enrollments", []), list):
        fail(_("The Onboarding state has an invalid format."))
    return loaded


def save_state(state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    STATE_DIR.chmod(0o755)
    atomic_write(PRIVATE_STATE_FILE, json.dumps(state, indent=2, sort_keys=True) + "\n", 0o600)
    public_state = {
        "version": state.get("version", 1),
        "enrollments": [
            {
                "username": item.get("username"),
                "serial": item.get("serial"),
                "slot": item.get("slot"),
            }
            for item in state.get("enrollments", [])
        ],
        "pam": state.get("pam", {"login": False, "sudo": False}),
    }
    atomic_write(STATE_FILE, json.dumps(public_state, indent=2, sort_keys=True) + "\n", 0o644)
