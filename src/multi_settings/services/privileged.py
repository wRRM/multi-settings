from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from multi_settings.config import HELPER_PATH
from multi_settings.i18n import _, get_language


@dataclass(frozen=True, slots=True)
class PrivilegedResponse:
    ok: bool
    message: str
    events: tuple[dict[str, Any], ...] = ()


class PrivilegedClient:
    """The only GUI-side gateway to root mutations."""

    def run(
        self,
        action: str,
        payload: dict[str, Any],
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> PrivilegedResponse:
        request = json.dumps(
            {"action": action, "payload": payload, "language": get_language()}
        )
        helper = os.environ.get("MULTI_SETTINGS_HELPER", str(HELPER_PATH))
        process = subprocess.Popen(
            ["pkexec", helper],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(request)
        process.stdin.close()

        events: list[dict[str, Any]] = []
        final_message = _("Operation completed.")
        for line in process.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            events.append(event)
            if isinstance(event.get("message"), str):
                final_message = event["message"]
            if event_callback is not None:
                event_callback(event)

        stderr = process.stderr.read().strip() if process.stderr is not None else ""
        return_code = process.wait()
        if return_code != 0:
            if return_code == 126:
                final_message = _("Administrator authentication was cancelled.")
            elif stderr:
                final_message = stderr.splitlines()[-1]
            elif not events:
                final_message = _("The privileged operation failed.")
        return PrivilegedResponse(return_code == 0, final_message, tuple(events))

    def run_async(
        self,
        action: str,
        payload: dict[str, Any],
        callback: Callable[[PrivilegedResponse], None],
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        def worker() -> None:
            try:
                response = self.run(action, payload, event_callback)
            except (OSError, subprocess.SubprocessError) as error:
                response = PrivilegedResponse(False, str(error))
            callback(response)

        threading.Thread(target=worker, daemon=True).start()
