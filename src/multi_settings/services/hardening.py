from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.services.privileged import PrivilegedClient, PrivilegedResponse


def parse_task_event(event: dict[str, Any]) -> HardeningResult | None:
    if event.get("event") != "task_result":
        return None
    try:
        return HardeningResult(
            task=str(event["task"]),
            role=str(event.get("role", "")),
            status=TaskStatus(str(event["status"])),
            changed=bool(event.get("changed", False)),
            details=str(event.get("details", "")),
        )
    except (KeyError, ValueError, TypeError):
        return None


class HardeningService:
    def __init__(self, privileged: PrivilegedClient | None = None) -> None:
        self.privileged = privileged or PrivilegedClient()

    def run_async(
        self,
        *,
        audit: bool,
        variables: dict[str, Any],
        event_callback: Callable[[dict[str, Any]], None],
        callback: Callable[[PrivilegedResponse], None],
    ) -> None:
        # A JSON round-trip guarantees the payload contains no Python-specific values.
        serializable_variables = json.loads(json.dumps(variables))
        self.privileged.run_async(
            "hardening.run",
            {"mode": "audit" if audit else "apply", "variables": serializable_variables},
            callback,
            event_callback,
        )
