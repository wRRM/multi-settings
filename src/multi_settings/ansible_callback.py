from __future__ import annotations

import json
from typing import Any


def result_details(data: dict[str, Any], status: str) -> str:
    """Extract a concise, non-secret explanation from an Ansible result."""
    if status == "skipped":
        fields = (
            ("Skip reason", "skip_reason"),
            ("Condition", "false_condition"),
            ("Message", "msg"),
        )
        fallback = "The task condition was not met."
    elif status == "failed":
        fields = (
            ("Message", "msg"),
            ("Standard error", "stderr"),
            ("Module error", "module_stderr"),
            ("Exception", "exception"),
            ("Module output", "module_stdout"),
        )
        fallback = "Ansible did not provide a failure reason."
    else:
        fields = (("Message", "msg"),)
        fallback = ""
    details: list[str] = []
    for label, key in fields:
        value = data.get(key)
        if value in (None, "", [], {}):
            continue
        rendered = (
            json.dumps(value, ensure_ascii=False)
            if isinstance(value, (dict, list))
            else str(value)
        )
        rendered = " ".join(rendered.split())
        item = f"{label}: {rendered}"
        if item not in details:
            details.append(item)
    return (" · ".join(details) or fallback)[:2_000]
