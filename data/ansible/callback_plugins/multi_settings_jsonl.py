from __future__ import annotations

import json

from ansible.plugins.callback import CallbackBase


DOCUMENTATION = r"""
name: multi_settings_jsonl
type: stdout
short_description: Emits one machine-readable JSON object per Ansible event
version_added: "2.16"
requirements: []
"""


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "multi_settings_jsonl"

    def _emit(self, event, **values):
        self._display.display(json.dumps({"event": event, **values}, default=str, ensure_ascii=False))

    @staticmethod
    def _task_name(result):
        return result._task.get_name().strip()

    @staticmethod
    def _role_name(result):
        role = getattr(result._task, "_role", None)
        return role.get_name() if role is not None else ""

    @staticmethod
    def _details(result):
        data = result._result
        for key in ("msg", "stderr", "module_stdout"):
            if data.get(key):
                return str(data[key])[:2_000]
        return ""

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._emit("task_start", task=task.get_name().strip())

    def v2_runner_on_ok(self, result):
        self._emit(
            "task_result",
            task=self._task_name(result),
            role=self._role_name(result),
            status="success",
            changed=bool(result._result.get("changed", False)),
            details=self._details(result),
        )

    def v2_runner_on_skipped(self, result):
        self._emit(
            "task_result",
            task=self._task_name(result),
            role=self._role_name(result),
            status="skipped",
            changed=False,
            details=self._details(result),
        )

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._emit(
            "task_result",
            task=self._task_name(result),
            role=self._role_name(result),
            status="failed",
            changed=bool(result._result.get("changed", False)),
            details=self._details(result),
        )

    def v2_playbook_on_stats(self, stats):
        totals = {}
        for host in sorted(stats.processed):
            totals[host] = stats.summarize(host)
        self._emit("stats", totals=totals)
