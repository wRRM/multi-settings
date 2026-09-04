from __future__ import annotations

import unittest

from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.services.hardening import parse_task_event


class HardeningEventTests(unittest.TestCase):
    def test_parses_supported_task_state(self) -> None:
        parsed = parse_task_event(
            {
                "event": "task_result",
                "task": "Configure sshd",
                "role": "devsec.hardening.ssh_hardening",
                "status": "success",
                "changed": True,
            }
        )
        self.assertEqual(
            parsed,
            HardeningResult(
                task="Configure sshd",
                role="devsec.hardening.ssh_hardening",
                status=TaskStatus.SUCCESS,
                changed=True,
            ),
        )

    def test_ignores_non_result_events(self) -> None:
        self.assertIsNone(parse_task_event({"event": "task_start", "task": "Gather facts"}))

    def test_rejects_unknown_status(self) -> None:
        self.assertIsNone(
            parse_task_event({"event": "task_result", "task": "x", "status": "changed"})
        )


if __name__ == "__main__":
    unittest.main()
