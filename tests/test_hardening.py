from __future__ import annotations

import unittest

from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.privileged.hardening import selected_hardening_tags
from multi_settings.services.hardening import HardeningService, parse_task_event


class RecordingPrivilegedClient:
    def run_async(self, action, payload, callback, event_callback) -> None:
        self.action = action
        self.payload = payload


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

    def test_selected_components_are_sent_to_the_helper(self) -> None:
        privileged = RecordingPrivilegedClient()
        service = HardeningService(privileged)
        service.run_async(
            audit=True,
            variables={},
            os_hardening=False,
            ssh_hardening=True,
            event_callback=lambda _event: None,
            callback=lambda _response: None,
        )
        self.assertEqual(privileged.action, "hardening.run")
        self.assertFalse(privileged.payload["os_hardening"])
        self.assertTrue(privileged.payload["ssh_hardening"])

    def test_at_least_one_hardening_component_is_required(self) -> None:
        self.assertEqual(
            selected_hardening_tags(
                {"os_hardening": True, "ssh_hardening": False}
            ),
            ("os_hardening",),
        )
        with self.assertRaises(ValueError):
            selected_hardening_tags(
                {"os_hardening": False, "ssh_hardening": False}
            )


if __name__ == "__main__":
    unittest.main()
