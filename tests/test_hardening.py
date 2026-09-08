from __future__ import annotations

import unittest

from multi_settings.ansible_callback import result_details
from multi_settings.domain.models import HardeningResult, TaskStatus
from multi_settings.privileged.hardening import selected_hardening_tags
from multi_settings.services.hardening import HardeningService, parse_task_event


class RecordingPrivilegedClient:
    def run_async(self, action, payload, callback, event_callback=None) -> None:
        self.action = action
        self.payload = payload


class HardeningEventTests(unittest.TestCase):
    def test_skip_and_failure_reasons_are_extracted(self) -> None:
        self.assertEqual(
            result_details(
                {
                    "skip_reason": "Conditional result was False",
                    "false_condition": "os_auditd_enabled",
                },
                "skipped",
            ),
            "Skip reason: Conditional result was False · Condition: os_auditd_enabled",
        )
        self.assertEqual(
            result_details({"msg": "Invalid sshd configuration"}, "failed"),
            "Message: Invalid sshd configuration",
        )

    def test_missing_ansible_reason_has_an_actionable_fallback(self) -> None:
        self.assertEqual(
            result_details({}, "skipped"),
            "The task condition was not met.",
        )
        self.assertEqual(
            result_details(
                {"invocation": {"module_args": {"password": "do-not-display"}}},
                "failed",
            ),
            "Ansible did not provide a failure reason.",
        )

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

    def test_restore_sends_only_the_validated_backup_identifier(self) -> None:
        privileged = RecordingPrivilegedClient()
        service = HardeningService(privileged)
        service.restore_async("20260908T120000Z-012345abcdef", lambda _response: None)
        self.assertEqual(privileged.action, "hardening.restore")
        self.assertEqual(
            privileged.payload,
            {"backup_id": "20260908T120000Z-012345abcdef"},
        )

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
