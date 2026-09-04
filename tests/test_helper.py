from __future__ import annotations

import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path

from multi_settings.config import PAM_LINE, PAM_MARKER_END, PAM_MARKER_START, PAM_PASSWORD_LINE
from multi_settings.domain.validation import ValidationError
from multi_settings.privileged.hardening import validate_hardening_variables
from multi_settings.privileged.pam import with_managed_pam_block, without_managed_pam_block
from multi_settings.privileged.yubikeys import unenroll_yubikey, validate_credential
from multi_settings.privileged.yubikeys import enroll_yubikey


class HelperTests(unittest.TestCase):
    def test_managed_pam_block_follows_password_stack(self) -> None:
        original = "#%PAM-1.0\n@include common-auth\n@include common-account\n"
        updated = with_managed_pam_block(original)
        self.assertIn(
            f"@include common-auth\n{PAM_MARKER_START}\n{PAM_PASSWORD_LINE}\n{PAM_LINE}\n{PAM_MARKER_END}",
            updated,
        )
        self.assertEqual(without_managed_pam_block(updated), original)

    def test_pam_update_is_idempotent(self) -> None:
        original = "@include common-auth\n"
        once = with_managed_pam_block(original)
        self.assertEqual(with_managed_pam_block(once), once)

    def test_pam_edit_refuses_unknown_stack(self) -> None:
        with self.assertRaises(ValidationError):
            with_managed_pam_block("auth required pam_unix.so\n")

    def test_credential_must_match_account(self) -> None:
        valid = "alice:key-handle,public-key,es256,+presence"
        self.assertEqual(validate_credential("alice", valid), valid)
        with self.assertRaises(ValidationError):
            validate_credential("bob", valid)

    def test_cannot_remove_last_key_while_login_requirement_is_active(self) -> None:
        state = {
            "enrollments": [
                {
                    "username": "alice",
                    "serial": "12345678",
                    "slot": "primary",
                    "credential": "alice:key,public,es256",
                }
            ],
            "pam": {"login": True, "sudo": False},
        }
        with patch("multi_settings.privileged.yubikeys.load_state", return_value=state):
            with self.assertRaises(ValidationError):
                unenroll_yubikey({"username": "alice", "slot": "primary"})

    def test_same_serial_cannot_be_enrolled_twice(self) -> None:
        state = {
            "enrollments": [
                {
                    "username": "alice",
                    "serial": "12345678",
                    "slot": "primary",
                    "credential": "alice:key,public,es256",
                }
            ],
            "pam": {"login": False, "sudo": False},
        }
        with (
            patch("multi_settings.privileged.yubikeys.ensure_known_user"),
            patch("multi_settings.privileged.yubikeys.load_state", return_value=state),
        ):
            with self.assertRaises(ValidationError):
                enroll_yubikey(
                    {
                        "username": "bob",
                        "serial": "12345678",
                        "slot": "secondary",
                        "credential": "bob:key,public,es256",
                    }
                )

    def test_hardening_variables_are_limited_to_pinned_role_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            roles = Path(directory)
            for role, content in (
                ("os_hardening", "os_env_umask: '027'\nsysctl_config: {}\n"),
                ("ssh_hardening", "ssh_server_ports: ['22']\n"),
            ):
                defaults = roles / role / "defaults"
                defaults.mkdir(parents=True)
                (defaults / "main.yml").write_text(content, encoding="utf-8")
            validate_hardening_variables({"os_env_umask": "027", "ssh_server_ports": [22]}, roles)
            with self.assertRaises(ValidationError):
                validate_hardening_variables({"ansible_python_interpreter": "/tmp/owned"}, roles)

    def test_hardening_variables_reject_jinja(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            roles = Path(directory)
            for role in ("os_hardening", "ssh_hardening"):
                defaults = roles / role / "defaults"
                defaults.mkdir(parents=True)
                (defaults / "main.yml").write_text("allowed_value: safe\n", encoding="utf-8")
            with self.assertRaises(ValidationError):
                validate_hardening_variables(
                    {"allowed_value": "{{ lookup('pipe', 'id') }}"}, roles
                )


if __name__ == "__main__":
    unittest.main()
