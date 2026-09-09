from __future__ import annotations

import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
from types import SimpleNamespace

from multi_settings.config import PAM_LINE, PAM_MARKER_END, PAM_MARKER_START, PAM_PASSWORD_LINE
from multi_settings.domain.validation import ValidationError
from multi_settings.privileged.hardening import validate_hardening_variables
from multi_settings.privileged.pam import (
    configure_pam,
    sudo_service_policy,
    with_managed_pam_block,
    without_managed_pam_block,
)
from multi_settings.privileged.yubikeys import unenroll_yubikey, validate_credential
from multi_settings.privileged.yubikeys import enroll_yubikey
from multi_settings.privileged.users import create_user, delete_user


class HelperTests(unittest.TestCase):
    def test_standard_user_removal_cleans_up_yubikey_state(self) -> None:
        state = {
            "enrollments": [
                {"username": "alice", "serial": "1234", "slot": "primary"},
                {"username": "bob", "serial": "5678", "slot": "primary"},
            ],
            "pam": {"login": False, "sudo": False},
        }
        with (
            patch(
                "multi_settings.privileged.users.ensure_known_user",
                return_value=SimpleNamespace(pw_uid=1001, pw_shell="/bin/bash"),
            ),
            patch("multi_settings.privileged.users.administrator_names", return_value=set()),
            patch("multi_settings.privileged.users.load_state", return_value=state),
            patch("multi_settings.privileged.users.subprocess.run") as run,
            patch("multi_settings.privileged.users.save_state") as save_state,
            patch("multi_settings.privileged.users.emit"),
            patch("multi_settings.privileged.yubikeys.rebuild_mapping_file") as rebuild,
            patch.dict("multi_settings.privileged.users.os.environ", {}, clear=True),
        ):
            delete_user({"username": "alice"})

        run.assert_called_once()
        rebuild.assert_called_once_with(state)
        save_state.assert_called_once_with(state)
        self.assertEqual([item["username"] for item in state["enrollments"]], ["bob"])

    def test_administrator_account_removal_is_refused(self) -> None:
        with (
            patch(
                "multi_settings.privileged.users.ensure_known_user",
                return_value=SimpleNamespace(pw_uid=1001, pw_shell="/bin/bash"),
            ),
            patch(
                "multi_settings.privileged.users.administrator_names",
                return_value={"alice"},
            ),
            patch("multi_settings.privileged.users.subprocess.run") as run,
        ):
            with self.assertRaises(ValidationError):
                delete_user({"username": "alice"})
        run.assert_not_called()

    def test_current_account_removal_is_refused(self) -> None:
        with (
            patch(
                "multi_settings.privileged.users.ensure_known_user",
                return_value=SimpleNamespace(pw_uid=1001, pw_shell="/bin/bash"),
            ),
            patch("multi_settings.privileged.users.administrator_names", return_value=set()),
            patch("multi_settings.privileged.users.subprocess.run") as run,
            patch.dict(
                "multi_settings.privileged.users.os.environ",
                {"PKEXEC_UID": "1001"},
                clear=True,
            ),
        ):
            with self.assertRaises(ValidationError):
                delete_user({"username": "alice"})
        run.assert_not_called()

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

    def test_pam_update_accepts_typed_common_auth_include(self) -> None:
        original = "auth include common-auth\naccount include common-account\n"
        updated = with_managed_pam_block(original)
        self.assertIn(f"auth include common-auth\n{PAM_MARKER_START}\n", updated)

    def test_sudo_i_inherits_managed_sudo_without_duplicate_factor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pam_directory = Path(directory)
            (pam_directory / "sudo").write_text("@include common-auth\n", encoding="utf-8")
            (pam_directory / "sudo-i").write_text("@include sudo\n", encoding="utf-8")
            with patch("multi_settings.privileged.pam.PAM_DIRECTORY", pam_directory):
                self.assertEqual(
                    sudo_service_policy(True),
                    {"sudo": True, "sudo-i": False},
                )

    def test_sudo_i_with_independent_auth_stack_is_managed_directly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pam_directory = Path(directory)
            (pam_directory / "sudo").write_text("@include common-auth\n", encoding="utf-8")
            (pam_directory / "sudo-i").write_text(
                "auth include common-auth\n", encoding="utf-8"
            )
            with patch("multi_settings.privileged.pam.PAM_DIRECTORY", pam_directory):
                self.assertEqual(
                    sudo_service_policy(True),
                    {"sudo": True, "sudo-i": True},
                )

    def test_sudo_i_unknown_auth_stack_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pam_directory = Path(directory)
            (pam_directory / "sudo").write_text("@include common-auth\n", encoding="utf-8")
            (pam_directory / "sudo-i").write_text(
                "auth required pam_unix.so\n", encoding="utf-8"
            )
            with patch("multi_settings.privileged.pam.PAM_DIRECTORY", pam_directory):
                with self.assertRaises(ValidationError):
                    sudo_service_policy(True)

    def test_polkit_requirement_updates_its_pam_service_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pam_directory = root / "pam.d"
            pam_directory.mkdir()
            polkit_service = pam_directory / "polkit-1"
            polkit_service.write_text("@include common-auth\n", encoding="utf-8")
            state = {
                "version": 1,
                "enrollments": [{"username": "alice"}],
                "pam": {"login": False, "sudo": False, "polkit": False},
            }
            with (
                patch("multi_settings.privileged.pam.PAM_DIRECTORY", pam_directory),
                patch(
                    "multi_settings.privileged.pam.PAM_MODULE_CANDIDATES",
                    (polkit_service,),
                ),
                patch("multi_settings.privileged.pam.PAM_BACKUP_DIR", root / "backups"),
                patch("multi_settings.privileged.pam.load_state", return_value=state),
                patch(
                    "multi_settings.privileged.pam.administrator_names",
                    return_value={"alice"},
                ),
                patch("multi_settings.privileged.pam.save_state") as save_state,
                patch("multi_settings.privileged.pam.emit"),
            ):
                configure_pam({"login": False, "sudo": False, "polkit": True})

            self.assertIn(PAM_MARKER_START, polkit_service.read_text(encoding="utf-8"))
            self.assertTrue(state["pam"]["polkit"])
            save_state.assert_called_once_with(state)

    def test_vendor_polkit_profile_gets_reversible_local_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pam_directory = root / "etc-pam.d"
            pam_directory.mkdir()
            vendor_directory = root / "usr-lib-pam.d"
            vendor_directory.mkdir()
            vendor_service = vendor_directory / "polkit-1"
            vendor_service.write_text("@include common-auth\n", encoding="utf-8")
            state = {
                "version": 1,
                "enrollments": [{"username": "alice"}],
                "pam": {"login": False, "sudo": False, "polkit": False},
            }
            with (
                patch("multi_settings.privileged.pam.PAM_DIRECTORY", pam_directory),
                patch(
                    "multi_settings.privileged.pam.PAM_VENDOR_DIRECTORIES",
                    (vendor_directory,),
                ),
                patch(
                    "multi_settings.privileged.pam.PAM_MODULE_CANDIDATES",
                    (vendor_service,),
                ),
                patch("multi_settings.privileged.pam.PAM_BACKUP_DIR", root / "backups"),
                patch("multi_settings.privileged.pam.load_state", return_value=state),
                patch(
                    "multi_settings.privileged.pam.administrator_names",
                    return_value={"alice"},
                ),
                patch("multi_settings.privileged.pam.save_state"),
                patch("multi_settings.privileged.pam.emit"),
            ):
                configure_pam({"login": False, "sudo": False, "polkit": True})
                local_service = pam_directory / "polkit-1"
                self.assertIn(
                    PAM_MARKER_START, local_service.read_text(encoding="utf-8")
                )

                configure_pam({"login": False, "sudo": False, "polkit": False})

            self.assertFalse(local_service.exists())
            self.assertEqual(
                vendor_service.read_text(encoding="utf-8"), "@include common-auth\n"
            )

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

    def test_cannot_remove_admin_last_key_while_polkit_requirement_is_active(self) -> None:
        state = {
            "enrollments": [
                {
                    "username": "alice",
                    "serial": "12345678",
                    "slot": "primary",
                    "credential": "alice:key,public,es256",
                }
            ],
            "pam": {"login": False, "sudo": False, "polkit": True},
        }
        with (
            patch("multi_settings.privileged.yubikeys.load_state", return_value=state),
            patch(
                "multi_settings.privileged.yubikeys.administrator_names",
                return_value={"alice"},
            ),
        ):
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

    def test_hardening_variables_accept_safe_additional_names(self) -> None:
        validate_hardening_variables(
            {
                "os_env_umask": "027",
                "organization_setting1": 0,
                "organization_setting2": 2,
            }
        )

    def test_hardening_variables_reject_ansible_control_names(self) -> None:
        with self.assertRaises(ValidationError):
            validate_hardening_variables(
                {"ansible_python_interpreter": "/tmp/owned"}
            )

    def test_hardening_variables_reject_jinja(self) -> None:
        with self.assertRaises(ValidationError):
            validate_hardening_variables(
                {"allowed_value": "{{ lookup('pipe', 'id') }}"}
            )

    def test_administrator_creation_is_refused_while_polkit_requires_a_key(self) -> None:
        with (
            patch(
                "multi_settings.privileged.users.load_state",
                return_value={"pam": {"polkit": True}},
            ),
            patch("multi_settings.privileged.users.subprocess.run") as run,
        ):
            with self.assertRaises(ValidationError):
                create_user(
                    {
                        "username": "alice",
                        "full_name": "Alice Example",
                        "password": "correct horse battery staple",
                        "administrator": True,
                    }
                )
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
