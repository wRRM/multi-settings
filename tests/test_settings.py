from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from multi_settings.domain.validation import ValidationError
from multi_settings.services.settings import CustomSettingsService


class SettingsTests(unittest.TestCase):
    def test_default_directory_and_yaml_file_are_loaded_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_directory = Path(directory) / "multi-settings"
            with patch(
                "multi_settings.services.settings.user_config_dir",
                return_value=config_directory,
            ):
                service = CustomSettingsService()
                self.assertEqual(service.load(), {})
                self.assertEqual(config_directory.stat().st_mode & 0o777, 0o700)
                service.destination.write_text("os_env_umask: '027'\n", encoding="utf-8")
                self.assertEqual(service.load(), {"os_env_umask": "027"})
                self.assertEqual(service.destination.stat().st_mode & 0o777, 0o600)

    def test_legacy_yml_file_is_migrated_to_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_directory = Path(directory) / "multi-settings"
            config_directory.mkdir()
            legacy = config_directory / "custom-settings.yml"
            legacy.write_text("ssh_server_ports: [22]\n", encoding="utf-8")
            with patch(
                "multi_settings.services.settings.user_config_dir",
                return_value=config_directory,
            ):
                service = CustomSettingsService()
                self.assertEqual(service.load(), {"ssh_server_ports": [22]})
                self.assertTrue((config_directory / "custom-settings.yaml").is_file())

    def test_import_persists_valid_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.yml"
            source.write_text("os_env_umask: '027'\nssh_server_ports: [22]\n", encoding="utf-8")
            destination = root / "config" / "custom-settings.yml"
            service = CustomSettingsService(destination)

            loaded = service.import_file(source)

            self.assertEqual(loaded["os_env_umask"], "027")
            self.assertEqual(service.load(), loaded)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_user_settings_override_bundled_build_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "bundled.yaml"
            bundled.write_text(
                "os_env_umask: '027'\nssh_server_ports: [22]\n",
                encoding="utf-8",
            )
            user = root / "config" / "custom-settings.yaml"
            user.parent.mkdir()
            user.write_text("ssh_server_ports: [2222]\n", encoding="utf-8")

            loaded = CustomSettingsService(
                user,
                bundled_settings=bundled,
            ).load()

            self.assertEqual(
                loaded,
                {"os_env_umask": "027", "ssh_server_ports": [2222]},
            )

    def test_import_rejects_yaml_sequence_at_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.yml"
            source.write_text("- one\n- two\n", encoding="utf-8")
            with self.assertRaises(ValidationError):
                CustomSettingsService(Path(directory) / "saved.yml").import_file(source)

    def test_import_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.yml"
            source.write_text("ssh_server_ports: [22]\nssh_server_ports: [2222]\n", encoding="utf-8")
            with self.assertRaises(ValidationError):
                CustomSettingsService(Path(directory) / "saved.yml").import_file(source)

    def test_import_rejects_jinja_before_privilege_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.yml"
            source.write_text("ssh_server_ports: \"{{ lookup('pipe', 'id') }}\"\n", encoding="utf-8")
            with self.assertRaises(ValidationError):
                CustomSettingsService(Path(directory) / "saved.yml").import_file(source)

    def test_import_accepts_safe_variables_not_declared_by_collection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.yml"
            source.write_text(
                "organization_setting1: 0\norganization_setting2: 2\n",
                encoding="utf-8",
            )
            loaded = CustomSettingsService(
                Path(directory) / "saved.yml"
            ).import_file(source)
            self.assertEqual(
                loaded,
                {"organization_setting1": 0, "organization_setting2": 2},
            )

    def test_import_rejects_ansible_control_variable_before_privilege_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.yml"
            source.write_text(
                "ansible_python_interpreter: /tmp/owned\n", encoding="utf-8"
            )
            with self.assertRaises(ValidationError):
                CustomSettingsService(Path(directory) / "saved.yml").import_file(source)


if __name__ == "__main__":
    unittest.main()
