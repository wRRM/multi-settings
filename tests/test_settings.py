from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from multi_settings.domain.validation import ValidationError
from multi_settings.services.settings import CustomSettingsService


class SettingsTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
