from __future__ import annotations

import unittest

from multi_settings.domain.validation import (
    ValidationError,
    validate_password,
    validate_serial,
    validate_username,
    validate_yaml_value,
)


class ValidationTests(unittest.TestCase):
    def test_accepts_ubuntu_username(self) -> None:
        self.assertEqual(validate_username("alice-admin"), "alice-admin")

    def test_rejects_command_like_username(self) -> None:
        with self.assertRaises(ValidationError):
            validate_username("alice; userdel bob")

    def test_password_minimum_is_enforced(self) -> None:
        with self.assertRaises(ValidationError):
            validate_password("short")

    def test_serial_is_numeric_and_nonzero(self) -> None:
        self.assertEqual(validate_serial("12345678"), "12345678")
        with self.assertRaises(ValidationError):
            validate_serial("0x1234")

    def test_yaml_rejects_non_string_keys(self) -> None:
        with self.assertRaises(ValidationError):
            validate_yaml_value({1: "value"})

    def test_yaml_accepts_role_variable_shapes(self) -> None:
        source = {"os_env_umask": "027", "ssh_server_ports": [22], "os_auditd_enabled": True}
        self.assertEqual(validate_yaml_value(source), source)

    def test_yaml_rejects_non_finite_numbers(self) -> None:
        with self.assertRaises(ValidationError):
            validate_yaml_value({"value": float("nan")})


if __name__ == "__main__":
    unittest.main()
