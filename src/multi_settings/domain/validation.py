from __future__ import annotations

import re
import math
from collections.abc import Mapping, Sequence
from typing import Any

USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
SERIAL_PATTERN = re.compile(r"^[1-9][0-9]{3,19}$")
MAX_CONFIG_DEPTH = 12
MAX_CONFIG_ITEMS = 2_000


class ValidationError(ValueError):
    """Raised when data crosses a trust boundary in an invalid shape."""


def validate_username(username: str) -> str:
    value = username.strip()
    if not USERNAME_PATTERN.fullmatch(value):
        raise ValidationError(
            "Usernames must start with a lowercase letter or underscore and "
            "contain at most 31 lowercase letters, numbers, underscores, or hyphens."
        )
    return value


def validate_serial(serial: str) -> str:
    value = serial.strip()
    if not SERIAL_PATTERN.fullmatch(value):
        raise ValidationError("The YubiKey serial number is invalid.")
    return value


def validate_full_name(full_name: str) -> str:
    value = full_name.strip()
    if len(value) > 128 or any(character in value for character in (":", "\n", "\r")):
        raise ValidationError("The full name is invalid.")
    return value


def validate_password(password: str) -> str:
    if len(password) < 12:
        raise ValidationError("Use a password of at least 12 characters.")
    if len(password) > 1_024 or "\n" in password or "\x00" in password:
        raise ValidationError("The password is invalid.")
    return password


def validate_yaml_value(value: Any, *, depth: int = 0, counter: list[int] | None = None) -> Any:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_CONFIG_ITEMS:
        raise ValidationError("The settings file contains too many values.")
    if depth > MAX_CONFIG_DEPTH:
        raise ValidationError("The settings file is nested too deeply.")

    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError("Settings numbers must be finite.")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValidationError("Every settings key must be a non-empty string.")
            clean[key] = validate_yaml_value(child, depth=depth + 1, counter=counter)
        return clean
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [validate_yaml_value(child, depth=depth + 1, counter=counter) for child in value]
    raise ValidationError(f"Unsupported YAML value: {type(value).__name__}")


def reject_template_expressions(value: Any) -> None:
    if isinstance(value, str) and any(marker in value for marker in ("{{", "{%", "{#")):
        raise ValidationError("Jinja expressions are not allowed in imported settings.")
    if isinstance(value, Mapping):
        for child in value.values():
            reject_template_expressions(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            reject_template_expressions(child)
