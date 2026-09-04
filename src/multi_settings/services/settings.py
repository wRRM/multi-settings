from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from multi_settings.config import user_config_dir
from multi_settings.domain.validation import (
    ValidationError,
    reject_template_expressions,
    validate_yaml_value,
)


class UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class CustomSettingsService:
    def __init__(self, destination: Path | None = None) -> None:
        self.destination = destination or user_config_dir() / "custom-settings.yml"

    def import_file(self, source: Path) -> dict[str, Any]:
        if not source.is_file():
            raise ValidationError("Choose an existing YAML file.")
        if source.stat().st_size > 1_048_576:
            raise ValidationError("The settings file must be smaller than 1 MiB.")
        try:
            loaded = yaml.load(source.read_text(encoding="utf-8"), Loader=UniqueKeySafeLoader)
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValidationError(f"Could not read YAML: {error}") from error
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValidationError("The top-level YAML value must be a mapping.")
        clean = validate_yaml_value(loaded)
        reject_template_expressions(clean)
        self._save(clean)
        return clean

    def load(self) -> dict[str, Any]:
        if not self.destination.exists():
            return {}
        return self.import_file(self.destination)

    def _save(self, settings: dict[str, Any]) -> None:
        self.destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content = yaml.safe_dump(settings, default_flow_style=False, sort_keys=True)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix="custom-settings.", dir=self.destination.parent, text=True
        )
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, self.destination)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
