from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from multi_settings.config import (
    ANSIBLE_COLLECTIONS_PATH,
    CALLBACK_DIR,
    COLLECTIONS_PATH,
    HARDENING_COLLECTION_VERSION,
    PLAYBOOK_PATH,
)
from multi_settings.domain.validation import (
    ValidationError,
    reject_template_expressions,
    validate_yaml_value,
)
from multi_settings.privileged.protocol import SAFE_ENVIRONMENT, emit, fail


def validate_hardening_variables(variables: dict[str, Any], roles_root: Path) -> None:
    allowed_names: set[str] = set()
    for role_name in ("os_hardening", "ssh_hardening"):
        defaults_path = roles_root / role_name / "defaults/main.yml"
        try:
            defaults = yaml.safe_load(defaults_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise ValidationError(f"Could not read trusted {role_name} defaults: {error}") from error
        if not isinstance(defaults, dict):
            raise ValidationError(f"The installed {role_name} defaults are invalid.")
        allowed_names.update(str(name) for name in defaults)
    unknown = sorted(set(variables) - allowed_names)
    if unknown:
        raise ValidationError(
            "Unsupported hardening variable" + ("s: " if len(unknown) > 1 else ": ") + ", ".join(unknown)
        )

    reject_template_expressions(variables)


def validate_ubuntu_2604() -> None:
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", maxsplit=1)
                os_release[key] = value.strip().strip('"')
    except OSError as error:
        raise ValidationError(f"Could not identify the operating system: {error}") from error
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "26.04":
        raise ValidationError("Hardening is restricted to Ubuntu 26.04.")


def hardening_run(payload: dict[str, Any]) -> None:
    mode = payload.get("mode")
    if mode not in ("audit", "apply"):
        raise ValidationError("Hardening mode must be audit or apply.")
    variables = validate_yaml_value(payload.get("variables", {}))
    if not isinstance(variables, dict):
        raise ValidationError("Hardening variables must be a mapping.")
    validate_ubuntu_2604()
    if not PLAYBOOK_PATH.is_file():
        raise ValidationError("The Multi Settings Ansible playbook is not installed.")
    roles_root = COLLECTIONS_PATH / "ansible_collections/devsec/hardening/roles"
    expected_roles = (roles_root / "os_hardening", roles_root / "ssh_hardening")
    if not all(role.is_dir() for role in expected_roles):
        raise ValidationError("The pinned DevSec hardening collection is not installed.")
    manifest_path = roles_root.parent / "MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        installed_version = manifest["collection_info"]["version"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValidationError(f"Could not verify the installed hardening collection: {error}") from error
    if installed_version != HARDENING_COLLECTION_VERSION:
        raise ValidationError(
            f"Hardening collection {installed_version} is installed; version "
            f"{HARDENING_COLLECTION_VERSION} is required."
        )
    validate_hardening_variables(variables, roles_root)
    executable = Path("/usr/bin/ansible-playbook")
    if not executable.is_file():
        raise ValidationError("ansible-playbook is not installed.")

    descriptor, variables_path = tempfile.mkstemp(prefix="multi-settings-vars.", suffix=".json")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(variables, stream)
            stream.flush()
            os.fsync(stream.fileno())
        environment = dict(SAFE_ENVIRONMENT)
        environment.update(
            {
                "ANSIBLE_COLLECTIONS_PATH": ANSIBLE_COLLECTIONS_PATH,
                "ANSIBLE_CALLBACK_PLUGINS": str(CALLBACK_DIR),
                "ANSIBLE_STDOUT_CALLBACK": "multi_settings_jsonl",
                "ANSIBLE_FORCE_COLOR": "0",
                "ANSIBLE_NOCOLOR": "1",
            }
        )
        command = [str(executable), str(PLAYBOOK_PATH), "--extra-vars", f"@{variables_path}"]
        if mode == "audit":
            command.extend(("--check", "--diff"))
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            env=environment,
        )
        assert process.stdout is not None
        last_unstructured_line = ""
        for line in process.stdout:
            rendered = line.rstrip("\n")
            print(rendered, flush=True)
            try:
                json.loads(rendered)
            except json.JSONDecodeError:
                if rendered.strip():
                    last_unstructured_line = rendered.strip()
        return_code = process.wait()
        if return_code != 0:
            fail(last_unstructured_line or "Ansible reported a failure.")
        emit("complete", message="Audit completed." if mode == "audit" else "Hardening completed.")
    finally:
        try:
            os.unlink(variables_path)
        except FileNotFoundError:
            pass
