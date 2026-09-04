from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_project_versions_match_debian_version(self) -> None:
        changelog = (ROOT / "debian/changelog").read_text(encoding="utf-8")
        debian_version = re.match(r"multi-settings \(([^)]+)\)", changelog).group(1)
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["version"], debian_version)
        self.assertIn(f"version: '{debian_version}'", (ROOT / "meson.build").read_text(encoding="utf-8"))

    def test_workflow_actions_use_full_commit_shas(self) -> None:
        workflow = (ROOT / ".github/workflows/debian-package.yml").read_text(encoding="utf-8")
        action_references = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow, re.MULTILINE)
        self.assertGreaterEqual(len(action_references), 3)
        for reference in action_references:
            self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_hardening_checksum_has_expected_shape(self) -> None:
        checksum = (ROOT / "data/ansible/devsec-hardening-10.6.0.sha256").read_text(
            encoding="utf-8"
        )
        self.assertRegex(checksum, r"^[0-9a-f]{64}  devsec-hardening-10\.6\.0\.tar\.gz\n$")


if __name__ == "__main__":
    unittest.main()
